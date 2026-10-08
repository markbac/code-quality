"""
Trust boundary paths: how data that enters through a communication interface can reach sensitive code.

An entry point is a function that something outside the project calls or nothing calls (an interrupt handler,
a task body, `main`) inside a component of a chosen domain, by default `comms`. A sink is any function in a
component of a sensitive domain: `security` (kind crypto), `storage` and `boot_update` (kind update). For each
entry point and sink kind the shortest chain of calls that crosses from one component to another is reported,
function by function, with the components it passes through. Where a function on the path calls an API in the
CBOM catalogue, the API and its catalogue entry are listed so the path can be matched with the CBOM.

`architecture.trust_entries` and `architecture.trust_sinks` replace the defaults. An item is a mapping with
exactly one of `domain`, `component` or `function` (a name pattern); a sink also has a `kind` label. A `function`
entry is always an entry point; a `domain` or `component` entry counts only functions nothing in the project calls.

Calls are the direct call graph: a path through a function pointer or a dispatch table is not seen.
"""

from __future__ import annotations

from collections import deque
from fnmatch import fnmatchcase

from fwlens.arch.edges import norm
from fwlens.arch.model import ArchModel
from fwlens.config import ConfigError
from fwlens.model.project import ProjectModel

ROWS = 30
MAX_DEPTH = 10
DEFAULT_ENTRIES = [{"domain": "comms"}]
DEFAULT_SINKS = [{"kind": "crypto", "domain": "security"}, {"kind": "storage", "domain": "storage"},
                 {"kind": "update", "domain": "boot_update"}]
_MATCHERS = ("domain", "component", "function")


def validate(entries, sinks) -> None:
    for key, items, extra in (("trust_entries", entries, set()), ("trust_sinks", sinks, {"kind"})):
        for i, item in enumerate(items or []):
            keys = set(item) if isinstance(item, dict) else set()
            matcher = keys & set(_MATCHERS)
            if (not isinstance(item, dict) or len(matcher) != 1 or keys - set(_MATCHERS) - extra
                    or not all(isinstance(v, str) and v for v in item.values())
                    or ("kind" in extra and "kind" not in item)):
                need = "a `kind` and " if extra else ""
                raise ConfigError(f"architecture.{key}[{i}] needs {need}exactly one of {list(_MATCHERS)}")


def _matches(item: dict, function: str, component: str, domain: str) -> bool:
    if "domain" in item:
        return domain == item["domain"]
    if "component" in item:
        return component == item["component"]
    return fnmatchcase(function, item["function"])


def compute(model: ProjectModel, arch: ArchModel, config) -> list[dict]:
    cfg = config.architecture
    entries = cfg.trust_entries or DEFAULT_ENTRIES
    sinks = cfg.trust_sinks or DEFAULT_SINKS
    comp_of = {u: c.name for c in arch.components for u in c.units}
    domain_of = {s.name: s.domain for s in arch.subsystems}

    funcs: dict = {}
    for m in model.modules:
        comp = comp_of.get(norm(m.path), "")
        for f in m.functions:
            funcs.setdefault(f.name, (f, comp, domain_of.get(comp, "")))
    called = {c for f, _c, _d in funcs.values() for c in f.callees if c in funcs and c != f.name}

    matcher = _catalog_matcher(config)
    out: list[dict] = []
    for name, (fn, comp, domain) in sorted(funcs.items()):
        is_entry = any(_matches(e, name, comp, domain) and ("function" in e or fn.is_isr or fn.is_entry_point
                                                            or name not in called) for e in entries)
        if not is_entry or not comp:
            continue
        parent: dict = {name: None}
        queue = deque([(name, 0)])
        found: dict = {}
        while queue:
            current, depth = queue.popleft()
            _f, ccomp, cdomain = funcs[current]
            if current != name and ccomp != comp:
                for s in sinks:
                    if s["kind"] not in found and _matches(s, current, ccomp, cdomain):
                        found[s["kind"]] = current
            if depth >= MAX_DEPTH:
                continue
            for callee in funcs[current][0].callees:
                if callee in funcs and callee not in parent:
                    parent[callee] = current
                    queue.append((callee, depth + 1))
        for kind, sink in sorted(found.items()):
            chain = []
            at = sink
            while at is not None:
                chain.append(at)
                at = parent[at]
            chain.reverse()
            hops = [{"function": f, "component": funcs[f][1], "domain": funcs[f][2]} for f in chain]
            crossings = [f"{a['component']} -> {b['component']}" for a, b in zip(hops, hops[1:])
                         if a["component"] != b["component"]]
            apis: list[dict] = []
            for f in chain:
                for callee in funcs[f][0].callees:
                    hit = matcher.lookup(callee) if matcher else None
                    if hit and callee not in funcs and all(a["api"] != callee for a in apis):
                        apis.append({"api": callee, "library": hit[0].id, "entry": hit[1].id, "in": f})
            out.append({"entry": name, "kind": kind, "sink": sink, "path": hops, "crossings": crossings,
                        "crypto_apis": apis[:5]})
    out.sort(key=lambda r: (len(r["crossings"]), len(r["path"]), r["entry"], r["kind"]))
    return out[:ROWS]


def _catalog_matcher(config):
    from fwlens.crypto.catalog import Matcher, load_catalog
    try:
        return Matcher(load_catalog(config.cbom.extra_catalog_dirs))
    except ConfigError:
        return None
