"""
The architecture brief: one JSON document that tells a reader (a person, or an LLM) how a firmware
code base is built, what runs when, and where each cross-cutting concern lives. It joins facts
FWLens already computes (the parse, call graph, RTOS objects, state machines, architecture model,
git history, linker map) with lexical ones read here (comments, types, constants, log strings,
interrupt priorities, peripherals, start-up order, linker memory regions) and the concern catalogue
in concerns.yaml (clock and time, firmware update, power, watchdog, storage, comms, security, logging).
"""

from __future__ import annotations

import os
import subprocess
from collections import Counter, defaultdict, deque
from dataclasses import asdict, dataclass, field
from pathlib import Path

from fwlens import __version__
from fwlens.brief import concerns as concern_mod
from fwlens.brief.source import SourceFile, collapse, memory_regions, peripheral_of_call, register_peripheral
from fwlens.crypto.keywords import words_of
from fwlens.identity import project_root, relative_posix
from fwlens.model.project import BoundaryClass, FunctionMetrics, ProjectModel

SCHEMA = "fwlens-brief/1"
REACHED_FROM_KEPT = 20
DOCS_KEPT = 60
LINKER_SCRIPTS_KEPT = 20
VOCABULARY_KEPT = 150
WALK_DEPTH = 8                               # folder levels searched for documents and linker scripts
TOP = 25                                     # rows kept in each "top" quality list
HEADER_SUFFIXES = {".h", ".hh", ".hpp", ".hxx", ".inc"}
SCHEDULER_START = {"vTaskStartScheduler", "osKernelStart", "OS_Start", "OS_Go", "tx_kernel_enter", "rt_system_scheduler_start",
                   "k_thread_start", "OSStart", "vTaskStartScheduler_", "chSysInit"}
_LINKER_SUFFIXES = {".ld", ".lds", ".icf", ".sct"}
_DOC_SUFFIXES = {".md", ".rst", ".txt", ".adoc"}
_SKIP_DIRS = {".git", "build", "out", "output", "node_modules", ".venv", "venv", "__pycache__", "debug", "release",
              ".cache", "dist", "cmake-build-debug", "cmake-build-release"}
_STOP_WORDS = {"get", "set", "init", "is", "the", "a", "an", "to", "of", "in", "on", "for", "and", "or", "by", "with",
               "t", "s", "p", "x", "i", "n", "c", "v", "u", "e", "b", "id", "no", "do", "if", "it", "be", "at", "as"}
_TEST_DIRS = {"test", "tests", "unittest", "unittests", "unit_tests", "ut", "testing"}

HOW_TO_READ = [
    "This file was written by FWLens (fwlens architecture brief) from a static analysis of the source. Nothing was run.",
    "Paths are relative to the repository root. Lines are 1-based. Every finding names the file and line it came from, so it can be checked against the code.",
    "Most sections are heuristics on names, calls and text: 'roles' in concerns, state machines, the start-up sequence, log strings, types and constants. Treat them as leads to read, not as proof.",
    "'not_found' and 'gaps' mean that FWLens did not detect something, not that the code lacks it. Code behind #if branches that this build configuration does not compile is not seen.",
    "Comments ('doc', 'header_comment') are the authors' own words and may be out of date.",
    "Call graph facts (callers, callees, reached_from) come from direct calls, plus calls through dispatch tables FWLens recognised; other calls through function pointers are missing.",
    "Sections: meta, build, files, directories, architecture, execution (entry points, start-up, RTOS), interrupts, peripherals, state_machines, concerns (clock and time, firmware update, power, watchdog, storage, comms, security, logging), memory, interfaces, types, constants, globals, symbols, log_messages, quality, history, tests, documents, vocabulary, gaps.",
]


@dataclass
class Fn:
    """A first-party function with what the brief needs from its source."""
    name: str
    file: Path
    rel: str
    line: int
    callees: list
    is_isr: bool
    metrics: FunctionMetrics
    src: SourceFile | None = None
    body: str = ""
    body_start: int = 0
    end_line: int = 0
    doc: str = ""
    signature: str = ""
    callers: list = field(default_factory=list)

    def line_at(self, pos: int) -> int:
        """File line of an offset in `body`."""
        return self.src.line_of(self.body_start + pos) if self.src else self.line


@dataclass
class _Global:
    name: str
    file: str
    is_volatile: bool
    readers: list
    writers: list
    isr_readers: list
    isr_writers: list
    volatile_risk: bool


def build_brief(model: ProjectModel, config) -> dict:
    root = project_root(config)

    def rel(p) -> str:
        return relative_posix(p, root)

    modules = model.first_party_modules()
    headers = _first_party_headers(model)
    sources: dict[str, SourceFile] = {}
    for path in [Path(m.path) for m in modules] + headers:
        key = rel(path)
        if key in sources:
            continue
        try:
            sources[key] = SourceFile(path, path.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue

    fns = _functions(model, sources, rel)
    by_name: dict[str, list[Fn]] = defaultdict(list)
    for f in fns:
        by_name[f.name].append(f)
    callees_of = _call_graph(model, fns)
    callers_of: dict[str, set] = defaultdict(set)
    for a, bs in callees_of.items():
        for b in bs:
            callers_of[b].add(a)
    for f in fns:
        f.callers = sorted(callers_of.get(f.name, ()))

    entries = _entry_points(model, config, fns, by_name)
    reached_from: dict[str, list] = defaultdict(list)
    reach_count = {}
    for e in entries:
        seen = _reach(e["function"], callees_of)
        reach_count[e["name"]] = seen
        for n in sorted(seen):
            if len(reached_from[n]) < REACHED_FROM_KEPT:
                reached_from[n].append(e["name"])
    isr_names = {e["name"] for e in entries if e["kind"] == "isr"}

    catalogue = concern_mod.load_catalogue()
    concerns = concern_mod.analyse(fns, catalogue, reached_from)
    concern_of: dict[str, list] = defaultdict(list)
    for cid, c in concerns.items():
        for n in c["functions"]:
            concern_of[n].append(cid)
    globals_ = [_Global(g.name, rel(g.file), g.is_volatile, list(g.readers), list(g.writers), list(g.isr_readers),
                        list(g.isr_writers), g.volatile_risk) for g in model.globals]
    concerns["time"]["findings"] = concern_mod.time_findings(fns, concerns, globals_, isr_names, reached_from)
    concerns["update"]["flow"] = concern_mod.update_flow(concerns, callees_of)

    arch = model.architecture
    component_of, domain_of, level_of = _component_maps(arch, rel)

    for e in entries:
        seen = reach_count[e["name"]]
        e["reaches"] = len(seen)
        e["concerns"] = sorted({c for n in seen for c in concern_of.get(n, [])})

    brief = {
        "schema": SCHEMA,
        "how_to_read": HOW_TO_READ,
        "meta": _meta(model, config, root, modules, fns),
        "build": _build(model, rel),
        "files": _files(model, sources, modules, headers, rel, component_of, domain_of, level_of),
        "directories": _directories(sources, fns, component_of),
        "architecture": _architecture(arch, rel),
        "execution": {
            "entry_points": entries,
            "startup": _startup(model, config, by_name, concern_of),
            "rtos": _rtos(model, rel),
        },
        "interrupts": _interrupts(fns, sources, reached_from, model, rel),
        "peripherals": _peripherals(fns),
        "state_machines": _state_machines(model, fns, sources, reached_from, rel),
        "concerns": concerns,
        "memory": _memory(model, config, arch, root, rel),
        "interfaces": _interfaces(model, arch, rel),
        "types": _types(sources),
        "constants": _constants(sources),
        "globals": [asdict(g) | {"concerns": sorted({c for n in g.readers + g.writers for c in concern_of.get(n, [])})}
                    for g in globals_],
        "symbols": [_symbol(f, reached_from, concern_of, component_of) for f in fns],
        "log_messages": _log_messages(fns),
        "quality": _quality(model, rel),
        "history": _history(model, rel),
        "tests": _tests(fns),
        "documents": _documents(root, rel),
        "vocabulary": _vocabulary(fns, model, sources),
    }
    brief["gaps"] = _gaps(model, brief, rel)
    return _relative_paths(brief, root)


def _relative_paths(obj, root: Path):
    """Absolute paths under the repository root, wherever they appear (some sections reuse
    records from other stages), made relative to it."""
    prefixes = sorted({root.as_posix().rstrip("/") + "/", root.resolve().as_posix().rstrip("/") + "/"}, key=len, reverse=True)

    def fix(o):
        if isinstance(o, dict):
            return {k: fix(v) for k, v in o.items()}
        if isinstance(o, (list, tuple)):
            return [fix(v) for v in o]
        if isinstance(o, Path):
            o = o.as_posix()
        if isinstance(o, str) and ("/" in o or "\\" in o):
            s = o.replace("\\", "/")
            for p in prefixes:
                if s.startswith(p):
                    return s[len(p):]
        return o
    return fix(obj)


# -- collection -----------------------------------------------------------------------------

def _first_party_headers(model: ProjectModel) -> list[Path]:
    """Headers the first-party units include whose nearest unit (by directory) is first party."""
    dirs: dict[str, set] = {}
    for m in model.modules:
        dirs.setdefault(str(Path(m.path).parent), set()).add(m.boundary_class)
    found = set()
    for m in model.first_party_modules():
        for a, b in list(m.all_include_edges) + [(m.path, i) for i in m.includes]:
            for h in (a, b):
                p = Path(h)
                if p.suffix.lower() in HEADER_SUFFIXES and _nearest_first_party(p, dirs):
                    found.add(p)
    return sorted(found)


def _nearest_first_party(path: Path, dirs: dict) -> bool:
    best, classes = -1, set()
    parts = path.parent.parts
    for d, cls in dirs.items():
        dp = Path(d).parts
        common = 0
        for x, y in zip(parts, dp):
            if x != y:
                break
            common += 1
        if common > best:
            best, classes = common, set(cls)
        elif common == best:
            classes |= cls
    return best > 0 and classes == {BoundaryClass.FIRST_PARTY}


def _functions(model, sources, rel) -> list[Fn]:
    out = []
    for m in model.first_party_modules():
        key = rel(m.path)
        src = sources.get(key)
        for f in m.functions:
            fn = Fn(f.name, Path(f.file), rel(f.file), f.line, sorted(set(f.callees)), f.is_isr, f)
            src_f = sources.get(rel(f.file)) or src
            if src_f is not None:
                fn.src = src_f
                body = src_f.body_at(f.line)
                if body:
                    fn.body = src_f.code[body.start:body.end]
                    fn.body_start = body.start
                    fn.end_line = body.end_line
                fn.doc = src_f.comment_before(f.line)
                fn.signature = src_f.signature_at(f.line, f.name)
            out.append(fn)
    out.sort(key=lambda f: (f.rel, f.line))
    return out


def _call_graph(model, fns) -> dict[str, set]:
    """Direct calls, plus a dispatcher calling every function stored in a table it reads."""
    graph: dict[str, set] = defaultdict(set)
    for f in fns:
        graph[f.name].update(f.callees)
    for t in model.dispatch_tables:
        for d in t.dispatchers:
            graph[d].update(t.stored_fns)
    return graph


def _reach(start: str, graph: dict) -> set:
    seen = {start}
    queue = deque([start])
    while queue:
        for nxt in graph.get(queue.popleft(), ()):
            if nxt not in seen:
                seen.add(nxt)
                queue.append(nxt)
    return seen


def _entry_points(model, config, fns, by_name) -> list[dict]:
    out, seen = [], set()

    def add(name, kind, function, **extra):
        if name in seen:
            return
        seen.add(name)
        f = by_name.get(function, [None])[0]
        entry = {"name": name, "kind": kind, "function": function,
                 "file": f.rel if f else "", "line": f.line if f else 0, "doc": f.doc if f else ""}
        entry.update(extra)
        if f:
            entry["calls"] = f.callees
        out.append(entry)

    for name in ["Reset_Handler"] + list(config.entry_points or []):
        if name in by_name:
            add(name, "reset" if name == "Reset_Handler" else "main", name)
    for t in model.rtos_tasks:
        add(t.name or t.entry_function, "task", t.entry_function, priority=t.priority_value if t.priority_value is not None
            else t.priority_expr, stack_size=t.stack_size_value if t.stack_size_value is not None else t.stack_size_expr,
            created_by=t.creation_function)
    for f in fns:
        if f.is_isr:
            add(f.name, "isr", f.name)
    return out


def _component_maps(arch, rel):
    component_of, domain_of, level_of = {}, {}, {}
    if arch is None:
        return component_of, domain_of, level_of
    domains = {s.name: s for s in arch.subsystems}
    for c in arch.components:
        for u in c.units:
            component_of[rel(u)] = c.name
            if c.name in domains:
                domain_of[rel(u)] = domains[c.name].domain
            if c.name in arch.layering.level_of:
                level_of[rel(u)] = arch.layering.level_of[c.name]
    return component_of, domain_of, level_of


# -- sections -------------------------------------------------------------------------------

def _git_revision(root: Path) -> str:
    try:
        out = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True, timeout=10)
        return out.stdout.strip() if out.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def _meta(model, config, root, modules, fns) -> dict:
    return {
        "tool": "fwlens", "version": __version__,
        "project": config.config_path.parent.name if config.config_path else "",
        "configuration": model.configuration,
        "mode": config.project.mode,
        "git_revision": _git_revision(root),
        "rtos": model.rtos_kind or "",
        "counts": {"source_files": len(modules), "functions": len(fns),
                   "lines_of_code": sum(m.file_sloc or m.loc for m in modules),
                   "rtos_tasks": len(model.rtos_tasks), "isrs": sum(1 for f in fns if f.is_isr),
                   "state_machines": len(model.state_machines)},
    }


def _build(model, rel) -> dict:
    units = [tu for tu in model.translation_units if getattr(tu, "boundary_class", None) == BoundaryClass.FIRST_PARTY] \
        or list(model.translation_units)
    if not units:
        return {"common_defines": [], "per_file_defines": {}, "include_paths": [], "flags": []}
    common = set(units[0].defines)
    for tu in units[1:]:
        common &= set(tu.defines)
    return {
        "configuration": model.configuration,
        "common_defines": sorted(common),
        "per_file_defines": {rel(tu.path): sorted(set(tu.defines) - common) for tu in units if set(tu.defines) - common},
        "include_paths": sorted({rel(p) for tu in units for p in tu.include_paths}),
        "flags": sorted({a for tu in units for a in getattr(tu, "extra_args", [])}),
    }


def _files(model, sources, modules, headers, rel, component_of, domain_of, level_of) -> list[dict]:
    by_path = {rel(m.path): m for m in modules}
    out = []
    for key in sorted(sources):
        src = sources[key]
        m = by_path.get(key)
        entry = {"path": key, "kind": "header" if Path(key).suffix.lower() in HEADER_SUFFIXES else "source",
                 "header_comment": src.header_comment(), "lines": src.raw.count("\n") + 1,
                 "component": component_of.get(key, ""), "domain": domain_of.get(key, ""),
                 "level": level_of.get(key)}
        if m is not None:
            entry.update({
                "layer": m.layer or "", "sloc": m.file_sloc, "comment_ratio": round(m.file_comment_ratio, 3),
                "functions": [f.name for f in m.functions], "includes": sorted({rel(i) for i in m.includes}),
                "flash_bytes": m.flash_bytes, "ram_bytes": m.ram_bytes, "commit_count": m.commit_count,
                "main_author": m.main_author, "max_cc": m.max_cc, "zone": m.zone,
                "parse_errors": sum(1 for d in m.parse_diagnostics if d.get("severity") in ("error", "fatal")),
            })
        out.append(entry)
    return out


def _directories(sources, fns, component_of) -> list[dict]:
    files: dict[str, list] = defaultdict(list)
    for key in sources:
        files[str(Path(key).parent.as_posix())].append(key)
    fn_count = Counter(str(Path(f.rel).parent.as_posix()) for f in fns)
    out = []
    for d in sorted(files):
        comps = sorted({component_of[k] for k in files[d] if k in component_of})
        out.append({"path": d, "files": sorted(Path(k).name for k in files[d]),
                    "lines": sum(sources[k].raw.count("\n") + 1 for k in files[d]),
                    "functions": fn_count.get(d, 0), "components": comps})
    return out


def _architecture(arch, rel) -> dict | None:
    if arch is None:
        return None
    from fwlens.arch.layers import component_graph
    domains = {s.name: s for s in arch.subsystems}
    components = []
    for c in arch.components:
        s = domains.get(c.name)
        components.append({"name": c.name, "files": [rel(u) for u in c.units], "found_by": c.source,
                           "cohesion": round(c.cohesion, 3), "configured_layer": c.layer,
                           "level": arch.layering.level_of.get(c.name),
                           "domain": s.domain if s else "unclassified", "domain_name": s.domain_name if s else "",
                           "domain_confidence": s.confidence if s else "", "domain_evidence": s.evidence if s else []})
    graph = component_graph(arch.components, arch.edges)
    deps = [{"from": a, "to": b, "kinds": sorted(d.get("kinds", [])), "weight": round(d.get("weight", 0.0), 2)}
            for a, b, d in sorted(graph.edges(data=True))]
    return {
        "components": components,
        "dependencies": deps,
        "layers": arch.layering.layers,
        "cycles": arch.layering.cycles,
        "next_layer_share": arch.layering.next_layer_share,
        "patterns": [asdict(p) for p in arch.patterns],
        "violations": [asdict(v) | {"file": rel(v.file) if v.file else ""} for v in arch.violations],
        "leaks": [asdict(lk) | {"file": rel(lk.file)} for lk in arch.leaks],
        "events": [asdict(e) for e in arch.events],
        "interface_catalogue": arch.interface_catalogue,
        "trust_paths": arch.trust_paths,
        "cycle_suggestions": arch.cycle_suggestions,
        "drift": [asdict(d) | {"unit": rel(d.unit)} for d in arch.drift],
    }


def _startup(model, config, by_name, concern_of) -> dict:
    """What main does, in order, up to the scheduler start or the main loop, and what the loop calls."""
    names = [n for n in list(config.entry_points or []) + ["main"] if n in by_name]
    if not names:
        return {"function": "", "sequence": [], "scheduler_start": None, "main_loop": None}
    f = by_name[names[0]][0]
    if not f.src or not f.body:
        return {"function": f.name, "sequence": [], "scheduler_start": None, "main_loop": None}
    src, start, end = f.src, f.body_start, f.body_start + len(f.body)
    loop = src.first_loop(start, end)
    stop = loop[0] if loop else end
    sequence, scheduler = [], None
    for name, line in src.calls_in(start, stop):
        step = {"call": name, "line": line, "concerns": concern_of.get(name, [])}
        callee = by_name.get(name)
        if callee and callee[0].body and callee[0].src and _is_setup(name):
            g = callee[0]
            step["calls"] = [{"call": n, "line": ln, "file": g.rel, "concerns": concern_of.get(n, [])}
                             for n, ln in g.src.calls_in(g.body_start, g.body_start + len(g.body))]
        sequence.append(step)
        if name in SCHEDULER_START:
            scheduler = {"call": name, "line": line}
            break
    main_loop = None
    if loop and loop[1] is not None and scheduler is None:
        body = loop[1]
        main_loop = {"line": src.line_of(loop[0]),
                     "calls": [{"call": n, "line": ln, "concerns": concern_of.get(n, [])}
                               for n, ln in src.calls_in(body.start, body.end)]}
    return {"function": f.name, "file": f.rel, "sequence": sequence, "scheduler_start": scheduler, "main_loop": main_loop}


def _is_setup(name: str) -> bool:
    return bool(set(words_of(name)) & {"init", "setup", "config", "configure", "start", "startup", "boot", "initialise",
                                        "initialize", "bsp", "board", "system", "platform", "hw"})


def _rtos(model, rel) -> dict:
    def ser(obj):
        d = asdict(obj)
        if "file" in d:
            d["file"] = rel(d["file"])
        return d
    return {"kind": model.rtos_kind or "", "tasks": [ser(t) for t in model.rtos_tasks],
            "sync_objects": [ser(o) for o in model.rtos_sync_objects],
            "object_usages": [ser(u) for u in model.rtos_object_usages],
            "priority_collisions": [asdict(c) for c in model.rtos_priority_collisions],
            "inversion_risks": [asdict(r) for r in model.rtos_inversion_risks],
            "unused_objects": [ser(o) for o in model.rtos_unused_objects]}


def _interrupts(fns, sources, reached_from, model, rel) -> dict:
    nvic = []
    for key, src in sorted(sources.items()):
        for entry in src.nvic():
            nvic.append(entry | {"file": key})
    shared = defaultdict(list)
    for g in model.globals:
        for isr in set(g.isr_readers) | set(g.isr_writers):
            shared[isr].append({"global": g.name, "volatile": g.is_volatile, "risk": g.volatile_risk})
    stack = {r.function_name: r for r in model.entry_point_stack_risks if r.is_isr}
    handlers = []
    for f in fns:
        if not f.is_isr:
            continue
        s = stack.get(f.name)
        handlers.append({"name": f.name, "file": f.rel, "line": f.line, "doc": f.doc, "calls": f.callees,
                         "cyclomatic_complexity": f.metrics.cyclomatic_complexity, "shared_globals": shared.get(f.name, []),
                         "stack_estimate": s.stack_depth_estimate if s else f.metrics.stack_depth_estimate})
    return {"handlers": handlers, "priorities": nvic, "risks": [asdict(r) | {"file": rel(r.file)} for r in model.isr_risks]}


def _peripherals(fns) -> list[dict]:
    uses: dict[str, dict] = defaultdict(lambda: {"functions": set(), "files": set(), "via": set()})
    for f in fns:
        for c in f.callees:
            p = peripheral_of_call(c)
            if p:
                uses[p]["functions"].add(f.name)
                uses[p]["files"].add(f.rel)
                uses[p]["via"].add(c)
        if f.src and f.body:
            for reg in f.src.registers(f.body_start, f.body_start + len(f.body)):
                p = register_peripheral(reg)
                uses[p]["functions"].add(f.name)
                uses[p]["files"].add(f.rel)
                uses[p]["via"].add(reg + "->")
    return [{"peripheral": p, "functions": sorted(u["functions"]), "files": sorted(u["files"]), "via": sorted(u["via"])[:30]}
            for p, u in sorted(uses.items())]


def _state_machines(model, fns, sources, reached_from, rel) -> list[dict]:
    enums = [(key, e) for key, src in sorted(sources.items()) for e in src.enums()]
    by_fn = {f.name: f for f in fns}
    out = []
    for sm in model.state_machines:
        f = by_fn.get(sm.function_name)
        entry = {"kind": "switch", "function": sm.function_name, "file": rel(sm.file), "line": sm.line,
                 "state_variable": sm.state_var, "states": sm.states,
                 "transitions": [{"from": a, "to": b} for a, b in sm.transitions], "case_count": sm.case_count,
                 "driven_by": reached_from.get(sm.function_name, []), "doc": f.doc if f else ""}
        entry.update(_resolve_enum(sm.states, enums))
        out.append(entry)
    out.extend(_function_pointer_machines(fns, reached_from))
    return out


def _resolve_enum(states: list, enums: list) -> dict:
    """The enum whose constants the states use, the states as constant names, and the constants
    no transition reaches."""
    best, score = None, 0
    for key, e in enums:
        names = {c["name"] for c in e["constants"]}
        values = {c["value"] for c in e["constants"] if isinstance(c["value"], int)}
        hits = sum(1 for s in states if s in names or (_as_int(s) is not None and _as_int(s) in values))
        named = sum(1 for s in states if s in names)
        if named and hits > score:
            best, score = (key, e), hits
    if not best:
        return {}
    key, e = best
    by_value = {c["value"]: c["name"] for c in e["constants"] if isinstance(c["value"], int)}
    resolved = sorted({s if _as_int(s) is None else by_value.get(_as_int(s), s) for s in states})
    constants = [c["name"] for c in e["constants"]]
    return {"enum": {"name": e["name"], "file": key, "line": e["line"], "doc": e["doc"]},
            "resolved_states": resolved,
            "unreached_constants": [n for n in constants if n not in resolved and not n.upper().endswith(("COUNT", "MAX", "NUM", "LAST", "END"))]}


def _as_int(text: str):
    try:
        return int(str(text).rstrip("uUlL"), 0)
    except ValueError:
        return None


def _function_pointer_machines(fns, reached_from) -> list[dict]:
    """A variable assigned two or more different functions, each assignment a transition: the
    state-as-function-pointer style (s_state = st_idle; ... s_state();)."""
    import re
    names = {f.name for f in fns}
    assign = re.compile(r"(?<![=!<>])\b((?:[A-Za-z_]\w*)(?:(?:\.|->)[A-Za-z_]\w*)*)\s*=\s*&?\s*([A-Za-z_]\w*)\s*;")
    targets: dict[str, list] = defaultdict(list)
    for f in fns:
        for m in assign.finditer(f.body):
            var, fn = m.group(1), m.group(2)
            if fn in names and fn != var:
                targets[var].append((f, fn, f.line_at(m.start())))
    out = []
    for var, uses in sorted(targets.items()):
        states = sorted({fn for _, fn, _ in uses})
        if len(states) < 2:
            continue
        called = any(re.search(rf"(?:\(\s*\*\s*)?\b{re.escape(var)}\s*\)?\s*\(", f.body) for f in fns)
        transitions = sorted({(f.name if f.name in states else f"(from {f.name})", fn) for f, fn, _ in uses})
        first = uses[0]
        out.append({"kind": "function_pointer", "state_variable": var, "file": first[0].rel, "line": first[2],
                    "states": states, "transitions": [{"from": a, "to": b} for a, b in transitions],
                    "called_through": called, "confidence": "medium" if called else "low",
                    "driven_by": sorted({e for s in states for e in reached_from.get(s, [])})[:REACHED_FROM_KEPT],
                    "assignments": [{"function": f.name, "to": fn, "line": ln} for f, fn, ln in uses][:40]})
    return out


def _memory(model, config, arch, root, rel) -> dict:
    found = [p for p in _walk(root, "*") if p.suffix.lower() in _LINKER_SUFFIXES]
    scripts = [{"path": rel(p), "regions": memory_regions(p)} for p in found[:LINKER_SCRIPTS_KEPT]]
    modules = model.first_party_modules()
    map_file = config.project.map_file
    return {
        "linker_scripts": scripts,
        "map_file": rel(map_file) if map_file else "",
        "map_totals": dict(model.footprint or {}),
        "first_party_flash_bytes": sum(m.flash_bytes for m in modules),
        "first_party_ram_bytes": sum(m.ram_bytes for m in modules),
        "by_component": arch.footprint if arch is not None else [],
    }


def _walk(root: Path, pattern: str):
    """Files under `root` matching a glob, skipping build output, VCS and environment folders."""
    from fnmatch import fnmatch
    base = len(root.parts)
    for dirpath, dirnames, filenames in os.walk(root):
        depth = len(Path(dirpath).parts) - base
        dirnames[:] = sorted(d for d in dirnames if d.lower() not in _SKIP_DIRS and not d.startswith(".")
                             and depth < WALK_DEPTH)
        for name in sorted(filenames):
            if fnmatch(name.lower(), pattern):
                yield Path(dirpath) / name


def _interfaces(model, arch, rel) -> dict:
    return {
        "dispatch_tables": [{"name": t.var_name, "file": rel(t.file), "line": t.line, "handlers": t.stored_fns,
                             "dispatched_by": t.dispatchers, "registered_into": t.registered_into}
                            for t in model.dispatch_tables],
        "public_functions": [asdict(i) | {"unit": rel(i.unit)} for i in arch.interfaces] if arch is not None else [],
        "ops_headers": [rel(h) for h in arch.ops_headers] if arch is not None else [],
    }


def _types(sources) -> dict:
    enums, structs = [], []
    for key, src in sorted(sources.items()):
        enums += [e | {"file": key} for e in src.enums()]
        structs += [s | {"file": key} for s in src.structs()]
    return {"enums": enums, "structs": structs}


def _constants(sources) -> list[dict]:
    return [d | {"file": key} for key, src in sorted(sources.items()) for d in src.defines()]


def _symbol(f: Fn, reached_from, concern_of, component_of) -> dict:
    m = f.metrics
    return {
        "name": f.name, "file": f.rel, "line": f.line, "end_line": f.end_line, "signature": f.signature, "doc": f.doc,
        "component": component_of.get(f.rel, ""), "is_isr": f.is_isr, "is_entry_point": m.is_entry_point,
        "callers": f.callers, "callees": f.callees, "global_reads": m.global_reads, "global_writes": m.global_writes,
        "dispatch_tables_read": m.dispatch_table_reads, "indirect_calls": m.indirect_call_count,
        "reached_from": reached_from.get(f.name, []), "concerns": concern_of.get(f.name, []),
        "loc": m.loc, "cyclomatic_complexity": m.cyclomatic_complexity, "cognitive_complexity": m.cognitive_complexity,
        "parameters": [{"name": p.name, "type": p.type_spelling} for p in m.parameters],
        "stack_estimate": m.stack_depth_estimate, "composite_risk": round(m.composite_risk_score, 3),
        "dead_candidate": m.is_dead_candidate, "magic_numbers": m.magic_numbers[:10],
    }


def _log_messages(fns) -> list[dict]:
    out = []
    for f in fns:
        if f.src and f.body:
            for entry in f.src.log_strings(f.body_start, f.body_start + len(f.body)):
                out.append(entry | {"function": f.name, "file": f.rel})
    return out


def _quality(model, rel) -> dict:
    fp = model.first_party_functions()

    def fn_row(f, **extra):
        return {"name": f.name, "file": rel(f.file), "line": f.line} | extra
    return {
        "most_complex": [fn_row(f, cyclomatic=f.cyclomatic_complexity, cognitive=f.cognitive_complexity, loc=f.loc)
                         for f in sorted(fp, key=lambda f: (-f.cognitive_complexity, f.name))[:TOP]],
        "composite_risk": [fn_row(f, score=round(f.composite_risk_score, 3)) for f in model.composite_risk[:TOP]],
        "hotspots": [fn_row(f, score=round(f.hotspot_score, 3)) for f in model.hotspots[:TOP]] if model.git_available else [],
        "bugfix_hotspots": [fn_row(f, score=round(f.bugfix_hotspot_score, 3)) for f in model.bugfix_hotspots[:TOP]]
        if model.git_available else [],
        "dead_candidates": [fn_row(f) for f in model.dead_candidates],
        "clones": [{"a": p.function_a, "file_a": rel(p.file_a), "b": p.function_b, "file_b": rel(p.file_b),
                    "similarity": p.similarity} for p in model.clone_pairs[:TOP]],
        "todo_markers": [{"tag": t.tag, "file": rel(t.file), "line": t.line, "text": t.text} for t in model.todo_markers],
        "stack_risks": [asdict(r) | {"file": rel(r.file)} for r in model.entry_point_stack_risks],
        "include_cycles": [[rel(p) for p in c.files] for c in model.include_cycles],
        "missing_include_guards": [rel(g.file) for g in model.missing_include_guards],
        "layer_violations": [{"from": rel(v.source_module), "from_layer": v.source_layer, "to": rel(v.target_module),
                              "to_layer": v.target_layer, "kind": v.violation_type} for v in model.arch_violations],
    }


def _history(model, rel) -> dict:
    if not model.git_available:
        return {"git_available": False}
    arch = model.architecture
    return {
        "git_available": True,
        "ownership_risks": [{"file": rel(m.path), "commits": m.commit_count, "main_author": m.main_author,
                             "main_author_share": round(m.main_author_share, 3), "authors": m.distinct_author_count}
                            for m in model.ownership_risks[:TOP]],
        "change_coupling": [{"a": rel(p.file_a), "b": rel(p.file_b), "co_changes": p.co_changes,
                             "coupling": round(p.coupling, 3), "surprising": p.surprising}
                            for p in model.change_coupling[:TOP * 2]],
        "commit_activity": [asdict(c) for c in model.commit_activity][-90:],
        "complexity_trends": [{"file": rel(t.file), "trend": t.trend, "slope": t.slope} for t in model.complexity_trends],
        "by_component": arch.activity if arch is not None else {},
    }


def _tests(fns) -> dict:
    def is_test(f: Fn) -> bool:
        parts = [p.lower() for p in Path(f.rel).parts]
        stem = Path(f.rel).stem.lower()
        return bool(set(parts[:-1]) & _TEST_DIRS) or stem.startswith("test_") or stem.endswith(("_test", "_tests"))
    tests = [f for f in fns if is_test(f)]
    product = [f for f in fns if not is_test(f)]
    called = {c for t in tests for c in t.callees}
    return {"test_files": sorted({t.rel for t in tests}), "test_functions": len(tests),
            "functions_called_by_tests": sorted(f.name for f in product if f.name in called),
            "functions_not_called_by_tests": len([f for f in product if f.name not in called]) if tests else None}


def _documents(root: Path, rel) -> list[dict]:
    out: list[dict] = []
    for p in sorted(_walk(root, "*")):
        if p.suffix.lower() not in _DOC_SUFFIXES or len(out) >= DOCS_KEPT:
            continue
        if p.suffix.lower() == ".txt" and not p.stem.lower().startswith(("readme", "notes", "design", "changelog", "history")):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        title = next((ln.lstrip("#= ").strip() for ln in text.splitlines() if ln.strip()), "")
        paras = [b for b in text.split("\n\n") if b.strip() and not b.lstrip().startswith(("#", "```", "<!--"))]
        out.append({"path": rel(p), "title": collapse(title, 160), "summary": collapse(paras[0] if paras else "", 600),
                    "lines": text.count("\n") + 1})
    return out


def _vocabulary(fns, model, sources) -> list[dict]:
    counts: Counter = Counter()
    for f in fns:
        counts.update(words_of(f.name))
    for g in model.globals:
        counts.update(words_of(g.name))
    for src in sources.values():
        for e in src.enums():
            counts.update(w for c in e["constants"] for w in words_of(c["name"]))
    return [{"word": w, "count": n} for w, n in counts.most_common() if w not in _STOP_WORDS and len(w) > 1][:VOCABULARY_KEPT]


def _gaps(model, brief, rel) -> list[str]:
    gaps = []
    failed = [rel(m.path) for m in model.first_party_modules()
              if any(d.get("severity") in ("error", "fatal") for d in m.parse_diagnostics)]
    if failed:
        gaps.append(f"{len(failed)} file(s) parsed with errors, so their facts may be incomplete: {', '.join(failed[:20])}")
    if model.architecture is None:
        gaps.append("the architecture model is off (architecture.enabled: false), so components, layers and patterns are empty")
    if not model.git_available:
        gaps.append("no git history, so hotspots, ownership and change coupling are empty")
    if not brief["execution"]["startup"]["sequence"]:
        gaps.append("no start-up sequence found (no main, or its body could not be read)")
    for cid, c in brief["concerns"].items():
        if not c["functions"]:
            gaps.append(f"concern '{c['name']}': nothing detected")
    gaps.extend(f"firmware update: {g}" for g in brief["concerns"]["update"]["flow"]["gaps"])
    if not brief["memory"]["linker_scripts"]:
        gaps.append("no linker script found, so the flash and RAM layout is unknown")
    return gaps
