"""
Intended versus implemented: the architecture you state in `architecture.intended_layers` and
`architecture.rules`, checked against the recovered dependencies.

    intended_layers   top to bottom; a component may depend on its own layer and lower ones. A name is
                      matched to a component by its configured layer, its name or its domain; an item
                      can also be {name, components: [globs], domains: [ids]}.
    rules             {id, from, to, allow, kinds}. `from` and `to` match components by `component`
                      (glob), `domain`, `layer` (an intended layer) or `unit` (path glob), combined
                      with `not`. `to: {symbol: "*_REG_*"}` matches identifiers used in the `from`
                      units. allow: false (the default) forbids the dependency; allow: true says the
                      `from` units may depend on nothing outside `to`.
    forbid_cycles     report every upward dependency inside a cycle of components.

Violations are findings: they go through the baseline and ratchet like any other breach.
"""

from __future__ import annotations

import re
from collections import defaultdict
from fnmatch import fnmatchcase

from fwlens.arch.components import matches
from fwlens.arch.edges import line_of, norm, read_text
from fwlens.arch.model import ArchModel, Component, Violation
from fwlens.config import ConfigError

MATCH_KEYS = {"component", "domain", "layer", "unit", "not", "symbol"}
_IDENT = re.compile(r"[A-Za-z_]\w*")


def validate(rules, intended) -> None:
    for i, item in enumerate(intended or []):
        if not isinstance(item, (str, dict)) or (isinstance(item, dict) and not item.get("name")):
            raise ConfigError(f"architecture.intended_layers[{i}] must be a name or a mapping with a 'name'")
    ids = set()
    for i, rule in enumerate(rules or []):
        where = f"architecture.rules[{i}]"
        if not isinstance(rule, dict) or not rule.get("id") or not isinstance(rule.get("from"), dict) or not isinstance(rule.get("to"), dict):
            raise ConfigError(f"{where} needs 'id', 'from' and 'to' (each a mapping)")
        if rule["id"] in ids:
            raise ConfigError(f"{where}: duplicate rule id '{rule['id']}'")
        ids.add(rule["id"])
        for side in ("from", "to"):
            _check_matcher(rule[side], f"{where}.{side}", allow_symbol=side == "to")
        if "symbol" in rule["to"] and rule.get("allow", False):
            raise ConfigError(f"{where}: allow: true cannot be combined with 'symbol'")
        if not isinstance(rule.get("allow", False), bool):
            raise ConfigError(f"{where}: 'allow' must be true or false")


def _check_matcher(spec: dict, where: str, allow_symbol: bool) -> None:
    unknown = set(spec) - MATCH_KEYS
    if unknown or not spec:
        raise ConfigError(f"{where}: use {sorted(MATCH_KEYS - ({'symbol'} if not allow_symbol else set()))}, not {sorted(unknown) or 'an empty mapping'}")
    if "symbol" in spec and not allow_symbol:
        raise ConfigError(f"{where}: 'symbol' is only valid under 'to'")
    if "not" in spec:
        if not isinstance(spec["not"], dict):
            raise ConfigError(f"{where}.not must be a mapping")
        _check_matcher(spec["not"], f"{where}.not", False)


def _listed(value) -> list[str]:
    return [str(v) for v in (value if isinstance(value, list) else [value])]


class Placement:
    """Which intended layer, domain and component each unit has."""

    def __init__(self, arch: ArchModel, intended: list | None):
        self.arch = arch
        self.intended = [i if isinstance(i, dict) else {"name": str(i)} for i in intended or []]
        self.component = {u: c for c in arch.components for u in c.units}
        domain = {s.component: s.domain for s in arch.subsystems}
        self.domain = {c.name: domain.get(c.id, "") for c in arch.components}
        self.layer = {c.name: self._place(c) for c in arch.components}
        self.rank = {i["name"].lower(): n for n, i in enumerate(self.intended)}

    def _place(self, comp: Component) -> str:
        for item in self.intended:
            name = item["name"]
            if any(fnmatchcase(comp.name, g) for g in _listed(item.get("components", []))) \
                    or self.domain[comp.name] in _listed(item.get("domains", [])):
                return name
            if any(matches(u, g) for u in comp.units for g in _listed(item.get("units", []))):
                return name
        for item in self.intended:
            if item["name"].lower() in {comp.layer.lower(), comp.name.lower(), self.domain[comp.name].lower()} - {""}:
                return item["name"]
        return ""

    def match(self, spec: dict, unit: str) -> bool:
        comp = self.component.get(unit)
        if comp is None:
            return False
        if "component" in spec and not any(fnmatchcase(comp.name, g) for g in _listed(spec["component"])):
            return False
        if "domain" in spec and self.domain[comp.name] not in _listed(spec["domain"]):
            return False
        if "layer" in spec and self.layer[comp.name].lower() not in {x.lower() for x in _listed(spec["layer"])}:
            return False
        if "unit" in spec and not any(matches(unit, g) for g in _listed(spec["unit"])):
            return False
        return not ("not" in spec and self.match(spec["not"], unit))


def check(arch: ArchModel, texts, intended: list | None, rules: list | None, strict: bool = False,
          forbid_cycles: bool = False) -> list[Violation]:
    """`texts(path)` returns the file's text with comments and strings blanked."""
    place = Placement(arch, intended)
    out: list[Violation] = []
    by_pair: dict = defaultdict(lambda: {"kinds": set(), "evidence": None})
    for e in arch.edges:
        a, b = place.component.get(e.source), place.component.get(e.target)
        if not a or not b or a is b:
            continue
        entry = by_pair[(a.name, b.name)]
        entry["kinds"].add(e.kind)
        if entry["evidence"] is None and e.evidence:
            entry["evidence"] = (e.evidence[0][0], e.evidence[0][1])
        entry.setdefault("units", (e.source, e.target))

    def where(pair) -> tuple:
        ev = by_pair[pair]["evidence"]
        return ev if ev else (by_pair[pair]["units"][0], 0)

    if place.intended:
        for (a, b), data in sorted(by_pair.items()):
            la, lb = place.layer[a], place.layer[b]
            if not la or not lb:
                continue
            ra, rb = place.rank[la.lower()], place.rank[lb.lower()]
            if rb < ra:
                text = f"{a} ({la}) depends on {b} ({lb}), a higher layer"
            elif strict and rb - ra > 1:
                text = f"{a} ({la}) skips {rb - ra - 1} layer(s) to depend on {b} ({lb})"
            else:
                continue
            f, line = where((a, b))
            out.append(Violation("intended-layers", "layer", a, b, a, b, f, line, text, sorted(data["kinds"])))

    if forbid_cycles:
        for edge in arch.layering.back_edges:
            pair = (edge["source"], edge["target"])
            f, line = where(pair)
            out.append(Violation("no-cycles", "cycle", pair[0], pair[1], pair[0], pair[1], f, line,
                                 f"{pair[0]} depends back on {pair[1]} inside a cycle", edge["kinds"]))

    for rule in rules or []:
        rid, allow = rule["id"], bool(rule.get("allow", False))
        kinds = set(_listed(rule["kinds"])) if rule.get("kinds") else None
        from_units = [u for u in arch.units if place.match(rule["from"], u)]
        if "symbol" in rule["to"]:
            patterns = _listed(rule["to"]["symbol"])
            for u in from_units:
                text = texts(u)
                seen: dict = {}
                for m in _IDENT.finditer(text):
                    if m.group(0) not in seen and any(fnmatchcase(m.group(0), p) for p in patterns):
                        seen[m.group(0)] = line_of(text, m.start())
                for symbol, line in sorted(seen.items()):
                    comp = place.component[u].name
                    out.append(Violation(rid, "rule", u, symbol, comp, "", norm(u), line,
                                         f"{rid}: {comp} uses {symbol}", []))
            continue
        to_units = {u for u in arch.units if place.match(rule["to"], u)}
        groups: dict = defaultdict(lambda: {"kinds": set(), "evidence": None})
        starts = set(from_units)
        for e in arch.edges:
            if e.source not in starts or e.target not in place.component:
                continue
            if place.component[e.source] is place.component[e.target] or (kinds and e.kind not in kinds):
                continue
            if (e.target in to_units) == (not allow):
                g = groups[(e.source, e.target)]
                g["kinds"].add(e.kind)
                g["evidence"] = g["evidence"] or (e.evidence[0] if e.evidence else None)
        for (s, t), g in sorted(groups.items()):
            sc, tc = place.component[s].name, place.component[t].name
            ev = g["evidence"] or (s, 0)
            verb = "depends on" if not allow else "depends on (not in the allowed set)"
            out.append(Violation(rid, "rule", s, t, sc, tc, ev[0], ev[1], f"{rid}: {sc} {verb} {tc}", sorted(g["kinds"])))
    out.sort(key=lambda v: (v.rule, v.source, v.target, v.line))
    return out


def evaluate(arch: ArchModel, cfg, text_for=read_text) -> list[Violation]:
    return check(arch, text_for, cfg.intended_layers, cfg.rules, cfg.strict_layers, cfg.forbid_cycles)
