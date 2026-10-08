"""
Subsystem domains: what each component is for (UI, comms, storage ...), from the names it uses.

Evidence is weighted: a file name says most (3 per matching file), then an included header (4 per
match, one per pattern), an RTOS task name (2), and each function or global name (1, up to 8 per
word list). The domain with the highest score wins. `high` needs a score of at least 12 from at
least two kinds of evidence, `medium` 5, `low` 2; below that the component is `unclassified`.
A domain you pin in `architecture.subsystems` is always `high`, with the evidence "pinned".
"""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath

import yaml

from fwlens.arch.components import matches
from fwlens.arch.edges import norm
from fwlens.arch.model import Component, Subsystem
from fwlens.config import ConfigError
from fwlens.crypto.keywords import words_of
from fwlens.model.project import ProjectModel

_BUNDLED = Path(__file__).parent / "domains.yaml"
WEIGHTS = {"file": 3, "include": 4, "task": 2, "name": 1}
NAME_CAP = 8
HIGH, MEDIUM, LOW = 12, 5, 2


@dataclass
class Domain:
    id: str
    name: str
    words: set[str]
    includes: list[str]


def _parse(items, where: str) -> list[Domain]:
    if not isinstance(items, list):
        raise ConfigError(f"{where}: domains must be a list")
    out = []
    for raw in items:
        if not isinstance(raw, dict) or not raw.get("id"):
            raise ConfigError(f"{where}: every domain needs an 'id'")
        words, includes = raw.get("words") or [], raw.get("includes") or []
        if not isinstance(words, list) or not isinstance(includes, list) or not (words or includes):
            raise ConfigError(f"{where}: domain '{raw['id']}' needs 'words' and/or 'includes' as lists")
        out.append(Domain(str(raw["id"]), str(raw.get("name") or raw["id"]), {str(w).lower() for w in words},
                          [str(p) for p in includes]))
    return out


def load_domains(extra: list[dict] | None = None) -> list[Domain]:
    try:
        raw = yaml.safe_load(_BUNDLED.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"domains {_BUNDLED}: {exc}") from exc
    domains = {d.id: d for d in _parse(raw["domains"], "bundled domains")}
    for d in _parse(extra or [], "architecture.domains"):
        domains[d.id] = d                      # the same id replaces the bundled domain
    return list(domains.values())


def label(model: ProjectModel, components: list[Component], domains: list[Domain],
          pins: list[dict] | None = None) -> list[Subsystem]:
    by_unit = {norm(m.path): m for m in model.modules}
    fn_unit = {f.name: norm(m.path) for m in model.modules for f in m.functions}
    out = []
    for comp in components:
        members = set(comp.units)
        comp_tasks = [tk for tk in model.rtos_tasks if fn_unit.get(tk.entry_function) in members]
        pinned = _pinned(comp, pins or [])
        if pinned:
            name = next((d.name for d in domains if d.id == pinned), pinned)
            out.append(Subsystem(comp.id, comp.name, pinned, name, "high", ["pinned in architecture.subsystems"], {}))
            continue
        scores: dict[str, float] = {}
        evidence: dict[str, dict[str, list[str]]] = {}
        for d in domains:
            ev: dict[str, list[str]] = {"file": [], "include": [], "task": [], "name": []}
            for unit in comp.units:
                stem = PurePosixPath(unit).stem
                if d.words & set(words_of(stem)):
                    ev["file"].append(stem)
                m = by_unit.get(unit)
                if not m:
                    continue
                headers = {norm(dst).rsplit("/", 1)[-1] for _s, dst in m.all_include_edges}
                ev["include"] += sorted(h for h in headers if any(fnmatchcase(h, p) for p in d.includes))
                for f in m.functions:
                    if d.words & set(words_of(f.name)):
                        ev["name"].append(f.name)
            ev["task"] = [tk.name for tk in comp_tasks if d.words & (set(words_of(tk.name)) | set(words_of(tk.entry_function)))]
            for k in ev:
                ev[k] = sorted(dict.fromkeys(ev[k]))
            score = (WEIGHTS["file"] * len(ev["file"]) + WEIGHTS["include"] * len(ev["include"])
                     + WEIGHTS["task"] * len(ev["task"]) + WEIGHTS["name"] * min(len(ev["name"]), NAME_CAP))
            scores[d.id] = score
            evidence[d.id] = ev
        best = max(domains, key=lambda d: (scores[d.id], -domains.index(d)))
        top, ev = scores[best.id], evidence[best.id]
        kinds = sum(1 for v in ev.values() if v)
        level = ("high" if top >= HIGH and kinds >= 2 else "medium" if top >= MEDIUM
                 else "low" if top >= LOW else "")
        if not level:
            out.append(Subsystem(comp.id, comp.name, "unclassified", "Unclassified", "low",
                                 ["no domain words in names or includes"], {k: v for k, v in scores.items() if v}))
            continue
        lines = []
        if ev["file"]:
            lines.append("files: " + ", ".join(ev["file"][:4]))
        if ev["include"]:
            lines.append("includes: " + ", ".join(ev["include"][:4]))
        if ev["task"]:
            lines.append("tasks: " + ", ".join(ev["task"][:3]))
        if ev["name"]:
            lines.append("names: " + ", ".join(ev["name"][:4]))
        out.append(Subsystem(comp.id, comp.name, best.id, best.name, level, lines, {k: v for k, v in scores.items() if v}))
    return out


def _pinned(comp: Component, pins: list[dict]) -> str:
    for pin in pins:
        hit = sum(1 for u in comp.units if any(matches(u, p) for p in pin["units"]))
        if hit * 2 > len(comp.units):
            return pin["domain"]
    return ""
