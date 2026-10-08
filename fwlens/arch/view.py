"""The architecture model as plain rows for the HTML report."""

from __future__ import annotations

from fwlens.arch.model import ArchModel

ROWS = 25


def short(unit: str) -> str:
    return "/".join(unit.split("/")[-2:])


def report_view(arch: ArchModel | None) -> dict | None:
    if arch is None or not arch.components:
        return None
    from fwlens.arch.drift import lines
    sub = {s.component: s for s in arch.subsystems}
    since = lines(arch.since_baseline) if arch.since_baseline and "error" not in arch.since_baseline else []
    return {
        "system_patterns": [p for p in arch.patterns if p.scope == "system"],
        "subsystem_patterns": [p for p in arch.patterns if p.scope == "subsystem"],
        "layers": arch.layering.layers,
        "next_layer_share": arch.layering.next_layer_share,
        "cycles": arch.layering.cycles,
        "back_edges": arch.layering.back_edges[:ROWS],
        "skip_edges": arch.layering.skip_edges[:ROWS],
        "disagreements": arch.layering.disagreements[:ROWS],
        "components": [{"name": c.name, "units": len(c.units), "source": c.source, "cohesion": c.cohesion,
                       "domain": sub[c.id].domain_name if c.id in sub else "", "confidence": sub[c.id].confidence if c.id in sub else "",
                       "evidence": "; ".join(sub[c.id].evidence[:2]) if c.id in sub else "",
                       "level": arch.layering.level_of.get(c.name, 0)} for c in arch.components],
        "drift": [{"unit": short(d.unit), "directory_component": d.directory_component, "best_component": d.best_component,
                   "outside": d.outside} for d in arch.drift[:ROWS]],
        "leaks": [{"source": short(lk.source), "target": short(lk.target), "symbol": lk.symbol, "kind": lk.kind,
                   "where": f"{short(lk.file)}:{lk.line}"} for lk in arch.leaks[:ROWS]],
        "differences": arch.differences,
        "events": [{"event": e.event, "publishers": ", ".join(sorted({p["function"] for p in e.publishers})),
                    "subscribers": ", ".join(sorted({s["callback"] for s in e.subscribers})),
                    "broker": ", ".join(sorted({s["broker"] for s in e.subscribers}))} for e in arch.events[:ROWS]],
        "since": since,
        "since_error": arch.since_baseline.get("error", ""),
    }
