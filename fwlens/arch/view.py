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
        "cycle_advice": [{"cycle": ", ".join(c["cycle"]), "exact": c["exact"], "call_sites": c["call_sites"],
                          "remove": "; ".join(f"{r['from']} -> {r['to']} ({r['call_sites']} call sites)" for r in c["remove"])}
                         for c in arch.cycle_suggestions[:ROWS]],
        "unused_exports": [{"component": r["component"], "public": r["public"], "unused": ", ".join(r["unused"][:8])}
                           for r in arch.interface_catalogue if r["unused"]][:ROWS],
        "footprint": [{"component": f["component"], "flash": f["flash_bytes"], "ram": f["ram_bytes"],
                       "flash_share": f["flash_share"], "ram_share": f["ram_share"], "mapped": f"{f['mapped']} of {f['units']}"}
                      for f in arch.footprint[:ROWS]],
        "trust": [{"entry": t["entry"], "kind": t["kind"], "sink": t["sink"], "path": " > ".join(h["function"] for h in t["path"]),
                   "crossings": ", ".join(t["crossings"]), "apis": ", ".join(a["api"] for a in t["crypto_apis"])}
                  for t in arch.trust_paths[:ROWS]],
        "activity": {k: v[:10] for k, v in arch.activity.items()},
        "since": since,
        "since_error": arch.since_baseline.get("error", ""),
    }
