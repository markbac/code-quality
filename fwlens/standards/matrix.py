"""
Compliance matrix (issue #49): one row per selected guideline with its status, how it was
checked and any deviation. This is a status report, NOT a compliance claim. A claim under
MISRA Compliance needs a guideline enforcement plan, a guideline recategorization plan and
deviation records, which are process documents outside this tool.
"""

from __future__ import annotations

import json
from collections import Counter

DISCLAIMER = ("This matrix reports what FWLens checked or imported. It is not a MISRA Compliance claim: "
              "that also needs an enforcement plan, any recategorization and deviation records. "
              "\"native (partial)\" means the check finds some violations of the guideline, not all of them, "
              "so \"no findings\" for such a guideline does not show compliance.")


def build_matrix(result) -> list[dict]:
    active = Counter(f.metric for f in result.findings)
    deviated = Counter(f.metric for f, _ in result.deviated)
    triaged = Counter(f.metric for f, _ in result.triaged)
    false_positive = Counter(f.metric for f, e in result.triaged if e.outcome == "false_positive")
    dev_ids: dict[str, set] = {}
    for f, d in result.deviated:
        dev_ids.setdefault(f.metric, set()).add(d.id)
    rows = []
    imports_supplied = bool(result.sources.get("_imports"))
    for rule in result.rules:
        evidence = sorted(result.sources.get(rule.key, set()))
        native = rule.check_type == "native"
        partial = native and rule.coverage == "partial"
        label = "native (partial)" if partial else "native"
        if rule.check_type == "manual":
            status, how = "manual review", "manual"
        elif active[rule.key]:
            status, how = "violated", "+".join(label if e == "native" else e for e in evidence)
        elif deviated[rule.key]:
            status, how = "deviated", "+".join(label if e == "native" else e for e in evidence)
        elif native:
            status = "no findings"
            how = label + ("+imported" if imports_supplied and any(c.type == "import" for c in rule.checks) else "")
        else:
            status = "no findings reported" if imports_supplied else "not assessed"
            how = "imported" if imports_supplied else "import-only, no results supplied"
        rows.append({
            "standard": rule.standard, "id": rule.id, "kind": rule.kind, "title": rule.title,
            "category": rule.category, "original_category": result.recategorised[rule.key][0] if rule.key in result.recategorised else "",
            "triaged": triaged[rule.key], "false_positive": false_positive[rule.key], "decidable": rule.decidable, "scope": rule.scope,
            "coverage": rule.coverage if native else "none",
            "status": status, "checked_by": how, "violations": active[rule.key],
            "deviated": deviated[rule.key], "deviations": sorted(dev_ids.get(rule.key, [])),
        })
    return rows


def _triage_lines(result) -> list[str]:
    out: list[str] = []
    if result.recategorised:
        out += ["## Recategorised guidelines", "", "| Guideline | From | To | Reason | Approved by |", "|---|---|---|---|---|"]
        for key, (old, new, r) in sorted(result.recategorised.items()):
            out.append(f"| {key} | {old} | {new} | {r.reason} | {r.approved_by or '-'} |")
        out.append("")
    if result.triaged:
        out += ["## Triaged findings", "", "| Finding | Outcome | Reason | Owner | Date |", "|---|---|---|---|---|"]
        for f, e in sorted(result.triaged, key=lambda t: t[0].id):
            out.append(f"| {f.id} | {e.outcome} | {e.reason} | {e.owner} | {e.date.isoformat() if e.date else '-'} |")
        out.append("")
    if result.stale_triage:
        out += ["## Stale triage entries", "", "No finding has these ids any more:", ""]
        out += [f"- {i}" for i in result.stale_triage] + [""]
    return out


def summarise(rows: list[dict]) -> dict:
    c = Counter(r["status"] for r in rows)
    return {"guidelines": len(rows), **{k: v for k, v in sorted(c.items())}}


def render_markdown(result) -> str:
    rows = build_matrix(result)
    out = ["# Coding standard compliance matrix", "", f"> **Note:** {DISCLAIMER}", ""]
    for std_id in sorted({r["standard"] for r in rows}):
        std = result.standards[std_id]
        sub = [r for r in rows if r["standard"] == std_id]
        out += [f"## {std.name} ({std.revision})", "",
                "| Id | Category | Title | Analysis | Status | Checked by | Violations | Deviations |",
                "|---|---|---|---|---|---|---|---|"]
        for r in sub:
            analysis = ("decidable" if r["decidable"] else "undecidable") + f", {r['scope']}"
            category = r["category"] + (f" (was {r['original_category']})" if r["original_category"] else "")
            dev = ", ".join(r["deviations"]) or "-"
            out.append(f"| {r['id']} | {category} | {r['title']} | {analysis} | {r['status']} | "
                       f"{r['checked_by']} | {r['violations']} | {dev} |")
        out.append("")
    out += _triage_lines(result)
    if result.problems:
        out += ["## Deviation problems", ""]
        out += [f"- {d.id}: {m}" for d, m in result.problems] + [""]
    if result.unmapped:
        out += ["## Imports", "", "Findings that matched no selected rule (ignored): "
                + ", ".join(f"{t} {n}" for t, n in sorted(result.unmapped.items())), ""]
    return "\n".join(out)


def render_json(result) -> str:
    rows = build_matrix(result)
    return json.dumps({"disclaimer": DISCLAIMER, "summary": summarise(rows), "guidelines": rows,
                       "deviation_problems": [{"id": d.id, "problem": m} for d, m in result.problems],
                       "unmapped_imports": result.unmapped,
                       "recategorised": [{"guideline": k, "from": o, "to": n, "reason": r.reason, "approved_by": r.approved_by}
                                         for k, (o, n, r) in sorted(result.recategorised.items())],
                       "triaged": [{"finding": f.id, "outcome": e.outcome, "reason": e.reason, "owner": e.owner,
                                    "date": e.date.isoformat() if e.date else ""} for f, e in result.triaged],
                       "stale_triage": result.stale_triage}, indent=2)
