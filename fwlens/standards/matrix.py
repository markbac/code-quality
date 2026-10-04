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
              "that also needs an enforcement plan, any recategorization and deviation records.")


def build_matrix(result) -> list[dict]:
    active = Counter(f.metric for f in result.findings)
    deviated = Counter(f.metric for f, _ in result.deviated)
    dev_ids: dict[str, set] = {}
    for f, d in result.deviated:
        dev_ids.setdefault(f.metric, set()).add(d.id)
    rows = []
    for rule in result.rules:
        evidence = sorted(result.sources.get(rule.key, set()))
        if rule.check_type == "manual":
            status, how = "manual review", "manual"
        elif active[rule.key]:
            status, how = "violated", "+".join(evidence)
        elif deviated[rule.key]:
            status, how = "deviated", "+".join(evidence)
        elif rule.check_type == "native":
            status, how = "no findings", "native"
        else:
            status = "no findings reported" if result.sources.get("_imports") else "not assessed"
            how = "imported" if result.sources.get("_imports") else "import-only, no results supplied"
        rows.append({
            "standard": rule.standard, "id": rule.id, "kind": rule.kind, "title": rule.title,
            "category": rule.category, "decidable": rule.decidable, "scope": rule.scope,
            "status": status, "checked_by": how, "violations": active[rule.key],
            "deviated": deviated[rule.key], "deviations": sorted(dev_ids.get(rule.key, [])),
        })
    return rows


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
            dev = ", ".join(r["deviations"]) or "-"
            out.append(f"| {r['id']} | {r['category']} | {r['title']} | {analysis} | {r['status']} | "
                       f"{r['checked_by']} | {r['violations']} | {dev} |")
        out.append("")
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
                       "unmapped_imports": result.unmapped}, indent=2)
