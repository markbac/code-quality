"""
SARIF 2.1.0 exporter for FWLens static analysis results.

Rules are generated from the same METRIC_INFO table the breach computation uses, so a
result's ruleId always refers to a declared rule (issue #27). Locations are repo-relative
URIs against %SRCROOT%, and each result carries a stable partial fingerprint.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fwlens.baseline import METRIC_INFO, Breach, compute_breaches
from fwlens.config import FwLensConfig
from fwlens.identity import SCHEME, project_root, relative_posix
from fwlens.model.project import ProjectModel


def tool_version() -> str:
    try:
        from importlib.metadata import version
        return version("fwlens")
    except Exception:
        return "0.0.0"


CATEGORY_LEVEL = {"mandatory": "error", "required": "warning", "advisory": "note"}


def rule_id(metric: str) -> str:
    # Coding-standard findings use the standard's own id (for example misra-c-2012:15.1)
    return f"FWLENS-{metric.upper()}" if metric in METRIC_INFO else metric


def result_level(b: Breach) -> str:
    if b.category:
        return CATEGORY_LEVEL.get(b.category, "warning")
    return METRIC_INFO[b.metric][2]


def build_rules(breaches: list[Breach] = ()) -> list[dict[str, Any]]:
    rules = []
    for metric, (name, short, level) in METRIC_INFO.items():
        rules.append({
            "id": rule_id(metric),
            "name": name,
            "shortDescription": {"text": short},
            "defaultConfiguration": {"level": level},
            "properties": {"metric": metric},
        })
    declared: set[str] = set()
    for b in breaches:
        if b.metric in METRIC_INFO or b.metric in declared:
            continue
        declared.add(b.metric)
        rules.append({
            "id": rule_id(b.metric),
            "name": b.metric,
            "shortDescription": {"text": b.description or b.metric},
            "defaultConfiguration": {"level": result_level(b)},
            "properties": {"category": b.category},
        })
    return rules


def breach_to_result(b: Breach, rule_index: dict[str, int]) -> dict[str, Any]:
    rid = rule_id(b.metric)
    properties: dict[str, Any] = {}
    if b.kind != "rule":
        properties = {"metric": b.metric, "value": b.value, "threshold": b.threshold}
        if b.function:
            properties["function"] = b.function
    result = {
        "ruleId": rid,
        "ruleIndex": rule_index[rid],
        "level": result_level(b),
        "message": {
            "text": (f"{b.description} ({b.metric})" if b.kind == "rule" else
                     f"Metric breach: '{b.metric}' value is {b.value} (threshold is {b.threshold})")
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": b.file, "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": max(1, b.line or 1)},
                }
            }
        ],
        "partialFingerprints": {f"{SCHEME}": b.id},
    }
    if properties:
        result["properties"] = properties
    return result


MAX_FUNCTIONS_IN_SARIF = 500


def _round(value: float, places: int = 2) -> float:
    return round(float(value), places)


def build_metrics(model: ProjectModel, config: FwLensConfig) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """
    The key metrics of first-party code for SARIF: a run-level summary with the most complex
    functions (``run.properties.fwlens``) and one artifact per file with its size and complexity.
    """
    root = project_root(config)
    modules = model.first_party_modules()
    functions = [(m, f) for m in modules for f in m.functions]
    artifacts = []
    for m in modules:
        fns = m.functions
        artifacts.append({
            "location": {"uri": relative_posix(m.path, root), "uriBaseId": "%SRCROOT%"},
            "length": m.loc,
            "properties": {
                "loc": m.loc,
                "functionCount": len(fns),
                "averageCyclomaticComplexity": _round(m.avg_cc),
                "maxCyclomaticComplexity": m.max_cc,
                "averageMaintainabilityIndex": _round(m.avg_mi_woc),
                "fanIn": m.fan_in,
                "fanOut": m.fan_out,
                "instability": _round(m.instability),
            },
        })

    def row(m, f):
        return {
            "name": f.name, "file": relative_posix(m.path, root), "line": f.line, "loc": f.loc,
            "cyclomaticComplexity": f.cyclomatic_complexity, "cognitiveComplexity": f.cognitive_complexity,
            "blockDepth": f.block_depth, "parameterCount": f.parameter_count, "returnPaths": f.return_path_count,
            "fanIn": f.fan_in, "fanOut": f.fan_out, "maintainabilityIndex": _round(f.mi_woc),
        }

    ranked = sorted(functions, key=lambda mf: (-mf[1].cyclomatic_complexity, -mf[1].cognitive_complexity, mf[1].name))
    ccs = [f.cyclomatic_complexity for _, f in functions]
    summary = {
        "files": len(modules),
        "functions": len(functions),
        "loc": sum(m.loc for m in modules),
        "averageCyclomaticComplexity": _round(sum(ccs) / len(ccs)) if ccs else 0,
        "maxCyclomaticComplexity": max(ccs, default=0),
        "maxCognitiveComplexity": max((f.cognitive_complexity for _, f in functions), default=0),
        "maxBlockDepth": max((f.block_depth for _, f in functions), default=0),
        "averageMaintainabilityIndex": _round(sum(f.mi_woc for _, f in functions) / len(functions)) if functions else 0,
    }
    props = {"summary": summary, "functions": [row(m, f) for m, f in ranked[:MAX_FUNCTIONS_IN_SARIF]],
             "functionsListed": min(len(ranked), MAX_FUNCTIONS_IN_SARIF), "functionsTotal": len(ranked)}
    return props, artifacts


def generate_sarif_report(model: ProjectModel, config: FwLensConfig,
                          breaches: list[Breach] | None = None) -> dict[str, Any]:
    """Generate SARIF 2.1.0 JSON payload from project breaches (computed unless given)."""
    if breaches is None:
        breaches = compute_breaches(model, config)
    rules = build_rules(breaches)
    rule_index = {r["id"]: i for i, r in enumerate(rules)}

    metrics, artifacts = build_metrics(model, config)
    run: dict[str, Any] = {
        "tool": {"driver": {"name": "FWLens", "version": tool_version(), "rules": rules}},
        "artifacts": artifacts,
        "results": [breach_to_result(b, rule_index) for b in breaches],
        "properties": {"fwlens": metrics},
    }
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }


def write_sarif_report(model: ProjectModel, config: FwLensConfig, output_path: Path,
                       breaches: list[Breach] | None = None) -> Path:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = generate_sarif_report(model, config, breaches)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    return output_path
