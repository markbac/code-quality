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
from fwlens.identity import SCHEME
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
    return {
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


def generate_sarif_report(model: ProjectModel, config: FwLensConfig) -> dict[str, Any]:
    """Generate SARIF 2.1.0 JSON payload from project breaches."""
    breaches = compute_breaches(model, config)
    rules = build_rules(breaches)
    rule_index = {r["id"]: i for i, r in enumerate(rules)}

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "FWLens",
                        "version": tool_version(),
                        "rules": rules,
                    }
                },
                "results": [breach_to_result(b, rule_index) for b in breaches],
            }
        ],
    }


def write_sarif_report(model: ProjectModel, config: FwLensConfig, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = generate_sarif_report(model, config)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
