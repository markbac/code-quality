"""
SARIF 2.1.0 exporter for FWLens static analysis results.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fwlens.baseline import Breach, compute_breaches
from fwlens.config import FwLensConfig
from fwlens.model.project import ProjectModel


def generate_sarif_report(model: ProjectModel, config: FwLensConfig) -> dict[str, Any]:
    """Generate SARIF 2.1.0 JSON payload from project breaches."""
    breaches = compute_breaches(model, config)

    rules = [
        {
            "id": "FWLENS-COMPLEXITY",
            "name": "CyclomaticComplexityBreach",
            "shortDescription": {"text": "Cyclomatic complexity exceeds maximum threshold"},
            "fullDescription": {"text": "Independent decision paths exceed maintainability guidelines."},
            "defaultConfiguration": {"level": "warning"},
        },
        {
            "id": "FWLENS-COGNITIVE",
            "name": "CognitiveComplexityBreach",
            "shortDescription": {"text": "Cognitive complexity exceeds threshold"},
            "fullDescription": {"text": "Mental effort required to comprehend control flow is excessively high."},
            "defaultConfiguration": {"level": "warning"},
        },
        {
            "id": "FWLENS-LOC",
            "name": "FunctionLengthBreach",
            "shortDescription": {"text": "Function LOC exceeds maximum threshold"},
            "fullDescription": {"text": "Function length in lines of code is too long."},
            "defaultConfiguration": {"level": "note"},
        },
    ]

    results = []
    for b in breaches:
        parts = b.id.split(":")
        line_num = int(parts[1]) if len(parts) >= 4 and parts[1].isdigit() else 1

        results.append({
            "ruleId": f"FWLENS-{b.metric.upper()}",
            "level": "warning",
            "message": {
                "text": f"Metric breach: '{b.metric}' value is {b.value} (threshold is {b.threshold})"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": b.file},
                        "region": {"startLine": line_num},
                    }
                }
            ],
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "FWLens",
                        "version": "0.29.0",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def write_sarif_report(model: ProjectModel, config: FwLensConfig, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = generate_sarif_report(model, config)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
