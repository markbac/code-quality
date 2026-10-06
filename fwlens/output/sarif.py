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


def rule_info(model: ProjectModel) -> dict[str, dict[str, Any]]:
    """What is known about the coding-standard rules that ran, by rule key. Empty when standards were not run."""
    result = getattr(model, "_standards_result", None)
    if result is None:
        return {}
    info: dict[str, dict[str, Any]] = {}
    for r in result.rules:
        std = result.standards.get(r.standard)
        engines = sorted({c.engine for c in r.native_checks if c.engine})
        checked = (f"native ({', '.join(engines)})" if r.check_type == "native"
                   else "imported from another analyser" if r.check_type == "import" else "manual review")
        info[r.key] = {
            "cwe": list(r.cwe), "standard": r.standard, "standardName": f"{std.name} ({std.revision})" if std else r.standard,
            "id": r.id, "kind": r.kind, "category": r.category, "coverage": r.coverage, "checkedBy": checked,
            "notes": r.notes, "help": r.help, "title": r.title,
            "guidelineUri": (std.guideline_uri if std and getattr(std, "guideline_uri", "") else ""),
        }
    return info


def rule_cwes(model: ProjectModel) -> dict[str, list[str]]:
    """CWE ids of the coding-standard rules that ran, by rule key."""
    return {k: v["cwe"] for k, v in rule_info(model).items() if v["cwe"]}


def _help_text(b_title: str, level: str, meta: dict[str, Any]) -> str:
    lines = [b_title, "", f"Standard: {meta['standardName']}. Guideline {meta['id']}, {meta['category']}."]
    lines.append(f"Checked by: {meta['checkedBy']}" + (" (partial: it finds some violations, not all)" if meta["coverage"] == "partial" else "") + ".")
    if meta["help"]:
        lines += ["", "How to fix: " + meta["help"]]
    if meta["notes"]:
        lines += ["", "Notes: " + meta["notes"]]
    if meta["cwe"]:
        lines += ["", "Related weaknesses: " + ", ".join(meta["cwe"])]
    lines += ["", "FWLens carries a short description of each guideline, not its text. Read the guideline in your licensed copy of the standard."]
    return "\n".join(lines)


def _cwe_properties(cwes: list[str]) -> tuple[list[str], list[dict[str, Any]]]:
    tags = [f"external/cwe/{c.lower()}" for c in cwes]
    relationships = [{"target": {"id": c.removeprefix("CWE-"), "toolComponent": {"name": "CWE"}}, "kinds": ["relevant"]}
                     for c in cwes]
    return tags, relationships


def build_rules(breaches: list[Breach] = (), info: dict[str, dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    rules = []
    for metric, (name, short, level) in METRIC_INFO.items():
        rules.append({
            "id": rule_id(metric),
            "name": name,
            "shortDescription": {"text": short},
            "defaultConfiguration": {"level": level},
            "help": {"text": f"{short}.\n\nThe limit is set under thresholds.{metric} in the FWLens config. "
                             "Split the function or module, or raise the limit for this project."},
            "properties": {"metric": metric, "standard": "fwlens-metrics", "standardName": "FWLens metric thresholds"},
        })
    declared: set[str] = set()
    for b in breaches:
        if b.metric in METRIC_INFO or b.metric in declared:
            continue
        declared.add(b.metric)
        entry: dict[str, Any] = {
            "id": rule_id(b.metric),
            "name": b.metric,
            "shortDescription": {"text": b.description or b.metric},
            "defaultConfiguration": {"level": result_level(b)},
            "properties": {"category": b.category},
        }
        meta = (info or {}).get(b.metric)
        if meta:
            entry["name"] = f"{meta['standard']} {meta['id']}"
            entry["fullDescription"] = {"text": meta["title"]}
            entry["help"] = {"text": _help_text(meta["title"], result_level(b), meta)}
            entry["properties"].update({"standard": meta["standard"], "standardName": meta["standardName"],
                                        "guideline": meta["id"], "kind": meta["kind"], "checkedBy": meta["checkedBy"],
                                        "coverage": meta["coverage"]})
            if meta["guidelineUri"]:
                entry["helpUri"] = meta["guidelineUri"]
            if meta["cwe"]:
                tags, relationships = _cwe_properties(meta["cwe"])
                entry["properties"]["tags"] = tags
                entry["properties"]["cwe"] = meta["cwe"]
                entry["relationships"] = relationships
        rules.append(entry)
    return rules


def build_cwe(breaches: list[Breach], cwe_by_rule: dict[str, list[str]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """The CWE taxonomy that the rules point at, and a summary of findings per CWE against the Top 25."""
    from fwlens.standards.cwe import TOP25, TOP25_EDITION
    by_cwe: dict[str, int] = {}
    for b in breaches:
        for cwe in cwe_by_rule.get(b.metric, ()):
            by_cwe[cwe] = by_cwe.get(cwe, 0) + 1
    covered = sorted({c for cwes in cwe_by_rule.values() for c in cwes} & set(TOP25), key=TOP25.index)
    taxonomy = []
    if cwe_by_rule:
        ids = sorted({c for cwes in cwe_by_rule.values() for c in cwes}, key=lambda c: int(c.removeprefix("CWE-")))
        taxonomy = [{"name": "CWE", "organization": "MITRE", "shortDescription": {"text": "Common Weakness Enumeration"},
                     "informationUri": "https://cwe.mitre.org/",
                     "taxa": [{"id": c.removeprefix("CWE-"), "name": c,
                               "helpUri": f"https://cwe.mitre.org/data/definitions/{c.removeprefix('CWE-')}.html"} for c in ids]}]
    summary = {
        "top25Edition": TOP25_EDITION,
        "top25": TOP25,
        "top25CheckedByRules": covered,
        "top25WithFindings": [c for c in TOP25 if c in by_cwe],
        "findingsByCwe": dict(sorted(by_cwe.items(), key=lambda kv: (-kv[1], kv[0]))),
        "rulesWithCwe": len(cwe_by_rule),
    }
    return taxonomy, summary


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


def outside_first_party(model: ProjectModel, config: FwLensConfig, uris: set[str]) -> list[str]:
    """The result files that are SDK or third-party code: a parsed module's class, else the scope folders in the path."""
    root = project_root(config)
    known = {relative_posix(m.path, root): m.boundary_class.value for m in model.modules}
    sdk = {s.lower() for s in config.scope.sdk}
    lib = {s.lower() for s in config.scope.third_party_lib}
    out = []
    for uri in sorted(uris):
        cls = known.get(uri)
        if cls is None:
            parts = {p.lower() for p in uri.split("/")[:-1]}
            cls = "sdk" if parts & sdk else "third_party_lib" if parts & lib else "first_party"
        if cls in ("sdk", "third_party_lib"):
            out.append(uri)
    return out


def generate_sarif_report(model: ProjectModel, config: FwLensConfig,
                          breaches: list[Breach] | None = None) -> dict[str, Any]:
    """Generate SARIF 2.1.0 JSON payload from project breaches (computed unless given)."""
    if breaches is None:
        breaches = compute_breaches(model, config)
    info = rule_info(model)
    cwe_by_rule = {k: v["cwe"] for k, v in info.items() if v["cwe"]}
    rules = build_rules(breaches, info)
    rule_index = {r["id"]: i for i, r in enumerate(rules)}

    metrics, artifacts = build_metrics(model, config)
    run: dict[str, Any] = {
        "tool": {"driver": {"name": "FWLens", "version": tool_version(), "rules": rules}},
        "artifacts": artifacts,
        "results": [breach_to_result(b, rule_index) for b in breaches],
        "properties": {"fwlens": metrics},
    }
    metrics["thirdPartyFiles"] = outside_first_party(
        model, config, {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in run["results"]})
    if cwe_by_rule:
        taxonomy, cwe_summary = build_cwe(breaches, cwe_by_rule)
        run["taxonomies"] = taxonomy
        metrics["cwe"] = cwe_summary
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
