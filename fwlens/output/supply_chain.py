"""
Readable views of the SBOM, CBOM and SARIF documents for the HTML report (#97). Each builder reads
the same JSON the exports write, so the report and the files cannot disagree, and returns plain
dicts and lists for the template.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Any

_COPYLEFT = re.compile(r"\b(?:A?GPL|LGPL|MPL|EPL|CDDL)\b", re.IGNORECASE)


def _props(component: dict) -> dict[str, str]:
    """A component's fwlens properties; repeated names are joined."""
    out: dict[str, list[str]] = {}
    for p in component.get("properties", []):
        out.setdefault(p["name"].removeprefix("fwlens:"), []).append(str(p.get("value", "")))
    return {k: "; ".join(v) for k, v in out.items()}


def _licence_names(component: dict) -> list[str]:
    names = []
    for entry in component.get("licenses", []):
        if "expression" in entry:
            names.append(entry["expression"])
        else:
            lic = entry.get("license", {})
            names.append(lic.get("id") or lic.get("name") or "unknown")
    return names


def _licence_kind(names: list[str]) -> str:
    if not names:
        return "unknown"
    joined = " ".join(names)
    if re.search(r"propriet|commercial", joined, re.IGNORECASE):
        return "proprietary"
    if _COPYLEFT.search(joined):
        return "copyleft"
    return "permissive"


def sbom_view(doc: dict) -> dict[str, Any]:
    meta = doc.get("metadata", {})
    main = meta.get("component", {})
    deps = {d["ref"]: d.get("dependsOn", []) for d in doc.get("dependencies", [])}
    rows = []
    for c in doc.get("components", []):
        p = _props(c)
        lic = _licence_names(c)
        rows.append({
            "name": c.get("name", ""), "type": c.get("type", ""), "version": c.get("version") or "",
            "supplier": (c.get("supplier") or {}).get("name", ""), "licences": lic, "licence_kind": _licence_kind(lic),
            "source": p.get("evidence") or p.get("classification", ""), "location": p.get("location") or p.get("path", ""),
            "files": p.get("file-count", ""), "linked": p.get("linked", ""), "depends_on": len(deps.get(c.get("bom-ref"), [])),
            "gaps": p.get("gaps", ""), "actions": p.get("compliance-action", ""), "purl": c.get("purl", ""),
        })
    rows.sort(key=lambda r: (r["source"], r["name"].lower()))
    mp = _props(meta)
    kinds = Counter(r["licence_kind"] for r in rows)
    return {
        "name": main.get("name", ""), "version": main.get("version", ""), "type": main.get("type", ""),
        "supplier": (main.get("supplier") or meta.get("supplier") or {}).get("name", ""),
        "timestamp": meta.get("timestamp", ""), "spec": f"CycloneDX {doc.get('specVersion', '')}",
        "components_file": mp.get("components-file", ""), "last_reviewed": mp.get("last-reviewed", ""),
        "rows": rows, "total": len(rows), "licence_kinds": dict(kinds),
        "missing_version": [r["name"] for r in rows if not r["version"]],
        "missing_licence": [r["name"] for r in rows if r["licence_kind"] == "unknown"],
        "attention": [{"name": r["name"], "gaps": r["gaps"], "actions": r["actions"]}
                      for r in rows if r["gaps"] or r["actions"]],
        "completeness": mp.get("completeness", ""),
    }


def cbom_view(doc: dict) -> dict[str, Any]:
    meta = doc.get("metadata", {})
    assets, libraries = [], []
    for c in doc.get("components", []):
        p = _props(c)
        crypto = c.get("cryptoProperties")
        if c.get("type") == "library" and not crypto:
            libraries.append({"name": c.get("name", ""), "evidence": p.get("evidence", "")})
            continue
        if not crypto:
            continue
        kind = crypto.get("assetType", "")
        detail = ""
        if kind == "algorithm":
            a = crypto.get("algorithmProperties", {})
            detail = ", ".join(str(x) for x in (a.get("primitive"), a.get("mode"), a.get("parameterSetIdentifier"),
                                                a.get("curve")) if x)
        elif kind == "protocol":
            a = crypto.get("protocolProperties", {})
            detail = ", ".join(str(x) for x in (a.get("type"), a.get("version")) if x)
            if a.get("cipherSuites"):
                detail += f" ({len(a['cipherSuites'])} cipher suites)"
        where = [f"{o.get('location', '')}:{o.get('line', '')}" for o in c.get("evidence", {}).get("occurrences", [])]
        assets.append({
            "name": c.get("name", ""), "kind": kind, "detail": detail, "weak": p.get("weak", ""),
            "evidence": p.get("evidence-kind", ""), "library": p.get("library", ""),
            "count": p.get("occurrence-count", ""), "where": where[:5], "more": max(len(where) - 5, 0),
        })
    mp = _props(meta)
    assets.sort(key=lambda r: (not r["weak"], r["kind"], r["name"].lower()))
    return {
        "assets": assets, "libraries": libraries, "weak": [a for a in assets if a["weak"]],
        "algorithms": sum(1 for a in assets if a["kind"] == "algorithm"),
        "protocols": sum(1 for a in assets if a["kind"] == "protocol"),
        "files_scanned": mp.get("files-scanned", ""), "scopes": mp.get("scanned-scopes", ""),
        "completeness": mp.get("completeness", ""), "timestamp": meta.get("timestamp", ""),
    }


def sarif_explorer(doc: dict) -> dict[str, Any]:
    """
    Every result and every rule of the SARIF document in a compact form for the report's filter
    view: results are [rule index, file index, line, level index, message], rules carry their help
    and CWE ids. Nothing is dropped, so the view can show all results and filter them in the page.
    """
    run = doc["runs"][0]
    rules: list[dict] = []
    rule_index: dict[str, int] = {}
    for r in run["tool"]["driver"]["rules"]:
        props = r.get("properties", {})
        rid = r["id"]
        standard = props.get("standard") or (rid.split(":")[0] if ":" in rid else "fwlens-metrics")
        rule_index[rid] = len(rules)
        rules.append({
            "id": rid, "title": r.get("shortDescription", {}).get("text", ""),
            "level": r.get("defaultConfiguration", {}).get("level", "warning"), "standard": standard,
            "standardName": props.get("standardName", standard), "guideline": props.get("guideline", rid),
            "category": props.get("category", ""), "checkedBy": props.get("checkedBy", ""),
            "coverage": props.get("coverage", ""), "cwe": props.get("cwe", []),
            "help": r.get("help", {}).get("text", ""), "helpUri": r.get("helpUri", ""),
        })
    files: list[str] = []
    file_index: dict[str, int] = {}
    levels: list[str] = []
    level_index: dict[str, int] = {}
    rows = []
    for res in run.get("results", []):
        loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
        uri = loc.get("artifactLocation", {}).get("uri", "")
        if uri not in file_index:
            file_index[uri] = len(files)
            files.append(uri)
        level = res.get("level", "warning")
        if level not in level_index:
            level_index[level] = len(levels)
            levels.append(level)
        message = res.get("message", {}).get("text", "") if res.get("properties", {}).get("metric") else ""
        rows.append([rule_index.get(res["ruleId"], 0), file_index[uri], loc.get("region", {}).get("startLine", 1),
                     level_index[level], message])
    standards: dict[str, dict] = {}
    for r in rules:
        standards.setdefault(r["standard"], {"id": r["standard"], "name": r["standardName"]})
    third = set(run.get("properties", {}).get("fwlens", {}).get("thirdPartyFiles", []))
    return {"rules": rules, "files": files, "levels": levels, "results": rows, "standards": list(standards.values()),
            "thirdParty": [i for i, f in enumerate(files) if f in third]}


def sarif_view(doc: dict, top_rules: int = 15, top_files: int = 15, top_functions: int = 15) -> dict[str, Any]:
    run = doc["runs"][0]
    rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
    results = run.get("results", [])
    levels = Counter(r.get("level", "warning") for r in results)
    by_rule = Counter(r["ruleId"] for r in results)
    by_file: Counter = Counter()
    for r in results:
        loc = r.get("locations") or [{}]
        by_file[loc[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")] += 1
    rule_rows = []
    for rid, n in by_rule.most_common(top_rules):
        rule = rules.get(rid, {})
        rule_rows.append({"id": rid, "title": rule.get("shortDescription", {}).get("text", ""),
                          "level": rule.get("defaultConfiguration", {}).get("level", ""), "count": n})
    metrics = run.get("properties", {}).get("fwlens", {})
    breaches = [{"rule": r["ruleId"], **r["properties"]} for r in results if r.get("properties", {}).get("metric")]
    standards = Counter(r["ruleId"].split(":")[0] for r in results if ":" in r["ruleId"])
    cwe = metrics.get("cwe") or {}
    cwe_rows = [{"cwe": c, "count": n} for c, n in list(cwe.get("findingsByCwe", {}).items())[:top_rules]]
    return {
        "explorer": sarif_explorer(doc),
        "cwe": ({"edition": cwe.get("top25Edition", ""), "rows": cwe_rows, "total": len(cwe.get("findingsByCwe", {})),
                 "top25_checked": cwe.get("top25CheckedByRules", []), "top25_found": cwe.get("top25WithFindings", []),
                 "top25_size": len(cwe.get("top25", []))} if cwe else None),
        "version": doc.get("version", ""), "tool": f"{run['tool']['driver']['name']} {run['tool']['driver'].get('version', '')}",
        "total": len(results), "levels": dict(levels), "rule_rows": rule_rows, "rule_count": len(by_rule),
        "file_rows": [{"file": f, "count": n} for f, n in by_file.most_common(top_files)], "file_count": len(by_file),
        "summary": metrics.get("summary", {}), "functions": metrics.get("functions", [])[:top_functions],
        "functions_total": metrics.get("functionsTotal", 0), "standards": dict(standards),
        "metric_breaches": len(breaches),
    }
