"""
GitLab SAST report (security report schema 15) for coding-standard findings (#91).

Only findings from the coding standards are written (MISRA C, CERT C and the others), not metric breaches or
architecture rules: those belong in the Code Quality report. Severity follows the guideline category
(mandatory High, required Medium, advisory Low). Each finding carries the standard's guideline id and, where the
rule maps to one, its CWE ids as identifiers. Deviated findings are left out, as in the other reports.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fwlens import __version__
from fwlens.baseline import Breach
from fwlens.model.project import ProjectModel
from fwlens.output.reporters import fingerprint_for
from fwlens.output.sarif import rule_info

SCHEMA_VERSION = "15.0.7"
DEFAULT_SAST_REPORT = "gl-sast-report.json"
SEVERITY = {"mandatory": "High", "required": "Medium", "advisory": "Low"}
_NAMESPACE = uuid.UUID("5a1d3c52-5f0e-4a43-9a5a-7e2f4f0f6d11")
_VENDOR = {"name": "FWLens"}


def _tool() -> dict:
    return {"id": "fwlens", "name": "FWLens", "vendor": _VENDOR, "version": __version__}


def _identifiers(b: Breach, meta: dict) -> list[dict]:
    ids = [{"type": meta["standard"], "name": f"{meta['standardName']} {meta['kind']} {meta['id']}", "value": meta["id"]}]
    for cwe in meta["cwe"]:
        number = str(cwe).upper().replace("CWE-", "")
        ids.append({"type": "cwe", "name": f"CWE-{number}", "value": number,
                    "url": f"https://cwe.mitre.org/data/definitions/{number}.html"})
    return ids


def to_sast(model: ProjectModel, breaches: list[Breach], now: datetime | None = None) -> dict:
    info = rule_info(model)
    stamp = (now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%S")
    vulnerabilities = []
    for b in breaches:
        meta = info.get(b.metric)
        if b.kind != "rule" or meta is None or b.deviation:
            continue
        vulnerabilities.append({
            "id": str(uuid.uuid5(_NAMESPACE, fingerprint_for(b))),
            "name": f"{meta['id']}: {meta['title']}",
            "description": (b.description or meta["title"]) + (f" (in {b.function})" if b.function else ""),
            "severity": SEVERITY.get(b.category or "", "Medium"),
            "scanner": _tool(),
            "location": {"file": b.file, "start_line": max(1, b.line or 1)},
            "identifiers": _identifiers(b, meta),
        })
    return {"version": SCHEMA_VERSION, "vulnerabilities": vulnerabilities, "remediations": [],
            "scan": {"analyzer": _tool(), "scanner": _tool(), "type": "sast",
                     "start_time": stamp, "end_time": stamp, "status": "success"}}


def write_sast_report(model: ProjectModel, breaches: list[Breach], path: Path | str) -> Path:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(to_sast(model, breaches), indent=2) + "\n", encoding="utf-8")
    return out
