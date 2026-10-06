"""
Import findings from other analysers (issue #49, builds on #42).

Most MISRA and CERT coverage comes from tools built for it. FWLens reads their output and maps
each finding onto a rule from the enabled standards, so results land in the same compliance
matrix, baseline and PR comment.

    cppcheck        XML (``cppcheck --xml``), with the MISRA addon or Premium ids
    clang-tidy      text output, ``cert-*`` and ``clang-analyzer-*`` checks
    clang-tidy-yaml the YAML written by ``clang-tidy --export-fixes=file``
    clang-analyzer  plist output of the clang static analyser (``scan-build -plist``)
    sarif           SARIF 2.1.0 from any tool, for example ``gcc -fanalyzer -fdiagnostics-format=sarif``

Mapping order: the standard's ``tool_map`` (an exact id, then a ``*`` pattern), then built-in id
patterns.
"""

from __future__ import annotations

import fnmatch
import json
import plistlib
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

from fwlens.standards.rules import Rule, Standard


@dataclass
class RawFinding:
    tool: str
    tool_id: str
    file: str
    line: int
    message: str


_MISRA_RE = re.compile(r"misra-?c-?(?:2012|2023)-(dir-)?(\d+\.\d+)")
_CERT_RE = re.compile(r"cert-([a-z]{3}\d{2})-c\b")


def candidate_ids(tool_id: str) -> list[str]:
    """Rule ids a tool's check id might correspond to (matched case-insensitively later)."""
    low = tool_id.lower()
    out: list[str] = []
    m = _MISRA_RE.search(low)
    if m:
        out.append(("D" if m.group(1) else "") + m.group(2))
    m = _CERT_RE.search(low)
    if m:
        out.append(m.group(1).upper() + "-C")
    return out


def map_to_rule(raw: RawFinding, standards: list[Standard]) -> Rule | None:
    for std in standards:
        mapped = std.tool_map.get(raw.tool, {}).get(raw.tool_id)
        if mapped and mapped in std.rules:
            return std.rules[mapped]
    for cand in candidate_ids(raw.tool_id):
        for std in standards:
            for rid, rule in std.rules.items():
                if rid.lower() == cand.lower():
                    return rule
    for std in standards:
        for pattern, mapped in std.tool_map.get(raw.tool, {}).items():
            if any(ch in pattern for ch in "*?[") and fnmatch.fnmatchcase(raw.tool_id, pattern) and mapped in std.rules:
                return std.rules[mapped]
    return None


def parse_cppcheck_xml(path: Path) -> list[RawFinding]:
    out = []
    for err in ET.parse(path).getroot().iter("error"):
        loc = err.find("location")
        if loc is None:
            continue
        out.append(RawFinding("cppcheck", err.get("id", ""), loc.get("file", ""),
                              int(loc.get("line", "0") or 0), err.get("msg", "")))
    return out


_TIDY_RE = re.compile(r"^(?P<file>.+?):(?P<line>\d+):(?P<col>\d+): (?:warning|error): (?P<msg>.*) \[(?P<checks>[\w\-,.]+)\]$")


def parse_clang_tidy(path: Path) -> list[RawFinding]:
    out = []
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        m = _TIDY_RE.match(line.strip())
        if m:
            for check in m.group("checks").split(","):
                out.append(RawFinding("clang-tidy", check, m.group("file"), int(m.group("line")), m.group("msg")))
    return out


def parse_clang_tidy_yaml(path: Path) -> list[RawFinding]:
    """The YAML from ``clang-tidy --export-fixes``. It gives a file offset, so the line is worked out here."""
    import yaml
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8", errors="replace")) or {}
    out = []
    lines_of: dict[str, list[int]] = {}
    for diag in data.get("Diagnostics", []):
        msg = diag.get("DiagnosticMessage", {})
        file = msg.get("FilePath", "")
        if file not in lines_of:
            try:
                text = Path(file).read_text(encoding="utf-8", errors="replace")
                lines_of[file] = [i for i, ch in enumerate(text) if ch == "\n"]
            except OSError:
                lines_of[file] = []
        offset = int(msg.get("FileOffset", 0) or 0)
        newlines = lines_of[file]
        line = sum(1 for n in newlines if n < offset) + 1 if newlines else 0
        out.append(RawFinding("clang-tidy", diag.get("DiagnosticName", ""), file, line, msg.get("Message", "")))
    return out


def parse_clang_analyzer_plist(path: Path) -> list[RawFinding]:
    """Plist from the clang static analyser. A check is reported as clang-analyzer-<check name>."""
    with open(path, "rb") as fh:
        data = plistlib.load(fh)
    files = data.get("files", [])
    out = []
    for diag in data.get("diagnostics", []):
        loc = diag.get("location", {})
        idx = loc.get("file", 0)
        file = files[idx] if isinstance(idx, int) and 0 <= idx < len(files) else ""
        check = diag.get("check_name", "") or diag.get("category", "")
        out.append(RawFinding("clang-tidy", f"clang-analyzer-{check}", file, int(loc.get("line", 0) or 0),
                              diag.get("description", "")))
    return out


def parse_sarif(path: Path) -> list[RawFinding]:
    out = []
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    for run in data.get("runs", []):
        for res in run.get("results", []):
            locs = res.get("locations") or [{}]
            phys = locs[0].get("physicalLocation", {})
            uri = phys.get("artifactLocation", {}).get("uri", "")
            uri = uri.removeprefix("file://")
            out.append(RawFinding("sarif", res.get("ruleId", ""), uri,
                                  int(phys.get("region", {}).get("startLine", 0) or 0),
                                  res.get("message", {}).get("text", "")))
    return out


PARSERS = {"cppcheck": parse_cppcheck_xml, "clang-tidy": parse_clang_tidy, "clang-tidy-yaml": parse_clang_tidy_yaml,
           "clang-analyzer": parse_clang_analyzer_plist, "sarif": parse_sarif}


def read_import(tool: str, path: Path) -> list[RawFinding]:
    if tool not in PARSERS:
        raise ValueError(f"unknown import tool '{tool}', expected one of {sorted(PARSERS)}")
    findings = PARSERS[tool](Path(path))
    # SARIF carries its own tool name: let tool_map entries keyed by that name apply too
    return findings
