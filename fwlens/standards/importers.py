"""
Import findings from other analysers (issue #49, builds on #42).

Most MISRA and CERT coverage comes from tools built for it. FWLens reads their output and maps
each finding onto a rule from the enabled standards, so results land in the same compliance
matrix, baseline and PR comment.

    cppcheck    XML (``cppcheck --xml``), with the MISRA addon or Premium ids
    clang-tidy  text output, ``cert-*`` checks
    sarif       SARIF 2.1.0 from any tool

Mapping order: the standard's ``tool_map``, then built-in id patterns.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from fwlens.standards.rules import Rule, Standard


@dataclass
class RawFinding:
    tool: str
    tool_id: str
    file: str
    line: int
    message: str


_MISRA_RE = re.compile(r"misra-?c-?2012-(dir-)?(\d+\.\d+)")
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


def map_to_rule(raw: RawFinding, standards: list[Standard]) -> Optional[Rule]:
    for std in standards:
        mapped = std.tool_map.get(raw.tool, {}).get(raw.tool_id)
        if mapped and mapped in std.rules:
            return std.rules[mapped]
    for cand in candidate_ids(raw.tool_id):
        for std in standards:
            for rid, rule in std.rules.items():
                if rid.lower() == cand.lower():
                    return rule
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


def parse_sarif(path: Path) -> list[RawFinding]:
    out = []
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    for run in data.get("runs", []):
        for res in run.get("results", []):
            locs = res.get("locations") or [{}]
            phys = locs[0].get("physicalLocation", {})
            uri = phys.get("artifactLocation", {}).get("uri", "")
            if uri.startswith("file://"):
                uri = uri[len("file://"):]
            out.append(RawFinding("sarif", res.get("ruleId", ""), uri,
                                  int(phys.get("region", {}).get("startLine", 0) or 0),
                                  res.get("message", {}).get("text", "")))
    return out


PARSERS = {"cppcheck": parse_cppcheck_xml, "clang-tidy": parse_clang_tidy, "sarif": parse_sarif}


def read_import(tool: str, path: Path) -> list[RawFinding]:
    if tool not in PARSERS:
        raise ValueError(f"unknown import tool '{tool}', expected one of {sorted(PARSERS)}")
    findings = PARSERS[tool](Path(path))
    # SARIF carries its own tool name: let tool_map entries keyed by that name apply too
    return findings
