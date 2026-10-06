"""
CWE ids for rules. The bundled ``cwe-map.yaml`` adds ids to the guidelines of the bundled standards
when they load, and this module holds the CWE Top 25 list that the SARIF summary compares against.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

MAP_FILE = Path(__file__).parent / "data" / "cwe-map.yaml"

# MITRE CWE Top 25 Most Dangerous Software Weaknesses, 2024 edition.
TOP25_EDITION = "2024"
TOP25 = ["CWE-79", "CWE-787", "CWE-89", "CWE-352", "CWE-22", "CWE-125", "CWE-78", "CWE-416", "CWE-862", "CWE-434",
         "CWE-94", "CWE-20", "CWE-77", "CWE-287", "CWE-269", "CWE-502", "CWE-200", "CWE-863", "CWE-918", "CWE-119",
         "CWE-476", "CWE-798", "CWE-190", "CWE-400", "CWE-306"]

_ID = re.compile(r"^CWE-\d+$")


def normalise(value) -> str:
    """CWE-476 from 476, "cwe-476" or "CWE-476"."""
    text = str(value).strip().upper()
    return text if text.startswith("CWE-") else f"CWE-{text}"


def load_map(path: Path = MAP_FILE) -> dict[str, dict[str, list[str]]]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return {std: {str(rid): [normalise(c) for c in cwes] for rid, cwes in rules.items()} for std, rules in raw.items()}


def apply_map(standards: dict) -> None:
    """Add the mapped CWE ids to the rules of the bundled standards, keeping what a rule already lists."""
    for std_id, rules in load_map().items():
        std = standards.get(std_id)
        if std is None:
            continue
        for rid, cwes in rules.items():
            rule = std.rules.get(rid)
            if rule is None:
                continue
            have = [normalise(c) for c in rule.cwe]
            rule.cwe = have + [c for c in cwes if c not in have]
    for std in standards.values():
        for rule in std.rules.values():
            rule.cwe = [normalise(c) for c in rule.cwe]


def valid(cwe: str) -> bool:
    return bool(_ID.match(cwe))
