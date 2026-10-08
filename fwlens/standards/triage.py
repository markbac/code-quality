"""
Message triage and guideline recategorisation records (#88), two small YAML files read like the deviation
register. Neither is a compliance claim: they record what the team decided so the decision is reviewed with
the code. MISRA Compliance expects both as process documents.

Triage (`standards.triage_file`), keyed by the stable finding id (the `id` in the findings JSON):

    triage:
      - id: src/app.c:run:misra-c-2012:15.1
        outcome: false_positive      # true_positive | false_positive | accepted
        reason: The goto leaves a nested loop and is reviewed in the design note.
        owner: A. Developer
        date: 2026-10-08

`false_positive` removes the finding from the gate and lists it as triaged. `true_positive` and `accepted` keep
it counting (an accepted finding that should stop failing needs a deviation) and only record the decision. An
entry whose id matches no finding is reported as stale.

Recategorisation (`standards.recategorisation_file`):

    recategorisations:
      - standard: misra-c-2012
        rule: "11.4"
        category: required           # a category the standard defines
        reason: Pointer-to-integer conversions are treated as errors on this product.
        approved_by: Safety lead
        date: 2026-10-08

The finding's category (and so its severity) follows the new one, and the matrix shows the original beside it.
A mandatory guideline cannot be moved to a weaker category.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import date
from pathlib import Path

import yaml

from fwlens.standards.rules import RuleFileError, Standard

OUTCOMES = ("true_positive", "false_positive", "accepted")
_STRENGTH = {"advisory": 0, "required": 1, "mandatory": 2}


@dataclass
class Triage:
    id: str
    outcome: str
    reason: str
    owner: str
    date: date | None = None


@dataclass
class Recategorisation:
    standard: str
    rule: str
    category: str
    reason: str
    approved_by: str = ""
    date: date | None = None

    @property
    def key(self) -> str:
        return f"{self.standard}:{self.rule}"


def _read(path: Path, top: str) -> list:
    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as e:
        raise RuleFileError(f"{path}: invalid YAML: {e}") from e
    except OSError as e:
        raise RuleFileError(f"{path}: {e}") from e
    items = raw.get(top, []) if isinstance(raw, dict) else None
    if items is None or not isinstance(items, list):
        raise RuleFileError(f"{path}: expected a '{top}' list")
    return items


def _date(value, path: Path, where: str) -> date | None:
    if value is None or isinstance(value, date):
        return value
    try:
        return date.fromisoformat(str(value))
    except ValueError:
        raise RuleFileError(f"{path}: {where}: date must be YYYY-MM-DD") from None


def load_triage(path: Path) -> list[Triage]:
    out, seen = [], set()
    for i, item in enumerate(_read(path, "triage"), start=1):
        where = f"triage #{i}"
        if not isinstance(item, dict):
            raise RuleFileError(f"{path}: {where}: must be a mapping")
        for key in ("id", "outcome", "reason", "owner"):
            if not item.get(key):
                raise RuleFileError(f"{path}: {where}: missing required field '{key}'")
        if item["outcome"] not in OUTCOMES:
            raise RuleFileError(f"{path}: {where}: outcome must be one of {list(OUTCOMES)}")
        if item["id"] in seen:
            raise RuleFileError(f"{path}: {where}: duplicate id '{item['id']}'")
        seen.add(item["id"])
        out.append(Triage(str(item["id"]), item["outcome"], str(item["reason"]), str(item["owner"]),
                          _date(item.get("date"), path, where)))
    return out


def load_recategorisations(path: Path, standards: dict[str, Standard]) -> list[Recategorisation]:
    out, seen = [], set()
    for i, item in enumerate(_read(path, "recategorisations"), start=1):
        where = f"recategorisation #{i}"
        if not isinstance(item, dict):
            raise RuleFileError(f"{path}: {where}: must be a mapping")
        for key in ("standard", "rule", "category", "reason"):
            if not item.get(key):
                raise RuleFileError(f"{path}: {where}: missing required field '{key}'")
        std = standards.get(item["standard"])
        rule = std.rules.get(str(item["rule"])) if std else None
        if std is None or rule is None:
            raise RuleFileError(f"{path}: {where}: unknown guideline {item['standard']}:{item['rule']}")
        if item["category"] not in std.categories:
            raise RuleFileError(f"{path}: {where}: category must be one of {list(std.categories)}")
        if rule.category == "mandatory" and _STRENGTH.get(item["category"], 1) < _STRENGTH["mandatory"]:
            raise RuleFileError(f"{path}: {where}: mandatory guideline {rule.key} cannot move to a weaker category")
        guideline = (item["standard"], str(item["rule"]))
        if guideline in seen:
            raise RuleFileError(f"{path}: {where}: duplicate guideline {item['standard']}:{item['rule']}")
        seen.add(guideline)
        out.append(Recategorisation(item["standard"], str(item["rule"]), item["category"], str(item["reason"]),
                                    str(item.get("approved_by", "")), _date(item.get("date"), path, where)))
    return out


def apply_recategorisations(standards: dict[str, Standard], recats: list[Recategorisation]) -> dict[str, tuple]:
    """Change the category of the named guidelines in `standards`. Returns {rule key: (original, new, entry)}."""
    changed: dict[str, tuple] = {}
    for r in recats:
        std = standards[r.standard]
        rule = std.rules[r.rule]
        if rule.category == r.category:
            continue
        std.rules[r.rule] = replace(rule, category=r.category, severity=std.severity_map.get(r.category, rule.severity),
                                    undeviable=r.category in std.undeviable_categories)
        changed[rule.key] = (rule.category, r.category, r)
    return changed


def apply_triage(findings: list, entries: list[Triage]) -> tuple[list, list[tuple], list[str]]:
    """(findings that still count, [(finding, entry)] triaged, stale entry ids)."""
    by_id = {e.id: e for e in entries}
    kept, triaged, used = [], [], set()
    for f in findings:
        e = by_id.get(f.id)
        if e is None:
            kept.append(f)
            continue
        used.add(e.id)
        triaged.append((f, e))
        if e.outcome != "false_positive":
            kept.append(f)
    return kept, triaged, sorted(set(by_id) - used)
