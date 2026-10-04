"""
Deviation register (issue #49): a separate YAML file so deviations are reviewed and expire
independently of the rules.

    deviations:
      - id: DEV-001
        standard: misra-c-2012
        rule: "21.3"
        type: project            # project | specific
        justification: ...
        approved_by: ...
        scope: { paths: ["src/platform/*.c"], functions: [alloc_init] }
        expires: 2027-03-31

A deviation can also be applied at the place it is needed, with a comment on the line of the
finding or the line above it that names the rule and the register entry:

    /* fwlens-deviation: Rule 11.4 DEV-007 */
    ptr = (uint32_t *)0x40021000u;

The register entry still carries the justification, approval and expiry, and the usual checks
(mandatory rules, expiry) still apply. A deviation with `scope: { inline: true }` applies only
through such comments. A comment that names an unknown entry or a different rule covers nothing,
so the finding stays visible.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

import yaml

from fwlens.standards.rules import RuleFileError, Standard


@dataclass
class Deviation:
    id: str
    standard: str
    rule: str
    type: str
    justification: str
    approved_by: str = ""
    paths: list[str] = field(default_factory=list)
    functions: list[str] = field(default_factory=list)
    expires: date | None = None
    inline: bool = False        # applies only where a fwlens-deviation comment names it

    @property
    def key(self) -> str:
        return f"{self.standard}:{self.rule}"


def load_deviations(path: Path, standards: dict[str, Standard]) -> list[Deviation]:
    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as e:
        raise RuleFileError(f"{path}: invalid YAML: {e}") from e
    out: list[Deviation] = []
    seen: set[str] = set()
    for i, d in enumerate(raw.get("deviations", []) or []):
        where = f"deviation #{i + 1}"
        if not isinstance(d, dict):
            raise RuleFileError(f"{path}: {where}: must be a mapping")
        for key in ("id", "standard", "rule", "type", "justification"):
            if not d.get(key):
                raise RuleFileError(f"{path}: {where}: missing required field '{key}'")
        if d["id"] in seen:
            raise RuleFileError(f"{path}: {where}: duplicate deviation id '{d['id']}'")
        seen.add(d["id"])
        if d["type"] not in ("project", "specific"):
            raise RuleFileError(f"{path}: deviation {d['id']}: type must be 'project' or 'specific'")
        std = standards.get(d["standard"])
        if std is None or str(d["rule"]) not in std.rules:
            raise RuleFileError(f"{path}: deviation {d['id']}: unknown rule {d['standard']}:{d['rule']}")
        scope = d.get("scope") or {}
        if d["type"] == "specific" and not (scope.get("paths") or scope.get("functions") or scope.get("inline")):
            raise RuleFileError(f"{path}: deviation {d['id']}: a specific deviation needs scope.paths, "
                                "scope.functions or scope.inline")
        expires = d.get("expires")
        if expires is not None and not isinstance(expires, date):
            try:
                expires = date.fromisoformat(str(expires))
            except ValueError:
                raise RuleFileError(f"{path}: deviation {d['id']}: expires must be a date (YYYY-MM-DD)")
        out.append(Deviation(
            id=str(d["id"]), standard=d["standard"], rule=str(d["rule"]), type=d["type"],
            justification=str(d["justification"]), approved_by=str(d.get("approved_by", "")),
            paths=list(scope.get("paths", [])), functions=list(scope.get("functions", [])), expires=expires,
            inline=bool(scope.get("inline")),
        ))
    return out


MARKER_RE = re.compile(r"fwlens-deviation:\s*(?:Rule\s+)?(?P<rule>[\w.]+)\s+(?P<id>[A-Za-z0-9_.-]+)")

# (file, line) -> {(rule, deviation id)}
Markers = dict[tuple[str, int], set[tuple[str, str]]]


def scan_markers(files: dict[str, Path]) -> Markers:
    """Inline deviation comments in the given files ({repo-relative path: file on disk})."""
    out: Markers = {}
    for rel, path in files.items():
        try:
            lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for n, text in enumerate(lines, start=1):
            for m in MARKER_RE.finditer(text):
                out.setdefault((rel, n), set()).add((m.group("rule"), m.group("id")))
    return out


def _marked(markers: Markers | None, dev: Deviation, finding) -> bool:
    if not markers or not finding.line:
        return False
    return any((dev.rule, dev.id) in markers.get((finding.file, ln), ()) for ln in (finding.line, finding.line - 1))


def covers(dev: Deviation, finding, markers: Markers | None = None) -> bool:
    if dev.key != finding.metric:
        return False
    if _marked(markers, dev, finding):
        return True
    if dev.inline:
        return False
    if dev.paths and not any(fnmatch.fnmatch(finding.file, pat) for pat in dev.paths):
        return False
    return not (dev.functions and finding.function not in dev.functions)


@dataclass
class DeviationOutcome:
    active: list = field(default_factory=list)      # findings that still count
    deviated: list = field(default_factory=list)    # (finding, deviation)
    problems: list = field(default_factory=list)    # (deviation, message)


def apply_deviations(findings: list, deviations: list[Deviation], standards: dict[str, Standard],
                     today: date | None = None, markers: Markers | None = None) -> DeviationOutcome:
    today = today or date.today()
    out = DeviationOutcome()
    problems_seen: set[tuple[str, str]] = set()

    def problem(dev: Deviation, message: str) -> None:
        if (dev.id, message) not in problems_seen:
            problems_seen.add((dev.id, message))
            out.problems.append((dev, message))

    for f in findings:
        chosen = None
        for dev in deviations:
            if not covers(dev, f, markers):
                continue
            rule = standards[dev.standard].rules[dev.rule]
            if rule.undeviable:
                problem(dev, f"{rule.category} rules cannot be deviated")
                continue
            if dev.expires and dev.expires < today:
                problem(dev, f"expired on {dev.expires.isoformat()}")
                continue
            chosen = dev
            break
        if chosen:
            f.deviation = chosen.id
            out.deviated.append((f, chosen))
        else:
            out.active.append(f)
    return out
