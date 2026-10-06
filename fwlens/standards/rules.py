"""
Rule definitions loaded from YAML (issue #49).

Rules are data. A standard is one YAML file, extra files can be added through
``standards.extra_rule_dirs``. Native checks are declarative: the YAML names an engine and
its parameters, Python provides a small fixed set of engines (see fwlens.standards.engines).

Files are validated on load and every error names the file, the rule and the field.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

import yaml

SCHEMA_VERSION = 1
BUILTIN_DIR = Path(__file__).parent / "builtin"
CHECK_TYPES = {"native", "import", "manual"}
ENGINES = {"ast", "callgraph", "compound_body", "detector", "source", "diagnostic", "system"}
COVERAGES = {"full", "partial"}
SCOPES = {"single-tu", "system"}
KINDS = {"rule", "directive", "recommendation"}


class RuleFileError(ValueError):
    """A rule, profile or deviation file is invalid."""


@dataclass
class Check:
    """One way a rule is checked: a type (native, import, manual) and, for native, an engine."""
    type: str
    engine: str | None = None
    match: dict = field(default_factory=dict)


@dataclass
class Rule:
    standard: str
    id: str
    kind: str
    title: str
    category: str
    decidable: bool
    scope: str
    check_type: str
    engine: str | None = None
    match: dict = field(default_factory=dict)
    cwe: list[str] = field(default_factory=list)
    notes: str = ""
    help: str = ""                            # how to fix it, shown as rule help in SARIF and the report
    severity: str = "warning"
    undeviable: bool = False
    coverage: str = "full"                    # "partial": a native check that finds only some violations
    checks: list[Check] = field(default_factory=list)

    @property
    def native_checks(self) -> list[Check]:
        return [c for c in self.checks if c.type == "native"]

    @property
    def key(self) -> str:
        """Unique id across standards, used as the finding's metric: ``misra-c-2012:15.1``."""
        return f"{self.standard}:{self.id}"


@dataclass
class Standard:
    id: str
    name: str
    revision: str
    categories: list[str]
    rules: dict[str, Rule] = field(default_factory=dict)
    tool_map: dict[str, dict[str, str]] = field(default_factory=dict)
    source: Path | None = None
    guideline_uri: str = ""                  # where the standard is published, when the file says so


def _fail(path, where: str, message: str):
    raise RuleFileError(f"{path}: {where}: {message}")


def _require(path, where: str, mapping: dict, key: str, kinds):
    if key not in mapping:
        _fail(path, where, f"missing required field '{key}'")
    if not isinstance(mapping[key], kinds):
        _fail(path, where, f"field '{key}' must be {kinds}, got {type(mapping[key]).__name__}")
    return mapping[key]


def _parse_check(path, where: str, check: dict) -> Check:
    ctype = _require(path, where, check, "type", str)
    if ctype not in CHECK_TYPES:
        _fail(path, where, f"check.type must be one of {sorted(CHECK_TYPES)}")
    engine = check.get("engine")
    match = dict(check.get("match") or {})
    if ctype != "native":
        return Check(ctype, None, match)
    if engine not in ENGINES:
        _fail(path, where, f"check.engine must be one of {sorted(ENGINES)}, got {engine!r}")
    if engine == "ast" and "cursor" not in match:
        _fail(path, where, "check.match.cursor is required for the ast engine")
    if engine == "diagnostic":
        if "pattern" not in match and "option" not in match:
            _fail(path, where, "check.match needs a 'pattern' (regular expression over the message) "
                               "or an 'option' (the warning's -W name, or a list of them) for the diagnostic engine")
        if "option" in match and not isinstance(match["option"], (str, list)):
            _fail(path, where, "check.match.option must be a string or a list of strings")
    if engine in ("source", "diagnostic") and "pattern" in match:
        pattern = match["pattern"]
        if not isinstance(pattern, str):
            _fail(path, where, "check.match.pattern must be a string")
        try:
            re.compile(pattern)
        except re.error as exc:
            _fail(path, where, f"check.match.pattern is not a valid regular expression: {exc}")
    elif engine in ("source", "detector", "system"):
        from fwlens.standards.engines import DETECTORS, SOURCE_CHECKS, SYSTEM_CHECKS
        registries: dict[str, dict] = {"detector": DETECTORS, "system": SYSTEM_CHECKS, "source": SOURCE_CHECKS}  # type: ignore[dict-item]
        known = registries[engine]
        name = match.get("name")
        if name not in known:
            hint = " or check.match.pattern" if engine == "source" else ""
            _fail(path, where, f"check.match.name{hint} is required: a known {engine} check, got {name!r}; "
                               f"known: {sorted(known)}")
    return Check(ctype, engine, match)


def parse_standard(raw: dict, path: Path) -> Standard:
    if not isinstance(raw, dict):
        _fail(path, "file", "top level must be a mapping")
    if raw.get("schema_version") != SCHEMA_VERSION:
        _fail(path, "schema_version", f"expected {SCHEMA_VERSION}, got {raw.get('schema_version')!r}")
    head = _require(path, "standard", raw, "standard", dict)
    sid = _require(path, "standard", head, "id", str)
    categories = _require(path, "standard", head, "categories", list)
    undeviable = set(head.get("undeviable_categories", []))
    severity_map = head.get("severity_map", {})
    std = Standard(sid, _require(path, "standard", head, "name", str), str(head.get("revision", "")),
                   list(categories), source=path,
                   guideline_uri=str(head.get("guideline_text", "")) if str(head.get("guideline_text", "")).startswith("http") else "")

    for i, r in enumerate(_require(path, "file", raw, "rules", list)):
        rid = str(r.get("id", f"#{i}")) if isinstance(r, dict) else f"#{i}"
        where = f"rule {rid}"
        if not isinstance(r, dict):
            _fail(path, where, "must be a mapping")
        rid = str(_require(path, where, r, "id", (str, int, float)))
        if rid in std.rules:
            _fail(path, where, "duplicate rule id")
        kind = _require(path, where, r, "kind", str)
        if kind not in KINDS:
            _fail(path, where, f"kind must be one of {sorted(KINDS)}")
        category = _require(path, where, r, "category", str)
        if category not in categories:
            _fail(path, where, f"category '{category}' is not one of the standard's categories {categories}")
        scope = _require(path, where, r, "scope", str)
        if scope not in SCOPES:
            _fail(path, where, f"scope must be one of {sorted(SCOPES)}")
        raw_check = r.get("check")
        if isinstance(raw_check, dict):
            raw_checks = [raw_check]
        elif isinstance(raw_check, list) and raw_check and all(isinstance(c, dict) for c in raw_check):
            raw_checks = raw_check
        else:
            _fail(path, where, "missing required field 'check' (a mapping, or a list of mappings)")
        checks = [_parse_check(path, where, c) for c in raw_checks]
        coverage = str(r.get("coverage", "full"))
        if coverage not in COVERAGES:
            _fail(path, where, f"coverage must be one of {sorted(COVERAGES)}")
        # The rule's type is native if anything native checks it, else import, else manual.
        types = {c.type for c in checks}
        ctype = "native" if "native" in types else "import" if "import" in types else "manual"
        first = next((c for c in checks if c.type == "native"), checks[0])
        std.rules[rid] = Rule(
            standard=sid, id=rid, kind=kind, title=_require(path, where, r, "title", str),
            category=category, decidable=bool(_require(path, where, r, "decidable", bool)), scope=scope,
            check_type=ctype, engine=first.engine, match=dict(first.match),
            cwe=list(r.get("cwe", [])), notes=str(r.get("notes", "")), help=str(r.get("help", "")),
            severity=severity_map.get(category, "warning"), undeviable=category in undeviable,
            coverage=coverage, checks=checks,
        )
    tool_map = raw.get("tool_map", {}) or {}
    for tool, mapping in tool_map.items():
        for tool_id, rid in mapping.items():
            if str(rid) not in std.rules:
                _fail(path, f"tool_map.{tool}", f"'{tool_id}' maps to unknown rule '{rid}'")
        std.tool_map[tool] = {str(k): str(v) for k, v in mapping.items()}
    return std


def load_standard_file(path: Path) -> Standard:
    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise RuleFileError(f"{path}: invalid YAML: {e}") from e
    return parse_standard(raw, Path(path))


def load_standards(extra_dirs: Iterable[Path] = ()) -> dict[str, Standard]:
    """Built-in files first, then any ``*.yaml`` in the extra directories. An extra file with the
    same standard id replaces the built-in one, so a project can override a whole standard."""
    standards: dict[str, Standard] = {}
    for directory in [BUILTIN_DIR, *[Path(d) for d in extra_dirs]]:
        if not directory.is_dir():
            if directory != BUILTIN_DIR:
                raise RuleFileError(f"standards.extra_rule_dirs: {directory} is not a directory")
            continue
        for f in sorted(directory.glob("*.yaml")):
            std = load_standard_file(f)
            standards[std.id] = std
    from fwlens.standards.cwe import apply_map
    apply_map(standards)
    return standards
