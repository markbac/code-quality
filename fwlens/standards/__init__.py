"""
Optional coding-standard compliance: MISRA C, CERT C and any standard described in YAML
(issue #49). Off unless ``standards.enabled`` is set in the config.

    run_standards(model, config) -> StandardsResult
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from fwlens.baseline import Breach
from fwlens.config import FwLensConfig, StandardSelection
from fwlens.identity import project_root, relative_posix, statement_fingerprint
from fwlens.model.project import ProjectModel
from fwlens.standards.deviations import Deviation, apply_deviations, load_deviations, scan_markers
from fwlens.standards.engines import Hit, Records, run_ast_engines, run_callgraph_engine, run_system_engines
from fwlens.standards.importers import map_to_rule, read_import
from fwlens.standards.rules import Rule, RuleFileError, Standard, load_standards
from fwlens.standards.triage import apply_recategorisations, load_recategorisations, load_triage
from fwlens.standards.sourcechecks import (
    diagnostic_flags,
    analysed_modules,
    first_party_files,
    run_diagnostic_engine,
    run_source_engines,
)

__all__ = ["RuleFileError", "StandardsResult", "load_standards", "run_standards", "select_rules"]

CATEGORY_LEVEL = {"mandatory": "error", "required": "warning", "advisory": "note"}


@dataclass
class StandardsResult:
    standards: dict[str, Standard]
    rules: list[Rule]                                  # the selected rules
    findings: list[Breach] = field(default_factory=list)          # active, these gate
    deviated: list[tuple] = field(default_factory=list)           # (Breach, Deviation)
    problems: list[tuple] = field(default_factory=list)           # (Deviation, message)
    sources: dict[str, set] = field(default_factory=dict)         # rule key -> {"native", "imported"}
    unmapped: dict[str, int] = field(default_factory=dict)        # tool -> findings not mapped to a rule
    deviations: list[Deviation] = field(default_factory=list)
    recategorised: dict[str, tuple] = field(default_factory=dict)  # rule key -> (original, new, Recategorisation)
    triage: list = field(default_factory=list)                    # Triage entries read from standards.triage_file
    triaged: list[tuple] = field(default_factory=list)            # (Breach, Triage), set once finding ids exist
    stale_triage: list[str] = field(default_factory=list)         # triage ids that match no finding


def select_rules(standards: dict[str, Standard], selections: list[StandardSelection]) -> list[Rule]:
    rules: list[Rule] = []
    for sel in selections:
        std = standards.get(sel.standard)
        if std is None:
            raise RuleFileError(f"standards.enabled: unknown standard '{sel.standard}', "
                                f"known: {sorted(standards)}")
        for rid, rule in std.rules.items():
            if sel.include_categories and rule.category not in sel.include_categories:
                continue
            if sel.include_ids and rid not in sel.include_ids:
                continue
            if rid in sel.exclude_rules:
                continue
            rules.append(rule)
    return rules


def _enclosing_function(model: ProjectModel, file: Path, line: int) -> str | None:
    best = None
    for f in model.first_party_functions():
        if Path(f.file) == file and f.line <= line < f.line + max(f.loc, 1):
            if best is None or f.line > best.line:
                best = f
    return best.name if best else None


def _finding(rule: Rule, root: Path, file: Path, line: int, function: str | None, text: str,
             fingerprint: dict | None = None) -> Breach:
    return Breach("", "rule", relative_posix(file, root), rule.key, 1.0, 0.0, line=line, function=function,
                  fingerprint=fingerprint or statement_fingerprint(text), category=rule.category,
                  description=rule.title)


def _has_engine(rule: Rule, *engines: str) -> bool:
    return any(c.engine in engines for c in rule.native_checks)


def _native_hits(model: ProjectModel, config: FwLensConfig, rules: list[Rule]) -> list[Hit]:
    native = [r for r in rules if r.check_type == "native"]
    if not native:
        return []
    hits: list[Hit] = []
    file_cache: dict = {}
    records = Records()
    diag_rules = [r for r in native if _has_engine(r, "diagnostic")]
    ast_rules = [r for r in native if _has_engine(r, "ast", "compound_body", "detector")]
    system_rules = [r for r in native if _has_engine(r, "system")]
    if ast_rules or diag_rules or system_rules:
        import fwlens.parser.ast_walker as walker
        from fwlens.parser.ast_walker import _ensure_clang, build_clang_args
        _ensure_clang(config)
        ci = walker._clang
        first_party = {Path(m.path) for m in analysed_modules(model, config)}
        fp_files = {str(p) for p in first_party_files(model, config)}
        extra = diagnostic_flags(diag_rules)
        for tu in model.translation_units:
            if Path(tu.path) not in first_party or not Path(tu.path).exists():
                continue
            index = ci.Index.create()
            parsed = index.parse(str(tu.path), args=[*build_clang_args(tu, config), "-D__NO_CTYPE", *extra])
            hits.extend(run_ast_engines(ci, Path(tu.path), parsed, ast_rules, file_cache, records,
                                        collect=bool(system_rules), first_party=fp_files))
            hits.extend(run_diagnostic_engine(Path(tu.path), parsed, diag_rules))
    hits.extend(run_callgraph_engine(model, native, file_cache))
    hits.extend(run_system_engines(records, system_rules))
    hits.extend(run_source_engines(model, config, [r for r in native if _has_engine(r, "source")]))
    return hits


def run_standards(model: ProjectModel, config: FwLensConfig, today=None) -> StandardsResult:
    cached = getattr(model, "_standards_result", None)
    if cached is not None:
        return cached

    cfg = config.standards
    standards = load_standards(cfg.extra_rule_dirs)
    recategorised = {}
    if cfg.recategorisation_file:
        recategorised = apply_recategorisations(standards, load_recategorisations(cfg.recategorisation_file, standards))
    rules = select_rules(standards, cfg.enabled)
    result = StandardsResult(standards, rules, recategorised=recategorised)
    if cfg.triage_file:
        result.triage = load_triage(cfg.triage_file)
    root = project_root(config)
    rule_by_key = {r.key: r for r in rules}
    raw: list[Breach] = []
    seen: set[tuple] = set()

    for hit in _native_hits(model, config, rules):
        key = (hit.rule.key, relative_posix(hit.file, root), hit.line)
        if key in seen:
            continue
        seen.add(key)
        raw.append(_finding(hit.rule, root, hit.file, hit.line, hit.function, hit.text, hit.fingerprint))
        result.sources.setdefault(hit.rule.key, set()).add("native")

    selected_standards = [standards[s.standard] for s in cfg.enabled]
    if cfg.imports:
        result.sources["_imports"] = {tool for tool, _ in cfg.imports}
    for tool, path in cfg.imports:
        for rf in read_import(tool, path):
            rule = map_to_rule(rf, selected_standards)
            if rule is None or rule.key not in rule_by_key:
                result.unmapped[tool] = result.unmapped.get(tool, 0) + 1
                continue
            file = Path(rf.file) if Path(rf.file).is_absolute() else root / rf.file
            key = (rule.key, relative_posix(file, root), rf.line)
            if key in seen:
                continue
            seen.add(key)
            text = ""
            try:
                lines = file.read_text(encoding="utf-8", errors="replace").splitlines()
                text = lines[rf.line - 1] if 0 < rf.line <= len(lines) else ""
            except OSError:
                pass
            raw.append(_finding(rule, root, file, rf.line, _enclosing_function(model, file, rf.line), text))
            result.sources.setdefault(rule.key, set()).add("imported")

    result.deviations = load_deviations(cfg.deviations_file, standards) if cfg.deviations_file else []
    markers = None
    if result.deviations:
        files = {f.file: root / f.file for f in raw}
        markers = scan_markers(files)
    outcome = apply_deviations(raw, result.deviations, standards, today, markers)
    result.findings = outcome.active
    result.deviated = outcome.deviated
    result.problems = outcome.problems
    # A broken deviation (expired, or covering a mandatory rule) is itself a finding, so it fails the gate
    for dev, message in outcome.problems:
        result.findings.append(Breach(
            f"deviation:{dev.id}", "rule", relative_posix(cfg.deviations_file, root), f"deviation:{dev.id}",
            1.0, 0.0, line=None, function=None, category="required", description=f"Deviation {dev.id}: {message}",
        ))
    model._standards_result = result
    return result
