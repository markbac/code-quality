"""
CSV and JSON exporters for fwlens.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from fwlens.config import FwLensConfig
from fwlens.model.project import FunctionMetrics, ModuleMetrics, ProjectModel


_FUNCTION_CSV_FIELDS = [
    "name", "file", "line", "loc",
    "cyclomatic_complexity", "cognitive_complexity", "block_depth",
    "parameter_count", "return_path_count",
    "magic_number_count", "magic_number_density",
    "assert_count", "assert_density",
    "fan_in", "fan_out",
    "halstead_vocabulary", "halstead_length", "halstead_volume",
    "halstead_difficulty", "halstead_effort", "halstead_bugs",
    "mi_woc", "mi_cw", "mi_comment_dependency",
    "complexity_efficiency", "vocabulary_concentration",
    "param_mutation_rate", "structural_debt_index",
    "hotspot_score", "composite_risk_score", "information_flow_complexity",
    "bugfix_hotspot_score", "vague_name_flag",
    "stack_depth_estimate", "stack_estimable",
    "is_isr", "is_entry_point", "is_dead_candidate",
]

_MODULE_CSV_FIELDS = [
    "path", "boundary_class", "layer", "zone",
    "loc", "function_count", "type_decl_count",
    "fan_in", "fan_out", "instability",
    "abstractness", "main_sequence_distance",
    "avg_cc", "max_cc",
    "avg_halstead_effort", "avg_mi_woc",
    "internal_call_cohesion",
    "header_source_coherence", "include_depth",
    "pragma_density", "in_cycle", "scc_id",
    "file_total_lines", "file_sloc", "file_comment_lines",
    "file_blank_lines", "file_comment_ratio",
    "commit_count", "bugfix_commit_count",
    "main_author", "main_author_share", "distinct_author_count",
    "ownership_fragmentation", "ownership_risk_score",
    "max_ifdef_depth", "ifdef_directive_count", "distinct_feature_flags",
]

_ARCH_VIOLATION_CSV_FIELDS = [
    "source_module", "source_layer",
    "target_module", "target_layer",
    "violation_type", "dependency_kind",
]


def _func_row(f: FunctionMetrics) -> dict:
    row = {}
    for field in _FUNCTION_CSV_FIELDS:
        v = getattr(f, field, "")
        if isinstance(v, Path):
            v = str(v).replace("\\", "/")
        row[field] = v
    return row


def _module_row(m: ModuleMetrics) -> dict:
    row = {}
    for field in _MODULE_CSV_FIELDS:
        v = getattr(m, field, "")
        if isinstance(v, Path):
            v = str(v).replace("\\", "/")
        elif hasattr(v, "value"):
            v = v.value
        row[field] = v
    return row


def export_csv(model: ProjectModel, config: FwLensConfig) -> None:
    exports_dir = config.output.exports_dir
    exports_dir.mkdir(parents=True, exist_ok=True)

    # Functions CSV
    func_path = exports_dir / "functions.csv"
    fp_funcs = model.first_party_functions()
    with open(func_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=_FUNCTION_CSV_FIELDS)
        writer.writeheader()
        for func in sorted(fp_funcs, key=lambda x: x.structural_debt_index, reverse=True):
            writer.writerow(_func_row(func))

    # Modules CSV
    mod_path = exports_dir / "modules.csv"
    fp_modules = model.first_party_modules()
    with open(mod_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=_MODULE_CSV_FIELDS)
        writer.writeheader()
        for mod in sorted(fp_modules, key=lambda x: x.instability, reverse=True):
            writer.writerow(_module_row(mod))

    # Dead code CSV
    dead_path = exports_dir / "dead_code_candidates.csv"
    with open(dead_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=_FUNCTION_CSV_FIELDS)
        writer.writeheader()
        for func in model.dead_candidates:
            writer.writerow(_func_row(func))

    # Architecture violations CSV
    arch_path = exports_dir / "arch_violations.csv"
    with open(arch_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=_ARCH_VIOLATION_CSV_FIELDS)
        writer.writeheader()
        for v in model.arch_violations:
            writer.writerow({
                "source_module":  v.source_module.name,
                "source_layer":   v.source_layer,
                "target_module":  v.target_module.name,
                "target_layer":   v.target_layer,
                "violation_type": v.violation_type,
                "dependency_kind":v.dependency_kind,
            })
    isr_path = exports_dir / "isr_risk.csv"
    with open(isr_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "isr_name", "file", "own_cc", "transitive_cc_sum",
            "call_depth", "risk_score", "non_estimable",
        ])
        writer.writeheader()
        for r in model.isr_risks:
            writer.writerow({
                "isr_name": r.isr_name,
                "file": str(r.file).replace("\\", "/"),
                "own_cc": r.own_cc,
                "transitive_cc_sum": r.transitive_cc_sum,
                "call_depth": r.call_depth,
                "risk_score": round(r.risk_score, 2),
                "non_estimable": r.non_estimable,
            })

    # Worst-case stack per entry point
    stack_path = exports_dir / "entry_point_stack_risk.csv"
    with open(stack_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "function_name", "file", "line", "is_isr",
            "stack_depth_estimate", "stack_estimable",
        ])
        writer.writeheader()
        for r in model.entry_point_stack_risks:
            writer.writerow({
                "function_name": r.function_name,
                "file": str(r.file).replace("\\", "/"),
                "line": r.line,
                "is_isr": r.is_isr,
                "stack_depth_estimate": r.stack_depth_estimate,
                "stack_estimable": r.stack_estimable,
            })

    # ISR / main-loop shared-variable access (all globals, not just flagged risks --
    # volatile_risk column lets you filter either way)
    globals_path = exports_dir / "global_access.csv"
    with open(globals_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "name", "file", "is_volatile", "volatile_risk",
            "readers", "writers", "isr_readers", "isr_writers",
        ])
        writer.writeheader()
        for g in model.globals:
            writer.writerow({
                "name": g.name,
                "file": str(g.file).replace("\\", "/"),
                "is_volatile": g.is_volatile,
                "volatile_risk": g.volatile_risk,
                "readers": ";".join(g.readers),
                "writers": ";".join(g.writers),
                "isr_readers": ";".join(g.isr_readers),
                "isr_writers": ";".join(g.isr_writers),
            })

    # Hotspots (churn x structural debt) -- only meaningful if git_available
    hotspots_path = exports_dir / "hotspots.csv"
    with open(hotspots_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "name", "file", "commit_count", "structural_debt_index", "hotspot_score",
        ])
        writer.writeheader()
        if model.git_available:
            commit_by_path = {m.path: m.commit_count for m in fp_modules}
            for func in model.hotspots:
                writer.writerow({
                    "name": func.name,
                    "file": str(func.file).replace("\\", "/"),
                    "commit_count": commit_by_path.get(func.file, 0),
                    "structural_debt_index": round(func.structural_debt_index, 4),
                    "hotspot_score": round(func.hotspot_score, 4),
                })

    # Composite risk ranking
    risk_path = exports_dir / "composite_risk.csv"
    with open(risk_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["name", "file", "line", "composite_risk_score"])
        writer.writeheader()
        for func in model.composite_risk:
            writer.writerow({
                "name": func.name,
                "file": str(func.file).replace("\\", "/"),
                "line": func.line,
                "composite_risk_score": round(func.composite_risk_score, 4),
            })

    # TODO/FIXME/HACK markers
    todo_path = exports_dir / "todo_markers.csv"
    with open(todo_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["tag", "file", "line", "text"])
        writer.writeheader()
        for t in model.todo_markers:
            writer.writerow({
                "tag": t.tag, "file": str(t.file).replace("\\", "/"),
                "line": t.line, "text": t.text,
            })

    # Commented-out code blocks
    commented_path = exports_dir / "commented_code.csv"
    with open(commented_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["file", "start_line", "end_line", "line_count"])
        writer.writeheader()
        for b in model.commented_code_blocks:
            writer.writerow({
                "file": str(b.file).replace("\\", "/"),
                "start_line": b.start_line, "end_line": b.end_line, "line_count": b.line_count,
            })

    # Near-duplicate function pairs
    clones_path = exports_dir / "clones.csv"
    with open(clones_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "function_a", "file_a", "line_a", "function_b", "file_b", "line_b",
            "similarity", "token_count_a", "token_count_b", "is_dead_a", "is_dead_b",
        ])
        writer.writeheader()
        for p in model.clone_pairs:
            writer.writerow({
                "function_a": p.function_a, "file_a": str(p.file_a).replace("\\", "/"), "line_a": p.line_a,
                "function_b": p.function_b, "file_b": str(p.file_b).replace("\\", "/"), "line_b": p.line_b,
                "similarity": p.similarity,
                "token_count_a": p.token_count_a, "token_count_b": p.token_count_b,
                "is_dead_a": p.is_dead_a, "is_dead_b": p.is_dead_b,
            })

    # Change coupling (files that co-change in the same commit)
    coupling_path = exports_dir / "change_coupling.csv"
    with open(coupling_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "file_a", "file_b", "co_changes", "changes_a", "changes_b", "coupling",
            "layer_a", "layer_b", "cross_layer", "surprising",
        ])
        writer.writeheader()
        for p in model.change_coupling:
            writer.writerow({
                "file_a": str(p.file_a).replace("\\", "/"), "file_b": str(p.file_b).replace("\\", "/"),
                "co_changes": p.co_changes, "changes_a": p.changes_a, "changes_b": p.changes_b,
                "coupling": p.coupling,
                "layer_a": p.layer_a, "layer_b": p.layer_b,
                "cross_layer": p.cross_layer, "surprising": p.surprising,
            })

    # Change coupling rolled up to the architecture-layer level
    layer_coupling_path = exports_dir / "layer_coupling.csv"
    with open(layer_coupling_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "layer_a", "layer_b", "file_pair_count", "total_co_changes",
            "avg_coupling", "surprising_pair_count",
        ])
        writer.writeheader()
        for lp in model.layer_coupling:
            writer.writerow({
                "layer_a": lp.layer_a, "layer_b": lp.layer_b,
                "file_pair_count": lp.file_pair_count, "total_co_changes": lp.total_co_changes,
                "avg_coupling": lp.avg_coupling, "surprising_pair_count": lp.surprising_pair_count,
            })

    # Bug-fix-weighted hotspots (churn restricted to fix-flavoured commits)
    bugfix_hotspots_path = exports_dir / "bugfix_hotspots.csv"
    with open(bugfix_hotspots_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "name", "file", "bugfix_commit_count", "structural_debt_index", "bugfix_hotspot_score",
        ])
        writer.writeheader()
        if model.git_available:
            bugfix_by_path = {m.path: m.bugfix_commit_count for m in fp_modules}
            for func in model.bugfix_hotspots:
                writer.writerow({
                    "name": func.name,
                    "file": str(func.file).replace("\\", "/"),
                    "bugfix_commit_count": bugfix_by_path.get(func.file, 0),
                    "structural_debt_index": round(func.structural_debt_index, 4),
                    "bugfix_hotspot_score": round(func.bugfix_hotspot_score, 4),
                })

    # Code ownership / knowledge map -- first-party files with commit history
    ownership_path = exports_dir / "ownership.csv"
    with open(ownership_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "file", "commit_count", "main_author", "main_author_share",
            "distinct_author_count", "ownership_fragmentation", "ownership_risk_score",
        ])
        writer.writeheader()
        for m in model.ownership_risks:
            writer.writerow({
                "file": str(m.path).replace("\\", "/"), "commit_count": m.commit_count,
                "main_author": m.main_author, "main_author_share": m.main_author_share,
                "distinct_author_count": m.distinct_author_count,
                "ownership_fragmentation": m.ownership_fragmentation,
                "ownership_risk_score": m.ownership_risk_score,
            })

    # Complexity trend over time for the top hotspot files
    trend_path = exports_dir / "complexity_trends.csv"
    with open(trend_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "file", "date", "complexity_proxy", "trend", "slope", "r_squared",
        ])
        writer.writeheader()
        for t in model.complexity_trends:
            for pt in t.points:
                writer.writerow({
                    "file": str(t.file).replace("\\", "/"),
                    "date": pt.date.isoformat(), "complexity_proxy": pt.complexity_proxy,
                    "trend": t.trend, "slope": t.slope, "r_squared": t.r_squared,
                })

    # Churn heatmap raw data (file x time-bin commit counts)
    churn_heatmap_path = exports_dir / "churn_heatmap.csv"
    with open(churn_heatmap_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["file", "bin_label", "commit_count"])
        writer.writeheader()
        for cell in sorted(model.churn_heatmap, key=lambda c: (str(c.file), c.bin_label)):
            writer.writerow({
                "file": str(cell.file).replace("\\", "/"),
                "bin_label": cell.bin_label,
                "commit_count": cell.commit_count,
            })

    # Commit activity by calendar day (whole codebase, not per file)
    commit_activity_path = exports_dir / "commit_activity.csv"
    with open(commit_activity_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["date", "commit_count"])
        writer.writeheader()
        for cell in sorted(model.commit_activity, key=lambda c: c.date):
            writer.writerow({"date": cell.date, "commit_count": cell.commit_count})

    # COCOMO effort estimate + reliability growth (single-row summaries)
    summary_path = exports_dir / "estimation_summary.csv"
    with open(summary_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["metric", "value"])
        if model.effort_estimate:
            e = model.effort_estimate
            writer.writerow(["cocomo_mode", e.mode])
            writer.writerow(["cocomo_kloc", e.kloc])
            writer.writerow(["cocomo_effort_person_months", e.effort_person_months])
            writer.writerow(["cocomo_schedule_months", e.schedule_months])
            writer.writerow(["cocomo_average_staffing", e.average_staffing])
        if model.reliability_growth:
            r = model.reliability_growth
            writer.writerow(["reliability_fix_commit_count", r.fix_commit_count])
            writer.writerow(["reliability_fitted_total_defects", r.fitted_total_defects])
            writer.writerow(["reliability_fitted_discovery_rate", r.fitted_discovery_rate])
            writer.writerow(["reliability_cumulative_to_date", r.cumulative_to_date])
            writer.writerow(["reliability_estimated_remaining", r.estimated_remaining])
            writer.writerow(["reliability_trend", r.trend])
            writer.writerow(["reliability_r_squared", r.r_squared])
            writer.writerow(["reliability_days_span", r.days_span])
        if model.cost_benefit:
            cb = model.cost_benefit
            writer.writerow(["cost_benefit_estimated_remaining_defects", cb.estimated_remaining_defects])
            writer.writerow(["cost_benefit_cost_per_defect_static_usd", cb.cost_per_defect_static_usd])
            writer.writerow(["cost_benefit_cost_per_defect_field_usd", cb.cost_per_defect_field_usd])
            writer.writerow(["cost_benefit_cost_if_static_usd", cb.cost_if_static_usd])
            writer.writerow(["cost_benefit_cost_if_field_usd", cb.cost_if_field_usd])
            writer.writerow(["cost_benefit_potential_savings_usd", cb.potential_savings_usd])

    # Complexity-vs-defect correlation
    correlation_path = exports_dir / "defect_correlation.csv"
    with open(correlation_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["metric", "label", "spearman_r", "p_value", "n"])
        writer.writeheader()
        for c in model.defect_correlations:
            writer.writerow({
                "metric": c.metric, "label": c.label,
                "spearman_r": c.spearman_r, "p_value": c.p_value, "n": c.n,
            })

    # RTOS tasks
    rtos_tasks_path = exports_dir / "rtos_tasks.csv"
    with open(rtos_tasks_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "name", "tcb_var", "priority_expr", "priority_value", "entry_function",
            "stack_expr", "stack_size_expr", "stack_size_value", "creation_function", "file", "line",
        ])
        writer.writeheader()
        for t in model.rtos_tasks:
            writer.writerow({
                "name": t.name, "tcb_var": t.tcb_var, "priority_expr": t.priority_expr,
                "priority_value": t.priority_value, "entry_function": t.entry_function,
                "stack_expr": t.stack_expr,
                "stack_size_expr": t.stack_size_expr, "stack_size_value": t.stack_size_value,
                "creation_function": t.creation_function,
                "file": str(t.file).replace("\\", "/"), "line": t.line,
            })

    # RTOS sync objects
    rtos_objects_path = exports_dir / "rtos_sync_objects.csv"
    with open(rtos_objects_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["kind", "var_name", "creation_function", "file", "line", "unused"])
        writer.writeheader()
        unused_vars = {o.var_name for o in model.rtos_unused_objects}
        for o in model.rtos_sync_objects:
            writer.writerow({
                "kind": o.kind, "var_name": o.var_name, "creation_function": o.creation_function,
                "file": str(o.file).replace("\\", "/"), "line": o.line,
                "unused": o.var_name in unused_vars,
            })

    # RTOS object usage
    rtos_usage_path = exports_dir / "rtos_object_usage.csv"
    with open(rtos_usage_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "object_var", "task_name", "used_by_function", "access_kind", "file", "line",
        ])
        writer.writeheader()
        for u in model.rtos_object_usages:
            writer.writerow({
                "object_var": u.object_var, "task_name": u.task_name,
                "used_by_function": u.used_by_function, "access_kind": u.access_kind,
                "file": str(u.file).replace("\\", "/"), "line": u.line,
            })

    # State machines
    state_machines_path = exports_dir / "state_machines.csv"
    with open(state_machines_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "function", "file", "line", "state_var", "state_count", "transition_count",
            "case_count", "transitions",
        ])
        writer.writeheader()
        for sm in model.state_machines:
            writer.writerow({
                "function": sm.function_name, "file": str(sm.file).replace("\\", "/"), "line": sm.line,
                "state_var": sm.state_var, "state_count": len(sm.states),
                "transition_count": len(sm.transitions), "case_count": sm.case_count,
                "transitions": "; ".join(f"{a}->{b}" for a, b in sm.transitions),
            })

    # Parse diagnostics -- one row per diagnostic, across all modules (not just
    # first-party) so an SDK/third-party header issue that's dragging down a
    # first-party file's parse is also visible. `file` is the translation unit (the .c
    # file that was being parsed); `in_file` is where the diagnostic actually physically
    # occurred, which libclang tracks precisely and is frequently a header #included by
    # `file` rather than `file` itself -- `line` is relative to `in_file`, not `file`,
    # whenever the two differ. `in_file` is blank if libclang couldn't resolve a location
    # (rare, mostly fatal parse-abort cases).
    diagnostics_path = exports_dir / "parse_diagnostics.csv"
    with open(diagnostics_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["file", "boundary_class", "severity", "line", "in_file", "message"])
        writer.writeheader()
        for m in model.modules:
            for d in m.parse_diagnostics:
                writer.writerow({
                    "file": str(m.path).replace("\\", "/"),
                    "boundary_class": m.boundary_class.value if hasattr(m.boundary_class, "value") else str(m.boundary_class),
                    "severity": d["severity"], "line": d["line"],
                    "in_file": d.get("in_file", "").replace("\\", "/"),
                    "message": d["message"],
                })

    # Header include hygiene (fwlens.header_checks)
    include_cycles_path = exports_dir / "include_cycles.csv"
    with open(include_cycles_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["cycle_id", "file", "cycle_length"])
        writer.writeheader()
        for i, c in enumerate(model.include_cycles):
            for p in c.files:
                writer.writerow({"cycle_id": i, "file": str(p).replace("\\", "/"), "cycle_length": c.length})

    self_includes_path = exports_dir / "self_includes.csv"
    with open(self_includes_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["file"])
        writer.writeheader()
        for s in model.self_includes:
            writer.writerow({"file": str(s.file).replace("\\", "/")})

    missing_guards_path = exports_dir / "missing_include_guards.csv"
    with open(missing_guards_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["file", "reason"])
        writer.writeheader()
        for g in model.missing_include_guards:
            writer.writerow({"file": str(g.file).replace("\\", "/"), "reason": g.reason})

    deep_includes_path = exports_dir / "deep_include_chains.csv"
    with open(deep_includes_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["file", "include_depth"])
        writer.writeheader()
        for d in model.deep_include_chains:
            writer.writerow({"file": str(d.file).replace("\\", "/"), "include_depth": d.depth})

    unused_includes_path = exports_dir / "unused_includes.csv"
    with open(unused_includes_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["file", "included", "declared_name_count"])
        writer.writeheader()
        for u in model.unused_includes:
            writer.writerow({
                "file": str(u.file).replace("\\", "/"),
                "included": str(u.included).replace("\\", "/"),
                "declared_name_count": u.declared_name_count,
            })


def export_json(model: ProjectModel, config: FwLensConfig) -> None:
    exports_dir = config.output.exports_dir
    exports_dir.mkdir(parents=True, exist_ok=True)

    fp_funcs = model.first_party_functions()
    fp_modules = model.first_party_modules()
    commit_by_file = {str(m.path).replace("\\", "/"): m.commit_count for m in fp_modules}

    def _serialise(obj):
        if isinstance(obj, Path):
            return str(obj).replace("\\", "/")
        if hasattr(obj, "value"):
            return obj.value
        if hasattr(obj, "__dict__"):
            return {k: _serialise(v) for k, v in obj.__dict__.items()
                    if not k.startswith("_")}
        if isinstance(obj, (list, tuple)):
            return [_serialise(i) for i in obj]
        if isinstance(obj, dict):
            return {k: _serialise(v) for k, v in obj.items()}
        return obj

    # Fields on ModuleMetrics that are internal pipeline data -- not useful in JSON output
    _MODULE_INTERNAL = frozenset({
        "dispatch_tables", "dispatch_table_lines", "var_registrations",
        "file_scope_fn_refs", "functions", "includes",
    })

    def _serialise_module(m):
        return {k: _serialise(v) for k, v in m.__dict__.items()
                if not k.startswith("_") and k not in _MODULE_INTERNAL}

    payload = {
        "meta": {
            "ewp": str(model.ewp_path).replace("\\", "/"),
            "configuration": model.configuration,
            "module_count": len(fp_modules),
            "function_count": len(fp_funcs),
        },
        "codebase_fingerprint": _serialise(model.codebase_fingerprint),
        "exceedance_probabilities": model.exceedance_probabilities,
        "functions": [_serialise(f) for f in fp_funcs],
        "modules": [_serialise_module(m) for m in fp_modules],
        "arch_violations": [
            {
                "source_module":  str(v.source_module).replace("\\", "/"),
                "source_layer":   v.source_layer,
                "target_module":  str(v.target_module).replace("\\", "/"),
                "target_layer":   v.target_layer,
                "violation_type": v.violation_type,
                "dependency_kind":v.dependency_kind,
            }
            for v in model.arch_violations
        ],
        "dead_candidates": [_serialise(f) for f in model.dead_candidates],
        "isr_risks": [_serialise(r) for r in model.isr_risks],
        "entry_point_stack_risks": [_serialise(r) for r in model.entry_point_stack_risks],
        "globals": [_serialise(g) for g in model.globals],
        "hotspots": {
            "git_available": model.git_available,
            "functions": [
                {
                    "name": func.name,
                    "file": str(func.file).replace("\\", "/"),
                    "commit_count": commit_by_file.get(str(func.file).replace("\\", "/"), 0),
                    "structural_debt_index": round(func.structural_debt_index, 4),
                    "hotspot_score": round(func.hotspot_score, 4),
                }
                for func in model.hotspots
            ] if model.git_available else [],
        },
        "composite_risk": [
            {
                "name": func.name,
                "file": str(func.file).replace("\\", "/"),
                "line": func.line,
                "composite_risk_score": round(func.composite_risk_score, 4),
            }
            for func in model.composite_risk
        ],
        "todo_markers": [
            {"tag": t.tag, "file": str(t.file).replace("\\", "/"), "line": t.line, "text": t.text}
            for t in model.todo_markers
        ],
        "commented_code_blocks": [
            {
                "file": str(b.file).replace("\\", "/"),
                "start_line": b.start_line, "end_line": b.end_line, "line_count": b.line_count,
            }
            for b in model.commented_code_blocks
        ],
        "clone_pairs": [
            {
                "function_a": p.function_a, "file_a": str(p.file_a).replace("\\", "/"), "line_a": p.line_a,
                "function_b": p.function_b, "file_b": str(p.file_b).replace("\\", "/"), "line_b": p.line_b,
                "similarity": p.similarity,
                "token_count_a": p.token_count_a, "token_count_b": p.token_count_b,
                "is_dead_a": p.is_dead_a, "is_dead_b": p.is_dead_b,
            }
            for p in model.clone_pairs
        ],
        "change_coupling": [
            {
                "file_a": str(p.file_a).replace("\\", "/"), "file_b": str(p.file_b).replace("\\", "/"),
                "co_changes": p.co_changes, "changes_a": p.changes_a, "changes_b": p.changes_b,
                "coupling": p.coupling,
                "layer_a": p.layer_a, "layer_b": p.layer_b,
                "cross_layer": p.cross_layer, "surprising": p.surprising,
            }
            for p in model.change_coupling
        ],
        "layer_coupling": [_serialise(lp) for lp in model.layer_coupling],
        "commit_activity": [_serialise(c) for c in model.commit_activity],
        "diagnostic_clusters": [
            {
                "message_pattern": c.message_pattern,
                "line": c.line,
                "file_count": c.file_count,
                "sample_tu": str(c.sample_tu).replace("\\", "/"),
                "sample_file": str(c.sample_file).replace("\\", "/"),
                "sample_message": c.sample_message,
                "context": [{"line": ln, "text": text} for ln, text in c.context],
            }
            for c in model.diagnostic_clusters
        ],
        "bugfix_hotspots": {
            "git_available": model.git_available,
            "functions": [
                {
                    "name": func.name,
                    "file": str(func.file).replace("\\", "/"),
                    "bugfix_commit_count": next(
                        (m.bugfix_commit_count for m in fp_modules if m.path == func.file), 0),
                    "structural_debt_index": round(func.structural_debt_index, 4),
                    "bugfix_hotspot_score": round(func.bugfix_hotspot_score, 4),
                }
                for func in model.bugfix_hotspots
            ] if model.git_available else [],
        },
        "ownership_risks": [
            {
                "file": str(m.path).replace("\\", "/"), "commit_count": m.commit_count,
                "main_author": m.main_author, "main_author_share": m.main_author_share,
                "distinct_author_count": m.distinct_author_count,
                "ownership_fragmentation": m.ownership_fragmentation,
                "ownership_risk_score": m.ownership_risk_score,
            }
            for m in model.ownership_risks
        ],
        "complexity_trends": [
            {
                "file": str(t.file).replace("\\", "/"), "trend": t.trend,
                "slope": t.slope, "r_squared": t.r_squared,
                "points": [
                    {"date": pt.date.isoformat(), "complexity_proxy": pt.complexity_proxy}
                    for pt in t.points
                ],
            }
            for t in model.complexity_trends
        ],
        "effort_estimate": _serialise(model.effort_estimate) if model.effort_estimate else None,
        "reliability_growth": _serialise(model.reliability_growth) if model.reliability_growth else None,
        "defect_correlations": [_serialise(c) for c in model.defect_correlations],
        "cost_benefit": _serialise(model.cost_benefit) if model.cost_benefit else None,
        "rtos": {
            "kind": model.rtos_kind,
            "tasks": [_serialise(t) for t in model.rtos_tasks],
            "sync_objects": [_serialise(o) for o in model.rtos_sync_objects],
            "object_usages": [_serialise(u) for u in model.rtos_object_usages],
            "priority_collisions": [_serialise(c) for c in model.rtos_priority_collisions],
            "inversion_risks": [_serialise(r) for r in model.rtos_inversion_risks],
            "unused_objects": [_serialise(o) for o in model.rtos_unused_objects],
        },
        "state_machines": [
            {
                "function": sm.function_name, "file": str(sm.file).replace("\\", "/"), "line": sm.line,
                "state_var": sm.state_var, "states": sm.states,
                "transitions": [{"from": a, "to": b} for a, b in sm.transitions],
                "case_count": sm.case_count,
            }
            for sm in model.state_machines
        ],
        "dispatch_tables": [
            {
                "var_name":        t.var_name,
                "file":            str(t.file).replace("\\", "/"),
                "line":            t.line,
                "stored_fns":      t.stored_fns,
                "dispatchers":     t.dispatchers,
                "registered_into": t.registered_into,
            }
            for t in model.dispatch_tables
        ],
        "group_dir_mismatches": [
            {
                "file":          str(m.file).replace("\\", "/"),
                "iar_group":     m.iar_group,
                "actual_dir":    m.actual_dir,
                "layer":         m.layer,
                "suggested_dir": str(m.suggested_dir).replace("\\", "/"),
            }
            for m in model.group_dir_mismatches
        ],
        "include_hygiene": {
            "cycles": [
                {"files": [str(p).replace("\\", "/") for p in c.files], "length": c.length}
                for c in model.include_cycles
            ],
            "self_includes": [str(s.file).replace("\\", "/") for s in model.self_includes],
            "missing_guards": [
                {"file": str(g.file).replace("\\", "/"), "reason": g.reason}
                for g in model.missing_include_guards
            ],
            "deep_chains": [
                {"file": str(d.file).replace("\\", "/"), "depth": d.depth}
                for d in model.deep_include_chains
            ],
            "possibly_unused": [
                {
                    "file": str(u.file).replace("\\", "/"),
                    "included": str(u.included).replace("\\", "/"),
                    "declared_name_count": u.declared_name_count,
                }
                for u in model.unused_includes
            ],
        },
    }

    json_path = exports_dir / "fwlens_results.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, default=str)