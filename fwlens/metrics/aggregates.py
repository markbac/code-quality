"""
Module-level metric aggregation and layer assignment.

Runs after the AST walk and before the stats engine.
"""

from __future__ import annotations

import re
from pathlib import Path

from fwlens.config import FwLensConfig
from fwlens.metrics.file_metrics import compute_file_metrics
from fwlens.model.project import ModuleMetrics, ProjectModel


def assign_layers(model: ProjectModel, config: FwLensConfig) -> None:
    """
    Assign architecture layer to each module using layer rules from config.
    Rules are matched in order; first match wins.
    """
    for m in model.modules:
        m.layer = _infer_layer(m, config)


def _infer_layer(module: ModuleMetrics, config: FwLensConfig) -> str:
    path_parts_lower = [p.lower() for p in module.path.parts]
    groups_lower = [g.lower() for g in module.iar_groups]

    for rule in config.layers:
        # Path match
        for path_frag in rule.paths:
            if path_frag.lower() in path_parts_lower:
                return rule.name
        # Group match
        for group_name in rule.groups:
            if group_name.lower() in groups_lower:
                return rule.name

    return "Unknown"


def aggregate_module_metrics(model: ProjectModel) -> None:
    """
    Compute module-level aggregate metrics from function list.
    """
    for m in model.modules:
        funcs = m.functions
        if not funcs:
            m.avg_cc = 0.0
            m.max_cc = 0
            m.avg_halstead_effort = 0.0
            m.avg_mi_woc = 0.0
            continue

        m.function_count = len(funcs)
        m.loc = sum(f.loc for f in funcs)
        m.avg_cc = sum(f.cyclomatic_complexity for f in funcs) / len(funcs)
        m.max_cc = max(f.cyclomatic_complexity for f in funcs)
        m.avg_halstead_effort = sum(f.halstead_effort for f in funcs) / len(funcs)
        m.avg_mi_woc = sum(f.mi_woc for f in funcs) / len(funcs)
        m.avg_magic_density = sum(f.magic_number_density for f in funcs) / len(funcs)

        # Internal call cohesion:
        # fraction of calls that stay within this module
        module_func_names = {f.name for f in funcs}
        total_calls = sum(len(f.callees) for f in funcs)
        internal_calls = sum(
            sum(1 for c in f.callees if c in module_func_names)
            for f in funcs
        )
        m.internal_call_cohesion = internal_calls / max(total_calls, 1)

        # Header/source coherence:
        # Check if a corresponding .h exists and estimate coverage
        h_path = m.path.with_suffix(".h")
        if not h_path.exists():
            # Try Inc/ sibling directory
            inc_candidates = list(m.path.parent.parent.glob(f"Inc/{m.path.stem}.h"))
            h_path = inc_candidates[0] if inc_candidates else None

        if h_path and h_path.exists():
            declared = _count_declared_functions(h_path)
            defined = len(funcs)
            m.header_source_coherence = min(1.0, defined / max(declared, 1))
        else:
            m.header_source_coherence = 1.0  # no header = no mismatch to measure

        # Pragma density
        m.pragma_density = _compute_pragma_density(m.path)


def _count_declared_functions(header_path: Path) -> int:
    """Count function declarations in a header (very rough -- semicolon-terminated lines)."""
    try:
        text = header_path.read_text(encoding="utf-8", errors="replace")
        # Lines that look like function declarations: type name(...); pattern
        count = len(re.findall(
            r'^\s*(?:extern\s+)?[\w\s\*]+\w+\s*\([^)]*\)\s*;',
            text, re.MULTILINE
        ))
        return max(count, 1)
    except Exception:
        return 1


def _compute_pragma_density(path: Path) -> float:
    """Count IAR-specific pragmas per LOC."""
    iar_pragma_pattern = re.compile(
        r'(#pragma\s+(location|segment|data_alignment|required|optimize|diag_suppress)'
        r'|__ramfunc|__no_init|__root\s|__stackless)',
        re.IGNORECASE
    )
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        loc = max(len(lines), 1)
        pragma_count = sum(1 for line in lines if iar_pragma_pattern.search(line))
        return pragma_count / loc
    except Exception:
        return 0.0


def run_aggregation(model: ProjectModel, config: FwLensConfig) -> None:
    """Run all aggregation passes in order."""
    assign_layers(model, config)
    aggregate_module_metrics(model)
    compute_file_metrics(model)