"""
HTML report generator for fwlens.

Produces a self-contained tabbed HTML report using the Jinja2 template in templates/report.html.j2.
No external assets required -- everything is inlined into the output file.

Tabs:
  Overview     -- summary stats, exceedance probability bars
  Functions    -- sortable/filterable function metrics table
  Modules      -- coupling, instability, zone classification
  Architecture -- layer violation list + stable abstractions scatter plot
  Distributions-- per-metric distribution bars with percentile markers
  Dead Code    -- zero-caller function candidates
  ISR Risk     -- ISR latency risk scores
  Coupling/Cohesion -- high coupling, low cohesion, and both combined
"""

from __future__ import annotations

import base64
import json
import zlib
from pathlib import Path

from jinja2 import BaseLoader, Environment

from fwlens.config import FwLensConfig
from fwlens.model.project import ProjectModel
from fwlens.output.diagrams import (
    generate_architecture_svg_inline,
    generate_rtos_object_graph_svg_inline,
    generate_state_machine_svg_inline,
)

def _load_template() -> str:
    """The report page (Jinja2), kept as package data so it can be linted, diffed and tested on its own."""
    return (Path(__file__).parent / "templates" / "report.html.j2").read_text(encoding="utf-8")


def _breach(value, threshold) -> bool:
    return value > threshold


def _build_distributions(model: ProjectModel, config) -> list[dict]:
    """Build per-metric distribution data for the Distributions tab."""
    from fwlens.stats.distributions import _exceedance_probability, _fit_lognormal

    t = config.thresholds
    fp_funcs = model.first_party_functions()
    if not fp_funcs:
        return []

    metrics = [
        ("cyclomatic_complexity", t.cyclomatic_complexity),
        ("cognitive_complexity",  t.cognitive_complexity),
        ("loc",                   t.function_loc),
        ("block_depth",           t.block_depth),
        ("halstead_effort",       t.halstead_effort),
        ("halstead_volume",       t.halstead_volume),
        ("return_path_count",     t.return_path_count),
        ("magic_number_density",  t.magic_number_density),
        ("fan_out",               t.fan_out),
    ]

    result = []
    for metric, threshold in metrics:
        values = [float(getattr(f, metric, 0)) for f in fp_funcs]
        if not values:
            continue
        fit = _fit_lognormal(values)
        exc = _exceedance_probability(float(threshold), fit)

        # Build percentile bars: p25, p50, p75, p90, p95, p99
        import numpy as np
        arr = sorted([v for v in values if v >= 0])
        if not arr:
            continue
        pcts = [25, 50, 75, 90, 95, 99]
        pct_vals = [float(np.percentile(arr, p)) for p in pcts]
        max_val = max(pct_vals[-1] * 1.1, float(threshold) * 1.1, 1.0)

        bars = []
        colours = ["#4f9cf9", "#4f9cf9", "#4f9cf9", "#e0b85c", "#e05c5c", "#e05c5c"]
        for pct, val, col in zip(pcts, pct_vals, colours):
            width_pct = min(100.0, 100.0 * val / max_val)
            threshold_pct = min(100.0, 100.0 * float(threshold) / max_val) \
                if threshold else None
            bars.append({
                "label":        f"p{pct}",
                "value":        f"{val:.1f}" if val < 100 else f"{val:.0f}",
                "width_pct":    round(width_pct, 1),
                "colour":       col,
                "threshold_pct": round(threshold_pct, 1) if threshold_pct else None,
            })

        result.append({
            "metric":          metric,
            "p50":             f"{fit.get('p50', 0):.1f}",
            "p90":             f"{fit.get('p90', 0):.1f}",
            "p99":             f"{fit.get('p99', 0):.1f}",
            "exceedance_pct":  round(exc * 100, 1),
            "bars":            bars,
        })
    return result


def _build_source_index(modules: list, max_file_loc: int =10000) -> dict:
    """Read source files and return {str(path): [lines]} for files within size limit."""
    index = {}
    for m in modules:
        path = m.path
        if not path.exists():
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        if len(lines) <= max_file_loc:
            index[str(path).replace("\\", "/")] = lines
    return index


def _compress_source_index(source_index: dict) -> tuple[str, int]:
    """
    Serialise + raw-deflate-compress the source index for embedding, then base64.
    Real C source compresses ~85-90% (measured against a 76-file/612KB sample), which
    matters a lot once a codebase reaches hundreds of files -- the embedded source text
    is by far the largest contributor to fwlens_report.html's file size. Uses raw
    deflate (zlib wbits=-15, no zlib/gzip header) paired with a small vendored pure-JS
    inflate implementation (tinyinflate, MIT licensed, ~3KB minified -- see
    fwlens/output/vendor/tinyinflate.LICENSE) rather than a full gzip/zlib-in-JS
    library, to keep the report a single self-contained file with minimal bundle
    weight added for the decompressor itself. Returns (base64_compressed, uncompressed_byte_length)
    -- tinyinflate needs the decompressed size upfront to pre-allocate its output buffer.
    """
    raw = json.dumps(source_index, ensure_ascii=False).encode("utf-8")
    compressor = zlib.compressobj(level=9, wbits=-15)
    compressed = compressor.compress(raw) + compressor.flush()
    return base64.b64encode(compressed).decode("ascii"), len(raw)


def _standards_context(model: ProjectModel, config: FwLensConfig) -> dict | None:
    """Guideline status for the Standards tab, or None when no standard is enabled or it cannot be run."""
    if not (getattr(config, "standards", None) and config.standards.enabled):
        return None
    from fwlens.standards import run_standards
    from fwlens.standards.matrix import DISCLAIMER, build_matrix, summarise
    try:
        result = run_standards(model, config)
    except Exception as e:      # a bad rule file is reported by `standards validate`; do not lose the report
        return {"error": str(e), "rows": [], "summary": {}, "disclaimer": DISCLAIMER, "problems": []}
    rows = build_matrix(result)
    return {"rows": rows, "summary": summarise(rows), "disclaimer": DISCLAIMER, "error": None,
            "problems": [{"id": d.id, "message": m} for d, m in result.problems],
            "names": {sid: f"{s.name} ({s.revision})" for sid, s in result.standards.items()}}


def _supply_chain_context(model: ProjectModel, config: FwLensConfig) -> dict | None:
    """Readable SBOM, CBOM and SARIF views, for each of those formats listed in output.formats (#97)."""
    wanted = set(config.output.formats) & {"sbom", "cbom", "sarif"}
    if not wanted:
        return None
    from fwlens.output import supply_chain as sc
    out: dict = {}

    def build(name, make):
        try:
            out[name] = make()
        except Exception as e:      # a failed export must not lose the report
            out[name] = {"error": f"{type(e).__name__}: {e}"}

    if "sbom" in wanted:
        from fwlens.sbom import build_sbom
        build("sbom", lambda: sc.sbom_view(build_sbom(config)))
    if "cbom" in wanted:
        from fwlens.cbom import build_cbom
        build("cbom", lambda: sc.cbom_view(build_cbom(config)))
    if "sarif" in wanted:
        from fwlens.output.sarif import generate_sarif_report
        build("sarif", lambda: sc.sarif_view(generate_sarif_report(model, config)))
    return out


def _history_rows(model: ProjectModel, config: FwLensConfig) -> list[dict]:
    """Stored runs (output.db_path) plus this run, newest last, for the Trend table. Empty without history."""
    from fwlens.baseline import compute_breaches
    from fwlens.history_db import recent_runs, summarise
    try:
        rows = recent_runs(config.output.db_path, limit=9)
    except Exception:   # a damaged or newer history file must not stop the report
        return []
    if not rows:
        return []
    current = summarise(model, compute_breaches(model, config))
    current.update(recorded_at="this run", label=None, commit_sha=None)
    current["delta_breaches"] = (current["total_breaches"] or 0) - (rows[-1]["total_breaches"] or 0)
    return rows + [current]


def generate_html_report(model: ProjectModel, config: FwLensConfig):
    t = config.thresholds
    fp_funcs  = model.first_party_functions()
    fp_modules = model.first_party_modules()

    # Threshold breach summary -- raw counts, same eight thresholds as the console
    # summary. Distinct from Exceedance %, which is a fitted-distribution estimate;
    # this is a plain count, useful as a sanity check against that estimate.
    _breach_defs = [
        ("Cyclomatic complexity", "cyclomatic_complexity", t.cyclomatic_complexity),
        ("Cognitive complexity", "cognitive_complexity", t.cognitive_complexity),
        ("Block depth", "block_depth", t.block_depth),
        ("Function LOC", "loc", t.function_loc),
        ("Parameter count", "parameter_count", t.parameter_count),
        ("Return paths", "return_path_count", t.return_path_count),
        ("Magic number density", "magic_number_density", t.magic_number_density),
        ("Fan-out", "fan_out", t.fan_out),
    ]
    _n_funcs = max(len(fp_funcs), 1)
    breach_rows = []
    for label, attr, threshold in _breach_defs:
        count = sum(1 for f in fp_funcs if getattr(f, attr) > threshold)
        breach_rows.append({
            "label": label, "threshold": threshold, "count": count,
            "pct": round(100 * count / _n_funcs, 1),
        })

    source_index = _build_source_index(fp_modules, max_file_loc=getattr(config, 'source_embed_loc_limit', 10000))
    source_index_compressed_b64, source_index_uncompressed_len = _compress_source_index(source_index)
    tinyinflate_js = (Path(__file__).parent / "vendor" / "tinyinflate.js").read_text(encoding="utf-8")

    # Function rows
    func_rows = []
    for f in sorted(fp_funcs, key=lambda x: x.structural_debt_index, reverse=True):
        func_rows.append({
            "name":                  f.name,
            "file_short":            f.file.name,
            "cyclomatic_complexity": f.cyclomatic_complexity,
            "cognitive_complexity":  f.cognitive_complexity,
            "loc":                   f.loc,
            "block_depth":           f.block_depth,
            "return_path_count":     f.return_path_count,
            "magic_number_density":  f.magic_number_density,
            "fan_out":               f.fan_out,
            "halstead_effort":       f.halstead_effort,
            "mi_woc":                f.mi_woc,
            "structural_debt_index": f.structural_debt_index,
            "cc_breach":    _breach(f.cyclomatic_complexity, t.cyclomatic_complexity),
            "cog_breach":   _breach(f.cognitive_complexity,  t.cognitive_complexity),
            "loc_breach":   _breach(f.loc,                   t.function_loc),
            "depth_breach": _breach(f.block_depth,           t.block_depth),
            "ret_breach":   _breach(f.return_path_count,     t.return_path_count),
            "magic_breach": _breach(f.magic_number_density,  t.magic_number_density),
            "fanout_breach":_breach(f.fan_out,               t.fan_out),
            "file_path":     str(f.file).replace("\\", "/"),
            "has_source":           str(f.file).replace("\\", "/") in source_index,
            "line":                 f.line,
            "magic_numbers":        sorted(set(f.magic_numbers)),
            "indirect_call_count":  f.indirect_call_count,
            "dispatch_table_reads": f.dispatch_table_reads,
        })

    # Module rows
    module_rows = []
    for m in sorted(fp_modules, key=lambda x: x.instability, reverse=True):
        module_rows.append({
            "name":                  m.path.name,
            "layer":                 m.layer,
            "loc":                   m.loc,
            "function_count":        m.function_count,
            "fan_in":                m.fan_in,
            "fan_out":               m.fan_out,
            "instability":           m.instability,
            "main_sequence_distance":m.main_sequence_distance,
            "avg_cc":                m.avg_cc,
            "avg_halstead_effort":   m.avg_halstead_effort,
            "avg_magic_density":     m.avg_magic_density,
            "internal_call_cohesion":m.internal_call_cohesion,
            "include_depth":         m.include_depth,
            "in_cycle":              m.in_cycle,
            "zone":                  getattr(m, "zone", "unknown"),
            "pain_score":            getattr(m, "pain_score", 0.0),
            "msd_breach":            m.main_sequence_distance > t.main_sequence_distance,
            "abstractness":          round(m.abstractness, 3),
            "file_path":             str(m.path).replace("\\", "/"),
            "has_source":            str(m.path).replace("\\", "/") in source_index,
        })

    # Architecture violation rows
    arch_rows = [
        {
            "source_module": v.source_module.name,
            "source_layer":  v.source_layer,
            "target_module": v.target_module.name,
            "target_layer":  v.target_layer,
            "violation_type":v.violation_type,
        }
        for v in model.arch_violations
    ]

    # Scatter data for stable abstractions plot
    scatter_data = [
        {
            "name":       m.path.name,
            "i":          round(m.instability, 3),
            "a":          round(m.abstractness, 3),
            "zone":       getattr(m, "zone", "unknown"),
            "msd":        round(m.main_sequence_distance, 3),
            "pain_score": round(getattr(m, "pain_score", 0.0), 3),
            "fan_in":     m.fan_in,
            "layer":      m.layer or "Unknown",
        }
        for m in fp_modules
    ]

    # Correlation heatmap data for the Distributions tab -- binned client-side
    # by drawDensityHeatmap(). Mirrors the (x, y) pairs plots.py already feeds
    # into its matplotlib hexbin PNGs (heatmap_effort_vs_cyclomatic.png etc.),
    # but those PNGs are never referenced by this report -- they're only
    # written to a sibling plots/ dir when "plots" is requested as an output
    # format. Rendering them natively here keeps the report self-contained.
    # Header include hygiene (fwlens.header_checks) -- display rows with short
    # filenames, matching every other table's file_short convention.
    def _short(p) -> str:
        return Path(p).name

    include_cycle_rows = [
        {"files": [_short(f) for f in c.files], "length": c.length}
        for c in model.include_cycles
    ]
    self_include_rows = [{"file": _short(s.file)} for s in model.self_includes]
    missing_guard_rows = [{"file": _short(g.file), "reason": g.reason} for g in model.missing_include_guards]
    deep_include_rows = [
        {"file": _short(d.file), "depth": d.depth, "chain": [_short(f) for f in d.chain]}
        for d in model.deep_include_chains
    ]
    unused_include_rows = [
        {"file": _short(u.file), "included": _short(u.included), "declared_name_count": u.declared_name_count}
        for u in model.unused_includes
    ]

    correlation_heatmap_data = {
        "cc_effort": [{"x": f.cyclomatic_complexity, "y": f.halstead_effort} for f in fp_funcs],
        "cc_loc":    [{"x": f.cyclomatic_complexity, "y": f.loc} for f in fp_funcs],
        "mi_volume": [{"x": f.mi_woc, "y": f.halstead_volume} for f in fp_funcs],
    }

    dead_rows = [
        {
            "name":                  f.name,
            "file_short":            f.file.name,
            "file_path":             str(f.file).replace("\\", "/"),
            "has_source":            str(f.file).replace("\\", "/") in source_index,
            "line":                  f.line,
            "loc":                   f.loc,
            "cyclomatic_complexity": f.cyclomatic_complexity,
        }
        for f in model.dead_candidates
    ]

    isr_rows = [
        {
            "isr_name":          r.isr_name,
            "file_short":        r.file.name,
            "file_path":         str(r.file).replace("\\", "/"),
            "has_source":        str(r.file).replace("\\", "/") in source_index,
            "line":              getattr(r, "line", 0),
            "own_cc":            r.own_cc,
            "transitive_cc_sum": r.transitive_cc_sum,
            "call_depth":        r.call_depth,
            "risk_score":        r.risk_score,
            "non_estimable":     r.non_estimable,
        }
        for r in model.isr_risks
    ]

    def _mod_row(m) -> dict:
        return {
            "name":                  m.path.name,
            "layer":                 m.layer,
            "fan_in":                m.fan_in,
            "fan_out":               m.fan_out,
            "instability":           m.instability,
            "internal_call_cohesion":m.internal_call_cohesion,
            "in_cycle":              m.in_cycle,
            "file_path":             str(m.path).replace("\\", "/"),
            "has_source":            str(m.path).replace("\\", "/") in source_index,
        }

    high_coupling_rows = [
        _mod_row(m) for m in sorted(fp_modules, key=lambda x: x.fan_out, reverse=True)
        if m.fan_out > t.fan_out
    ]
    low_cohesion_rows = [
        _mod_row(m) for m in sorted(fp_modules, key=lambda x: x.internal_call_cohesion)
        if m.internal_call_cohesion < t.cohesion_min
    ]
    high_coupling_low_cohesion_rows = [
        _mod_row(m) for m in sorted(fp_modules, key=lambda x: x.fan_out, reverse=True)
        if m.fan_out > t.fan_out and m.internal_call_cohesion < t.cohesion_min
    ]

    magic_rows = [
        {
            "name":                 f["name"],
            "file_short":           f["file_short"],
            "file_path":            f["file_path"],
            "has_source":           f["has_source"],
            "line":                 f["line"],
            "loc":                  f["loc"],
            "magic_number_density": f["magic_number_density"],
            "magic_numbers":        f["magic_numbers"],
        }
        for f in func_rows
        if f["magic_breach"]
    ]
    magic_rows.sort(key=lambda r: r["magic_number_density"], reverse=True)

    meta = {        "ewp":             model.ewp_path.name,
        "configuration":   model.configuration,
        "module_count":    len(fp_modules),
        "footprint":       getattr(model, "footprint", None),
        "function_count":  len(fp_funcs),
        "total_loc":       sum(f.loc for f in fp_funcs),
        "dead_count":      len(model.dead_candidates),
        "cc_breaches":     sum(1 for f in fp_funcs if f.cyclomatic_complexity > t.cyclomatic_complexity),
        "magic_breaches":  len(magic_rows),
        "cyclic_modules":  sum(1 for m in fp_modules if m.in_cycle),
        "arch_violations": len(model.arch_violations),
        "zone_pain":       sum(1 for m in fp_modules if getattr(m, "zone", "") == "pain"),
        "unknown_layers":  sum(1 for m in fp_modules if not m.layer or m.layer == "Unknown"),
        "group_dir_mismatches": len(model.group_dir_mismatches),
        "assert_coverage": round(100 * len([f for f in fp_funcs if f.assert_count > 0]) / max(len(fp_funcs), 1), 1),
        "stack_over50":    len([f for f in fp_funcs if f.stack_depth_estimate is not None and f.stack_depth_estimate > 50]),
        "include_cycle_count": sum(c.length for c in model.include_cycles) + len(model.self_includes),
        "missing_guard_count": len(model.missing_include_guards),
        "unused_include_count": len(model.unused_includes),
    }

    group_dir_rows = [
        {
            "file":          m.file,
            "file_name":     m.file.name,
            "iar_group":     m.iar_group,
            "actual_dir":    m.actual_dir,
            "layer":         m.layer,
            "suggested_dir": str(m.suggested_dir),
        }
        for m in model.group_dir_mismatches
    ]

    dispatch_table_rows = [
        {
            "var_name":       t.var_name,
            "file_short":     t.file.name,
            "file_path":      str(t.file).replace("\\", "/"),
            "has_source":     str(t.file).replace("\\", "/") in source_index,
            "line":           t.line,
            "stored_fns":     t.stored_fns,
            "dispatchers":    t.dispatchers,
            "registered_into": t.registered_into,
        }
        for t in model.dispatch_tables
    ]

    # -----------------------------------------------------------------------
    # Critical functions: high fan_in × SDI, not dead
    # -----------------------------------------------------------------------
    critical_rows = []
    for f in fp_funcs:
        if f.is_dead_candidate or f.fan_in == 0:
            continue
        score = f.fan_in * f.structural_debt_index
        if score > 0:
            critical_rows.append({
                "name":                  f.name,
                "file_short":            f.file.name,
                "file_path":             str(f.file).replace("\\", "/"),
                "has_source":            str(f.file).replace("\\", "/") in source_index,
                "line":                  f.line,
                "fan_in":                f.fan_in,
                "fan_out":               f.fan_out,
                "cyclomatic_complexity": f.cyclomatic_complexity,
                "structural_debt_index": round(f.structural_debt_index, 3),
                "halstead_bugs":         round(f.halstead_bugs, 2),
                "assert_count":          f.assert_count,
                "risk_score":            round(score, 1),
            })
    critical_rows.sort(key=lambda r: r["risk_score"], reverse=True)
    critical_rows = critical_rows[:25]

    # -----------------------------------------------------------------------
    # Assert coverage gaps: high CC + high fan_in + zero asserts
    # -----------------------------------------------------------------------
    assert_gap_rows = []
    for f in fp_funcs:
        if f.assert_count > 0 or f.fan_in < 3 or f.cyclomatic_complexity < 8:
            continue
        risk = f.fan_in * f.cyclomatic_complexity
        assert_gap_rows.append({
            "name":                  f.name,
            "file_short":            f.file.name,
            "file_path":             str(f.file).replace("\\", "/"),
            "has_source":            str(f.file).replace("\\", "/") in source_index,
            "line":                  f.line,
            "fan_in":                f.fan_in,
            "cyclomatic_complexity": f.cyclomatic_complexity,
            "halstead_effort":       round(f.halstead_effort),
            "risk":                  risk,
        })
    assert_gap_rows.sort(key=lambda r: r["risk"], reverse=True)
    assert_gap_rows = assert_gap_rows[:20]

    assert_total    = len([f for f in fp_funcs if f.assert_count > 0])
    assert_coverage = round(100 * assert_total / max(len(fp_funcs), 1), 1)

    # -----------------------------------------------------------------------
    # Stack depth analysis
    # -----------------------------------------------------------------------
    stack_rows = []
    for f in fp_funcs:
        if f.stack_depth_estimate is None:
            continue
        stack_rows.append({
            "name":             f.name,
            "file_short":       f.file.name,
            "file_path":        str(f.file).replace("\\", "/"),
            "has_source":       str(f.file).replace("\\", "/") in source_index,
            "line":             f.line,
            "depth":            f.stack_depth_estimate,
            "estimable":        f.stack_estimable,
            "is_isr":           f.is_isr,
            "fan_in":           f.fan_in,
            "cyclomatic_complexity": f.cyclomatic_complexity,
        })
    stack_rows.sort(key=lambda r: r["depth"], reverse=True)

    all_depths  = [r["depth"] for r in stack_rows]
    stack_stats = {
        "max":    max(all_depths) if all_depths else 0,
        "mean":   round(sum(all_depths) / max(len(all_depths), 1), 1),
        "median": sorted(all_depths)[len(all_depths) // 2] if all_depths else 0,
        "over50": len([d for d in all_depths if d > 50]),
        "over20": len([d for d in all_depths if d > 20]),
        "total":  len(all_depths),
    }
    stack_rows = stack_rows[:30]

    # -----------------------------------------------------------------------
    # Global coupling: functions reading/writing the most globals
    # -----------------------------------------------------------------------
    global_coupling_rows = []
    for f in fp_funcs:
        reads  = len(f.global_reads)
        writes = len(f.global_writes)
        total  = reads + writes
        if total < 4:
            continue
        global_coupling_rows.append({
            "name":       f.name,
            "file_short": f.file.name,
            "file_path":  str(f.file).replace("\\", "/"),
            "has_source": str(f.file).replace("\\", "/") in source_index,
            "line":       f.line,
            "reads":      reads,
            "writes":     writes,
            "total":      total,
            "fan_out":    f.fan_out,
            "fan_in":     f.fan_in,
            "top_reads":  f.global_reads[:6],
            "top_writes": f.global_writes[:6],
        })
    global_coupling_rows.sort(key=lambda r: r["total"], reverse=True)
    global_coupling_rows = global_coupling_rows[:25]

    # -----------------------------------------------------------------------
    # Dead code by layer
    # -----------------------------------------------------------------------
    _dead_by_layer: dict = {}
    for f in model.dead_candidates:
        # find the module this function belongs to
        fn_path = str(f.file).replace("\\", "/")
        layer = "Unknown"
        for m in fp_modules:
            if str(m.path).replace("\\", "/") == fn_path:
                layer = m.layer or "Unknown"
                break
        _dead_by_layer[layer] = _dead_by_layer.get(layer, 0) + 1
    dead_by_layer = sorted(_dead_by_layer.items(), key=lambda x: x[1], reverse=True)

    # --- Estimation / reliability / defect analysis -----------------------------------
    reliability = None
    if model.reliability_growth:
        r = model.reliability_growth
        reliability = {
            "fix_commit_count":    r.fix_commit_count,
            "fitted_total_defects": r.fitted_total_defects,
            "fitted_discovery_rate": r.fitted_discovery_rate,
            "cumulative_to_date":  r.cumulative_to_date,
            "estimated_remaining": r.estimated_remaining,
            "trend":               r.trend,
            "r_squared":           r.r_squared,
            "days_span":           r.days_span,
        }

    effort = None
    if model.effort_estimate:
        e = model.effort_estimate
        effort = {
            "mode":                  e.mode,
            "kloc":                  e.kloc,
            "effort_person_months":  e.effort_person_months,
            "schedule_months":       e.schedule_months,
            "average_staffing":      e.average_staffing,
        }

    cost_benefit = None
    if model.cost_benefit:
        cb = model.cost_benefit
        cost_benefit = {
            "estimated_remaining_defects": cb.estimated_remaining_defects,
            "cost_per_defect_static_usd":  cb.cost_per_defect_static_usd,
            "cost_per_defect_field_usd":   cb.cost_per_defect_field_usd,
            "cost_if_static_usd":          cb.cost_if_static_usd,
            "cost_if_field_usd":           cb.cost_if_field_usd,
            "potential_savings_usd":       cb.potential_savings_usd,
        }

    defect_correlations = [
        {"label": c.label, "spearman_r": c.spearman_r, "p_value": c.p_value, "n": c.n}
        for c in model.defect_correlations
    ]

    # Information flow complexity (Henry & Kafura) -- needs nonzero fan-in AND fan-out
    information_flow_rows = [
        {
            "name":       f.name,
            "file_short": f.file.name,
            "file_path":  str(f.file).replace("\\", "/"),
            "has_source": str(f.file).replace("\\", "/") in source_index,
            "line":       f.line,
            "fan_in":     f.fan_in,
            "fan_out":    f.fan_out,
            "loc":        f.loc,
            "if4":        f.information_flow_complexity,
        }
        for f in sorted(fp_funcs, key=lambda x: x.information_flow_complexity, reverse=True)
        if f.information_flow_complexity > 0
    ][:30]

    meta["reliability_trend"] = reliability["trend"] if reliability else "no_data"
    meta["defect_correlation_count"] = len(defect_correlations)
    meta["cost_benefit_savings"] = cost_benefit["potential_savings_usd"] if cost_benefit else 0

    # --- Hotspots (churn x structural debt) --------------------------------------------
    hotspot_rows = []
    if model.git_available:
        commit_by_path = {m.path: m.commit_count for m in fp_modules}
        for f in model.hotspots:
            if f.hotspot_score <= 0:
                continue
            hotspot_rows.append({
                "name":          f.name,
                "file_short":    f.file.name,
                "file_path":     str(f.file).replace("\\", "/"),
                "has_source":    str(f.file).replace("\\", "/") in source_index,
                "line":          f.line,
                "commit_count":  commit_by_path.get(f.file, 0),
                "sdi":           round(f.structural_debt_index, 3),
                "hotspot_score": round(f.hotspot_score, 3),
                "vague_name":    f.vague_name_flag,
            })
        hotspot_rows = hotspot_rows[:30]

    # --- Bug-fix-weighted hotspots (churn restricted to fix-flavoured commits) ---------
    bugfix_hotspot_rows = []
    if model.git_available:
        bugfix_by_path = {m.path: m.bugfix_commit_count for m in fp_modules}
        for f in model.bugfix_hotspots:
            if f.bugfix_hotspot_score <= 0:
                continue
            bugfix_hotspot_rows.append({
                "name":          f.name,
                "file_short":    f.file.name,
                "file_path":     str(f.file).replace("\\", "/"),
                "has_source":    str(f.file).replace("\\", "/") in source_index,
                "line":          f.line,
                "bugfix_commit_count": bugfix_by_path.get(f.file, 0),
                "sdi":           round(f.structural_debt_index, 3),
                "bugfix_hotspot_score": round(f.bugfix_hotspot_score, 3),
            })
        bugfix_hotspot_rows = bugfix_hotspot_rows[:30]

    # --- Code ownership / knowledge map --------------------------------------------------
    ownership_rows = [
        {
            "file":                m.path.name,
            "commit_count":        m.commit_count,
            "main_author":         m.main_author,
            "main_author_share":   round(m.main_author_share, 3),
            "distinct_author_count": m.distinct_author_count,
            "ownership_risk_score": round(m.ownership_risk_score, 3),
        }
        for m in model.ownership_risks if m.ownership_risk_score > 0
    ][:30]

    # --- Complexity trend in top hotspots -------------------------------------------------
    complexity_trend_rows = [
        {
            "file":  t.file.name,
            "trend": t.trend,
            "slope": round(t.slope, 4),
            "r_squared": round(t.r_squared, 3),
            "point_count": len(t.points),
        }
        for t in model.complexity_trends if t.trend != "insufficient_data"
    ]

    # --- Composite risk ranking ---------------------------------------------------------
    composite_risk_rows = [
        {
            "name":       f.name,
            "file_short": f.file.name,
            "file_path":  str(f.file).replace("\\", "/"),
            "has_source": str(f.file).replace("\\", "/") in source_index,
            "line":       f.line,
            "score":      round(f.composite_risk_score, 3),
        }
        for f in model.composite_risk if f.composite_risk_score > 0
    ][:30]

    # --- Clone / near-duplicate function pairs ------------------------------------------
    clone_rows = [
        {
            "function_a":  p.function_a,
            "file_a":      p.file_a.name,
            "file_a_path": str(p.file_a).replace("\\", "/"),
            "has_source_a": str(p.file_a).replace("\\", "/") in source_index,
            "line_a":      p.line_a,
            "function_b":  p.function_b,
            "file_b":      p.file_b.name,
            "file_b_path": str(p.file_b).replace("\\", "/"),
            "has_source_b": str(p.file_b).replace("\\", "/") in source_index,
            "line_b":      p.line_b,
            "similarity":  p.similarity,
            "is_dead_a":   p.is_dead_a,
            "is_dead_b":   p.is_dead_b,
        }
        for p in model.clone_pairs
    ][:50]

    # --- Change coupling -----------------------------------------------------------------
    coupling_pair_rows = [
        {
            "file_a":     p.file_a.name,
            "file_b":     p.file_b.name,
            "co_changes": p.co_changes,
            "coupling":   p.coupling,
            "cross_layer": p.cross_layer,
            "surprising":  p.surprising,
        }
        for p in model.change_coupling
    ][:30]

    # --- Architecture-level change coupling (rolled up from change_coupling by layer) ---
    layer_coupling_rows = [
        {
            "layer_a": lp.layer_a, "layer_b": lp.layer_b,
            "file_pair_count": lp.file_pair_count, "total_co_changes": lp.total_co_changes,
            "avg_coupling": lp.avg_coupling, "surprising_pair_count": lp.surprising_pair_count,
        }
        for lp in model.layer_coupling
    ][:30]

    # --- Churn heatmap, rendered as an HTML/CSS grid (not an image -- keeps the report
    #     a single self-contained file with no sibling PNGs required) -------------------
    churn_heatmap_grid = None
    if model.churn_heatmap:
        totals: dict = {}
        for cell in model.churn_heatmap:
            totals[cell.file] = totals.get(cell.file, 0) + cell.commit_count
        top_files = sorted(totals, key=lambda f: totals[f], reverse=True)[:config.output.top_n]
        bin_labels = sorted({c.bin_label for c in model.churn_heatmap})
        by_key = {(c.file, c.bin_label): c.commit_count for c in model.churn_heatmap}
        max_count = max((v for v in by_key.values()), default=1)
        grid_rows = []
        for f in top_files:
            cells = []
            for b in bin_labels:
                count = by_key.get((f, b), 0)
                intensity = round(count / max_count, 2) if max_count else 0
                cells.append({"count": count, "intensity": intensity})
            grid_rows.append({"file": f.name, "cells": cells})
        churn_heatmap_grid = {"bin_labels": bin_labels, "rows": grid_rows}

    # --- Change-coupling matrix heatmap, rendered as an HTML/CSS grid (same
    #     pattern as churn_heatmap_grid above) -- top-N files by total coupling,
    #     symmetric matrix, intensity 0-1. Previously only reachable as
    #     change_coupling_heatmap.png in plots.py, which this report never
    #     linked to. -------------------------------------------------------
    coupling_heatmap_grid = None
    if model.change_coupling:
        totals: dict = {}
        for p in model.change_coupling:
            totals[p.file_a] = totals.get(p.file_a, 0.0) + p.coupling
            totals[p.file_b] = totals.get(p.file_b, 0.0) + p.coupling
        top_files = sorted(totals, key=lambda f: totals[f], reverse=True)[:config.output.top_n]
        top_set = set(top_files)
        by_pair = {}
        for p in model.change_coupling:
            if p.file_a in top_set and p.file_b in top_set:
                by_pair[(p.file_a, p.file_b)] = p.coupling
                by_pair[(p.file_b, p.file_a)] = p.coupling
        grid_rows = []
        for fa in top_files:
            cells = []
            for fb in top_files:
                coupling = 0.0 if fa == fb else by_pair.get((fa, fb), 0.0)
                cells.append({"intensity": round(coupling, 2), "pct": round(coupling * 100)})
            grid_rows.append({"file": fa.name, "cells": cells})
        coupling_heatmap_grid = {
            "files": [f.name for f in top_files],
            "rows": grid_rows,
        }

    # --- Commit activity calendar (whole codebase, not per file) -- rendered as an
    #     HTML/CSS grid for the same reason as churn_heatmap_grid: keeps the report a
    #     single self-contained file with no sibling PNGs required. Capped to the most
    #     recent 53 weeks (~1 year, GitHub contribution-graph convention); full daily
    #     data is in commit_activity.csv regardless of this cap. ------------------------
    commit_activity_grid = None
    if model.commit_activity:
        from datetime import date as _date
        from datetime import timedelta as _timedelta
        counts = {_date.fromisoformat(c.date): c.commit_count for c in model.commit_activity}
        last_day = max(counts)
        first_day = last_day - _timedelta(weeks=52)
        first_day -= _timedelta(days=first_day.weekday())  # snap back to a Monday
        n_weeks = (last_day - first_day).days // 7 + 1
        max_count = max(counts.values(), default=1)

        week_cols = []
        for w in range(n_weeks):
            week_start = first_day + _timedelta(weeks=w)
            days = []
            for wd in range(7):
                d = week_start + _timedelta(days=wd)
                count = counts.get(d, 0) if first_day <= d <= last_day else None
                intensity = round(count / max_count, 2) if count else 0
                days.append({"date": d.isoformat(), "count": count, "intensity": intensity})
            week_cols.append(days)
        month_labels = []
        seen_months = set()
        for w in range(n_weeks):
            d = first_day + _timedelta(weeks=w)
            key = (d.year, d.month)
            month_labels.append(d.strftime("%b") if key not in seen_months else "")
            seen_months.add(key)
        commit_activity_grid = {
            "week_cols": week_cols, "month_labels": month_labels,
            "first_day": first_day.isoformat(), "last_day": last_day.isoformat(),
            "total_commits": sum(counts.values()),
        }

    # --- Tech debt: TODO/FIXME/HACK/XXX markers -----------------------------------------
    todo_rows = [
        {
            "tag":        t.tag,
            "file_short": t.file.name,
            "file_path":  str(t.file).replace("\\", "/"),
            "has_source": str(t.file).replace("\\", "/") in source_index,
            "line":       t.line,
            "text":       t.text,
        }
        for t in model.todo_markers
    ][:100]

    # --- Tech debt: commented-out code ---------------------------------------------------
    commented_code_rows = [
        {
            "file_short": b.file.name,
            "file_path":  str(b.file).replace("\\", "/"),
            "has_source": str(b.file).replace("\\", "/") in source_index,
            "start_line": b.start_line,
            "end_line":   b.end_line,
            "line_count": b.line_count,
        }
        for b in model.commented_code_blocks
    ][:50]

    # --- Tech debt: preprocessor complexity (module-level) -------------------------------
    preprocessor_rows = [
        {
            "file_short": m.path.name,
            "depth":      m.max_ifdef_depth,
            "directives": m.ifdef_directive_count,
            "flags":      m.distinct_feature_flags,
        }
        for m in sorted(
            [m for m in fp_modules if m.max_ifdef_depth > 0],
            key=lambda m: (m.max_ifdef_depth, m.distinct_feature_flags), reverse=True,
        )
    ][:30]

    # --- ISR / main-loop shared-variable race risk ---------------------------------------
    race_risk_rows = []
    for g in model.globals:
        if not g.volatile_risk:
            continue
        isr_side = sorted(set(g.isr_readers) | set(g.isr_writers))
        main_side = sorted((set(g.readers) | set(g.writers)) - set(isr_side))
        race_risk_rows.append({
            "name":       g.name,
            "file_short": g.file.name,
            "isr_side":   isr_side,
            "main_side":  main_side,
        })

    meta["hotspot_count"] = len(hotspot_rows)
    meta["bugfix_hotspot_count"] = len(bugfix_hotspot_rows)
    meta["ownership_risk_count"] = len(ownership_rows)
    meta["complexity_trend_count"] = len(complexity_trend_rows)
    meta["clone_pair_count"] = len(clone_rows)
    meta["change_coupling_count"] = len(coupling_pair_rows)
    meta["layer_coupling_count"] = len(layer_coupling_rows)
    meta["todo_count"] = len(model.todo_markers)
    meta["commented_code_count"] = len(model.commented_code_blocks)
    meta["race_risk_count"] = len(race_risk_rows)

    architecture_svg = generate_architecture_svg_inline(model, config, source_index=source_index)

    # --- RTOS tasks & synchronisation -----------------------------------------------------
    rtos_task_rows = [
        {
            "name": t.name,
            "tcb_var": t.tcb_var,
            "priority_value": t.priority_value,
            "priority_expr": t.priority_expr,
            "entry_function": t.entry_function,
            "has_source": str(t.file).replace("\\", "/") in source_index,
            "file_path": str(t.file).replace("\\", "/"),
            "line": t.line,
            "stack_expr": t.stack_expr,
            "stack_size_value": t.stack_size_value,
            "stack_size_expr": t.stack_size_expr,
        }
        for t in sorted(
            model.rtos_tasks,
            key=lambda x: (x.priority_value is None, -(x.priority_value if x.priority_value is not None else 0)),
        )
    ]
    rtos_object_rows = [
        {"var_name": o.var_name, "kind": o.kind, "file_short": o.file.name,
         "unused": o.var_name in {u.var_name for u in model.rtos_unused_objects}}
        for o in model.rtos_sync_objects
    ]
    rtos_collision_rows = [
        {"priority_value": c.priority_value, "task_names": c.task_names}
        for c in model.rtos_priority_collisions
    ]
    rtos_inversion_rows = [
        {"object_var": r.object_var,
         "pairs": list(zip(r.task_names, [p if p is not None else "?" for p in r.priorities]))}
        for r in model.rtos_inversion_risks
    ]
    rtos_object_graph_svg = generate_rtos_object_graph_svg_inline(model) if model.rtos_kind != "none" else None

    meta["rtos_kind"] = model.rtos_kind
    meta["output_top_n"] = config.output.top_n
    meta["history_warnings"] = list(getattr(model, "history_warnings", []) or [])

    # Parse diagnostics -- across all modules (not just first-party), so an
    # SDK/third-party header issue dragging down a first-party file's parse is
    # visible too.
    diag_modules = [m for m in model.modules if m.parse_diagnostics]
    meta["diag_module_count"] = len(diag_modules)
    meta["diag_fatal_count"] = sum(1 for m in diag_modules for d in m.parse_diagnostics if d["severity"] == "fatal")
    meta["diag_error_count"] = sum(1 for m in diag_modules for d in m.parse_diagnostics if d["severity"] == "error")
    meta["diag_warning_count"] = sum(1 for m in diag_modules for d in m.parse_diagnostics if d["severity"] == "warning")

    # Overview pane: errors/fatals only, capped -- warnings are numerous and rarely
    # block trusting a file's results the way an error does, so they'd otherwise
    # dominate the first thing anyone sees. Full detail (including every warning)
    # lives in the dedicated Parse Diagnostics tab below, not hidden, just not
    # first thing on the page.
    error_diag_modules = [
        m for m in diag_modules
        if any(d["severity"] in ("fatal", "error") for d in m.parse_diagnostics)
    ]
    meta["diag_error_module_count"] = len(error_diag_modules)
    meta["history"] = _history_rows(model, config)
    meta["standards"] = _standards_context(model, config)
    meta["supply_chain"] = _supply_chain_context(model, config)
    diagnostic_rows = []
    for m in sorted(error_diag_modules, key=lambda m: -len(m.parse_diagnostics))[:20]:
        worst = next(d for d in m.parse_diagnostics if d["severity"] in ("fatal", "error"))
        diagnostic_rows.append({
            "file_short": m.path.name,
            "severity": worst["severity"],
            "line": worst["line"],
            "message": worst["message"][:120],
            "extra_count": len(m.parse_diagnostics) - 1,
        })

    # Parse Diagnostics tab: every file with any diagnostic (fatal/error/warning),
    # uncapped, one row per file with its full diagnostic list attached for
    # click-to-expand -- same interaction pattern as the Deepest Include Chains
    # table. Worst-severity files first (fatal > error > warning), then by count.
    _SEV_RANK = {"fatal": 0, "error": 1, "warning": 2}

    def _module_sev_rank(m):
        return min(_SEV_RANK.get(d["severity"], 3) for d in m.parse_diagnostics)

    all_diagnostic_rows = []
    for m in sorted(diag_modules, key=lambda m: (_module_sev_rank(m), -len(m.parse_diagnostics))):
        worst = m.parse_diagnostics[0]
        all_diagnostic_rows.append({
            "file_short": m.path.name,
            "file_path": str(m.path).replace("\\", "/"),
            "has_source": str(m.path).replace("\\", "/") in source_index,
            "severity": worst["severity"],
            "line": worst["line"],
            "message": worst["message"][:160],
            "extra_count": len(m.parse_diagnostics) - 1,
            "all": [
                {"severity": d["severity"], "line": d["line"], "message": d["message"][:200]}
                for d in m.parse_diagnostics
            ],
        })
    meta["rtos_task_count"] = len(rtos_task_rows)
    meta["rtos_collision_count"] = len(rtos_collision_rows)
    meta["rtos_inversion_count"] = len(rtos_inversion_rows)
    meta["rtos_unused_count"] = len(model.rtos_unused_objects)

    # --- State machines --------------------------------------------------------------------
    state_machine_entries = []
    for sm in model.state_machines[:20]:
        state_machine_entries.append({
            "function_name": sm.function_name,
            "file_short": sm.file.name,
            "file_path": str(sm.file).replace("\\", "/"),
            "has_source": str(sm.file).replace("\\", "/") in source_index,
            "line": sm.line,
            "state_var": sm.state_var,
            "state_count": len(sm.states),
            "transition_count": len(sm.transitions),
            "svg": generate_state_machine_svg_inline(sm),
        })
    meta["state_machine_count"] = len(model.state_machines)
    meta["state_machine_shown"] = len(state_machine_entries)

    env = Environment(loader=BaseLoader())
    tmpl = env.from_string(_load_template())
    html = tmpl.render(
        meta=meta,
        functions=func_rows,
        modules=module_rows,
        arch_violations=arch_rows,
        scatter_data=scatter_data,
        distributions=_build_distributions(model, config),
        breach_rows=breach_rows,
        dead_funcs=dead_rows,
        isr_risks=isr_rows,
        exceedances=model.exceedance_probabilities,
        high_coupling=high_coupling_rows,
        low_cohesion=low_cohesion_rows,
        high_coupling_low_cohesion=high_coupling_low_cohesion_rows,
        thresholds=t,
        group_dir_mismatches=group_dir_rows,
        magic_funcs=magic_rows,
        dispatch_tables=dispatch_table_rows,
        critical_funcs=critical_rows,
        assert_gap_funcs=assert_gap_rows,
        assert_coverage=assert_coverage,
        assert_total=assert_total,
        stack_rows=stack_rows,
        stack_stats=stack_stats,
        global_coupling=global_coupling_rows,
        dead_by_layer=dead_by_layer,
        reliability=reliability,
        effort=effort,
        cost_benefit=cost_benefit,
        defect_correlations=defect_correlations,
        information_flow_rows=information_flow_rows,
        hotspot_rows=hotspot_rows,
        bugfix_hotspot_rows=bugfix_hotspot_rows,
        ownership_rows=ownership_rows,
        complexity_trend_rows=complexity_trend_rows,
        composite_risk_rows=composite_risk_rows,
        clone_rows=clone_rows,
        coupling_pair_rows=coupling_pair_rows,
        layer_coupling_rows=layer_coupling_rows,
        churn_heatmap_grid=churn_heatmap_grid,
        coupling_heatmap_grid=coupling_heatmap_grid,
        correlation_heatmap_data=correlation_heatmap_data,
        include_cycles=include_cycle_rows,
        self_includes=self_include_rows,
        missing_include_guards=missing_guard_rows,
        deep_include_chains=deep_include_rows,
        unused_includes=unused_include_rows,
        commit_activity_grid=commit_activity_grid,
        todo_rows=todo_rows,
        commented_code_rows=commented_code_rows,
        preprocessor_rows=preprocessor_rows,
        race_risk_rows=race_risk_rows,
        architecture_svg=architecture_svg,
        rtos_task_rows=rtos_task_rows,
        rtos_object_rows=rtos_object_rows,
        rtos_collision_rows=rtos_collision_rows,
        rtos_inversion_rows=rtos_inversion_rows,
        rtos_object_graph_svg=rtos_object_graph_svg,
        state_machine_entries=state_machine_entries,
        diagnostic_rows=diagnostic_rows,
        source_index_compressed_b64=source_index_compressed_b64,
        source_index_uncompressed_len=source_index_uncompressed_len,
        tinyinflate_js=tinyinflate_js,
    )

    reports_dir = config.output.reports_dir
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_path = reports_dir / "fwlens_report.html"
    report_path.write_text(html, encoding="utf-8")
    return report_path