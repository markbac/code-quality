"""
Statistical engine for fwlens.

Fits log-normal distributions to metric populations, computes exceedance
probabilities, produces distributional fingerprints, and computes
structural debt index (percentile-rank composite).
"""

from __future__ import annotations

import math
from typing import Optional

import numpy as np
from scipy import stats

from fwlens.config import FwLensConfig, ThresholdConfig
from fwlens.model.project import FunctionMetrics, ModuleMetrics, ProjectModel


_FUNCTION_METRICS = [
    "cyclomatic_complexity",
    "cognitive_complexity",
    "halstead_volume",
    "halstead_difficulty",
    "halstead_effort",
    "halstead_bugs",
    "mi_woc",
    "block_depth",
    "loc",
    "param_mutation_rate",
    "return_path_count",
    "magic_number_density",
]

_STRUCTURAL_DEBT_WEIGHTS = {
    "cyclomatic_complexity": 0.30,
    "halstead_difficulty":   0.25,
    "block_depth":           0.20,
    "fan_out":               0.15,
    "mi_woc":                0.10,  # inverted below
}


def _fit_lognormal(values: list[float]) -> dict:
    """
    Fit a log-normal distribution to a list of values.
    Returns shape parameters and percentiles.
    """
    arr = np.array([v for v in values if v > 0], dtype=float)
    if len(arr) < 3:
        return {
            "mu": 0.0, "sigma": 0.0, "skew": 0.0,
            "p50": 0.0, "p90": 0.0, "p95": 0.0, "p99": 0.0,
            "n": len(arr), "fit_valid": False,
        }

    log_arr = np.log(arr)
    mu = float(np.mean(log_arr))
    sigma = float(np.std(log_arr))
    skew = float(stats.skew(arr))

    return {
        "mu": mu,
        "sigma": sigma,
        "skew": skew,
        "p50": float(np.percentile(arr, 50)),
        "p90": float(np.percentile(arr, 90)),
        "p95": float(np.percentile(arr, 95)),
        "p99": float(np.percentile(arr, 99)),
        "n": len(arr),
        "fit_valid": sigma > 0,
    }


def _exceedance_probability(threshold: float, fit: dict) -> float:
    """
    Compute P(X > threshold) using fitted log-normal parameters.
    Returns 0 if fit is not valid.
    """
    if not fit.get("fit_valid") or fit["sigma"] <= 0 or threshold <= 0:
        return 0.0
    mu, sigma = fit["mu"], fit["sigma"]
    z = (math.log(threshold) - mu) / sigma
    return float(1.0 - stats.norm.cdf(z))


def _percentile_ranks(values: list[float]) -> list[float]:
    """
    Compute percentile rank (0-1) for each value in the list.
    """
    arr = np.array(values, dtype=float)
    n = len(arr)
    if n == 0:
        return []
    ranks = stats.rankdata(arr, method="average")
    return list(ranks / n)


def compute_structural_debt_index(funcs: list[FunctionMetrics]) -> None:
    """
    Compute structural_debt_index for each function.
    Uses percentile ranks within the supplied population.
    """
    if not funcs:
        return

    metrics_data = {
        "cyclomatic_complexity": [f.cyclomatic_complexity for f in funcs],
        "halstead_difficulty":   [f.halstead_difficulty for f in funcs],
        "block_depth":           [f.block_depth for f in funcs],
        "fan_out":               [f.fan_out for f in funcs],
        "mi_woc":                [f.mi_woc for f in funcs],
    }

    percentile_map: dict[str, list[float]] = {
        metric: _percentile_ranks(values)
        for metric, values in metrics_data.items()
    }

    for i, func in enumerate(funcs):
        debt = 0.0
        for metric, weight in _STRUCTURAL_DEBT_WEIGHTS.items():
            pct = percentile_map[metric][i]
            if metric == "mi_woc":
                pct = 1.0 - pct  # invert: low MI = high debt
            debt += pct * weight
        func.structural_debt_index = round(debt, 4)


def build_codebase_fingerprint(
    funcs: list[FunctionMetrics],
    thresholds: ThresholdConfig,
) -> dict:
    """
    Build a distributional fingerprint for the codebase (or a module).
    Returns per-metric fit parameters and exceedance probabilities.
    """
    fingerprint: dict = {}
    exceedances: dict = {}

    threshold_map = {
        "cyclomatic_complexity": thresholds.cyclomatic_complexity,
        "cognitive_complexity":  thresholds.cognitive_complexity,
        "halstead_volume":       thresholds.halstead_volume,
        "halstead_effort":       thresholds.halstead_effort,
        "block_depth":           thresholds.block_depth,
        "loc":                   thresholds.function_loc,
        "return_path_count":     thresholds.return_path_count,
        "magic_number_density":  thresholds.magic_number_density,
        "fan_out":               thresholds.fan_out,
    }

    for metric in _FUNCTION_METRICS:
        values = [getattr(f, metric, 0) for f in funcs]
        fit = _fit_lognormal([float(v) for v in values])
        fingerprint[metric] = fit

        if metric in threshold_map:
            exceedances[metric] = _exceedance_probability(
                float(threshold_map[metric]), fit
            )

    return {"fits": fingerprint, "exceedances": exceedances}


def build_module_fingerprints(model: ProjectModel, thresholds: ThresholdConfig) -> None:
    """Build per-module fingerprints from module function populations."""
    for m in model.modules:
        if m.functions:
            m.fingerprint = build_codebase_fingerprint(m.functions, thresholds)


def run_stats_engine(model: ProjectModel, config: FwLensConfig) -> None:
    """
    Run the full statistical engine:
    1. Structural debt index on first-party functions
    2. Codebase-level fingerprint
    3. Per-module fingerprints
    4. Exceedance probabilities stored on model
    """
    fp_funcs = model.first_party_functions()

    compute_structural_debt_index(fp_funcs)

    fingerprint = build_codebase_fingerprint(fp_funcs, config.thresholds)
    model.codebase_fingerprint = fingerprint["fits"]
    model.exceedance_probabilities = fingerprint["exceedances"]

    build_module_fingerprints(model, config.thresholds)
