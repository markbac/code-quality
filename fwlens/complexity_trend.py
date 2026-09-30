"""
Complexity trend over time in hotspots, for fwlens.

Tornhill, A. (2015). Your Code as a Crime Scene, Ch.6 ("Calculate Complexity Trends
from Your Code's Shape"). Two hotspot files can have identical current structural
debt and read very differently once you look at their history: one spiked once (a big
feature landed) and has been flat since, the other has climbed on every commit. Only
the second is an active, worsening problem -- the first may already be stabilising.

Text-based, same "no external tool" philosophy as fwlens.tech_debt and
fwlens.metrics.file_metrics: rather than re-parsing historical blobs with libclang
(expensive, and older revisions may not even be individually parseable in isolation),
this sums a lightweight decision-keyword count per file as a complexity proxy --
directional, not a substitute for the AST-derived cyclomatic_complexity used elsewhere
in fwlens for the current snapshot.
"""

from __future__ import annotations

import re

import numpy as np

from fwlens.config import FwLensConfig
from fwlens.git_history import _file_commit_snapshots, _find_git_root, _show_file_at
from fwlens.model.project import ComplexityTrend, ComplexityTrendPoint, ProjectModel

_MAX_HOTSPOT_FILES = 10   # top-N hotspot files to sample history for (bounds git-show cost)
_MAX_SAMPLES = 12         # commits sampled per file, evenly spaced across its history
_MIN_POINTS = 4           # fewer than this and a trend line is fitting noise
_FLAT_SLOPE_THRESHOLD = 0.01  # complexity-proxy units/day below which a fit counts as "stable"

_DECISION_RE = re.compile(
    r"\b(if|else\s+if|for|while|case|do)\b|(\&\&)|(\|\|)|(\?)"
)


def _complexity_proxy(source: str) -> int:
    """Decision-point count + 1, same shape as McCabe cyclomatic complexity but summed
    over a whole file rather than per function, and via regex rather than an AST."""
    return len(_DECISION_RE.findall(source)) + 1


def _fit_trend(points: list[ComplexityTrendPoint]) -> tuple[float, str, float]:
    t0 = points[0].date
    days = np.array([(p.date - t0).total_seconds() / 86400.0 for p in points])
    values = np.array([p.complexity_proxy for p in points], dtype=float)

    if days[-1] <= 0 or len(set(days.tolist())) < 2:
        return 0.0, "insufficient_data", 0.0

    slope, intercept = np.polyfit(days, values, 1)
    predicted = slope * days + intercept
    ss_res = float(np.sum((values - predicted) ** 2))
    ss_tot = float(np.sum((values - values.mean()) ** 2))
    r_squared = 1.0 - ss_res / ss_tot if ss_tot > 0 else 0.0

    if abs(slope) < _FLAT_SLOPE_THRESHOLD:
        trend = "stable"
    elif slope > 0:
        trend = "worsening"
    else:
        trend = "improving"
    return round(float(slope), 4), trend, round(r_squared, 3)


def compute_complexity_trends(model: ProjectModel, config: FwLensConfig) -> None:
    """
    Populate model.complexity_trends for the top _MAX_HOTSPOT_FILES distinct files (by
    hotspot_score) in model.hotspots. Must run after fwlens.git_history.compute_hotspots.
    Skips gracefully outside a git repo.
    """
    if not model.hotspots:
        return

    proj_root = config.project.source_dir or config.project.proj_dir
    git_root = _find_git_root(proj_root)
    if git_root is None:
        return

    seen: set = set()
    target_files = []
    for f in model.hotspots:
        if f.hotspot_score <= 0:
            break
        if f.file in seen:
            continue
        seen.add(f.file)
        target_files.append(f.file)
        if len(target_files) >= _MAX_HOTSPOT_FILES:
            break

    trends: list[ComplexityTrend] = []
    for file in target_files:
        snapshots = _file_commit_snapshots(git_root, file, config.git.since, _MAX_SAMPLES)
        if len(snapshots) < _MIN_POINTS:
            trends.append(ComplexityTrend(file=file))
            continue

        points: list[ComplexityTrendPoint] = []
        for dt, sha in snapshots:
            content = _show_file_at(git_root, file, sha)
            if content is None:
                continue
            points.append(ComplexityTrendPoint(date=dt, complexity_proxy=_complexity_proxy(content)))

        if len(points) < _MIN_POINTS:
            trends.append(ComplexityTrend(file=file, points=points))
            continue

        slope, trend, r_squared = _fit_trend(points)
        trends.append(ComplexityTrend(file=file, points=points, slope=slope,
                                       trend=trend, r_squared=r_squared))

    model.complexity_trends = trends
