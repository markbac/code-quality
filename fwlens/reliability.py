"""
Software reliability growth modeling for fwlens.

Goel, A.L., and Okumoto, K. (1979). "Time-Dependent Error-Detection Rate Model for
Software Reliability and Other Performance Measures." IEEE Transactions on
Reliability, R-28(3), 206-211.

Fits the Goel-Okumoto non-homogeneous Poisson process (NHPP) model,

    mu(t) = a * (1 - exp(-b*t))

to the cumulative count of "fix" commits over time (t in days since the first fix
commit), where `a` is the asymptotic expected total number of defects and `b` is
the defect discovery rate. This is a defect-*discovery* curve, not a defect count:
fewer commits than actual bugs (some bugs never get a dedicated fix commit; some fix
commits touch more than one bug) and fewer fix commits than total commits (most
commits aren't bug fixes) both apply, so treat `a` as an order-of-magnitude
discovery-trend indicator -- is discovery still climbing, flattening, or plateaued --
not a precise defect count.

"Fix" commits are identified by a commit-message keyword match (fix, bug, defect,
issue, resolve, patch, hotfix) -- a coarse heuristic, not a linked issue tracker.
Requires at least 8 matching commits to attempt a fit; fewer than that and any NHPP
fit is essentially fitting noise.
"""

from __future__ import annotations

import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional

import numpy as np
from scipy.optimize import curve_fit

from fwlens.config import FwLensConfig
from fwlens.git_history import _find_git_root
from fwlens.model.project import ProjectModel, ReliabilityGrowth

_MIN_FIX_COMMITS = 8


def fetch_fix_commits(git_root: Path, since: Optional[str], keywords: list[str]) -> list[dict]:
    """
    One `git log --name-only` pass -> list of {date, subject, files} for every commit
    whose message matches a fix-flavoured keyword. Shared by fwlens.reliability (dates
    only), fwlens.defect_analysis (subjects for root-cause categorisation, files for
    complexity-vs-defect correlation), and compute_bugfix_hotspots below (files for
    bug-fix-weighted hotspot scoring) so all draw from the same commit classification.
    `keywords` is config.git.fix_keywords -- override in config.yaml for non-English or
    non-default commit conventions.
    """
    pattern = "|".join(keywords)
    cmd = ["git", "-C", str(git_root), "log", "-i", "-E", "--grep", pattern,
           "--name-only", "--pretty=format:__FWLENS_COMMIT__%aI\x1f%s"]
    if since:
        cmd += ["--since", since]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        return []
    if result.returncode != 0:
        return []

    commits: list[dict] = []
    current: Optional[dict] = None

    for raw_line in result.stdout.splitlines():
        line = raw_line.rstrip("\n")
        if line.startswith("__FWLENS_COMMIT__"):
            if current is not None:
                commits.append(current)
            rest = line[len("__FWLENS_COMMIT__"):]
            date_str, _, subject = rest.partition("\x1f")
            try:
                dt: Optional[datetime] = datetime.fromisoformat(date_str)
            except ValueError:
                dt = None
            current = {"date": dt, "subject": subject, "files": []}
            continue

        stripped = line.strip()
        if not stripped or current is None:
            continue
        try:
            current["files"].append((git_root / stripped).resolve())
        except OSError:
            continue

    if current is not None:
        commits.append(current)
    return commits


def _fix_commit_dates(git_root: Path, since: Optional[str], keywords: list[str]) -> list[datetime]:
    dates = [c["date"] for c in fetch_fix_commits(git_root, since, keywords) if c["date"] is not None]
    dates.sort()
    return dates


def _percentile_rank(val: float, population: list[float]) -> float:
    if not population:
        return 0.0
    return sum(1 for v in population if v < val) / len(population)


def _goel_okumoto(t, a, b):
    return a * (1.0 - np.exp(-b * t))


def _fit_goel_okumoto(dates: list[datetime]) -> Optional[tuple[float, float, float]]:
    """Returns (a, b, r_squared), or None if the fit doesn't converge."""
    if len(dates) < _MIN_FIX_COMMITS:
        return None

    t0 = dates[0]
    days = np.array([(d - t0).total_seconds() / 86400.0 for d in dates])
    cumulative = np.arange(1, len(dates) + 1, dtype=float)

    n_final = cumulative[-1]
    a0 = n_final * 1.5
    b0 = 1.0 / max(days[-1], 1.0)

    try:
        popt, _ = curve_fit(
            _goel_okumoto, days, cumulative,
            p0=[a0, b0], bounds=([n_final, 1e-6], [n_final * 50, 10.0]),
            maxfev=5000,
        )
    except (RuntimeError, ValueError):
        return None

    a, b = popt
    predicted = _goel_okumoto(days, a, b)
    ss_res = float(np.sum((cumulative - predicted) ** 2))
    ss_tot = float(np.sum((cumulative - np.mean(cumulative)) ** 2))
    r_squared = 1.0 - ss_res / ss_tot if ss_tot > 0 else 0.0
    return float(a), float(b), r_squared


def _insufficient_data(fix_count: int, days_span: int = 0) -> ReliabilityGrowth:
    return ReliabilityGrowth(
        fix_commit_count=fix_count, fitted_total_defects=0.0,
        fitted_discovery_rate=0.0, cumulative_to_date=fix_count,
        estimated_remaining=0.0, trend="insufficient_data", r_squared=0.0,
        days_span=days_span,
    )


def compute_reliability_growth(model: ProjectModel, config: FwLensConfig) -> None:
    """Populate model.reliability_growth. Skips gracefully outside a git repo."""
    proj_root = config.project.source_dir or config.project.proj_dir
    git_root = _find_git_root(proj_root)
    if git_root is None:
        return

    dates = _fix_commit_dates(git_root, config.git.since, config.git.fix_keywords)
    if len(dates) < _MIN_FIX_COMMITS:
        model.reliability_growth = _insufficient_data(len(dates))
        return

    fit = _fit_goel_okumoto(dates)
    if fit is None:
        model.reliability_growth = _insufficient_data(len(dates), (dates[-1] - dates[0]).days)
        return

    a, b, r2 = fit
    cumulative_to_date = len(dates)
    ratio = cumulative_to_date / a if a > 0 else 1.0
    if ratio < 0.7:
        trend = "climbing"
    elif ratio < 0.9:
        trend = "flattening"
    else:
        trend = "plateaued"

    model.reliability_growth = ReliabilityGrowth(
        fix_commit_count=len(dates),
        fitted_total_defects=round(a, 1),
        fitted_discovery_rate=round(b, 4),
        cumulative_to_date=cumulative_to_date,
        estimated_remaining=round(max(a - cumulative_to_date, 0.0), 1),
        trend=trend,
        r_squared=round(r2, 3),
        days_span=(dates[-1] - dates[0]).days,
    )


def compute_bugfix_hotspots(model: ProjectModel, config: FwLensConfig) -> None:
    """
    Populate ModuleMetrics.bugfix_commit_count, FunctionMetrics.bugfix_hotspot_score,
    and model.bugfix_hotspots -- the same churn x structural-debt formula as
    fwlens.git_history.compute_hotspots, but churn is restricted to fix-flavoured
    commits (config.git.fix_keywords) rather than every commit. Code Maat, Tornhill's
    companion tool, makes the same distinction: raw churn answers "what changes a lot",
    fix-commit churn answers "what actually breaks a lot", and the two don't always
    agree -- a file that's rewritten often as new features land isn't necessarily the
    same file that keeps needing bug fixes.

    Must run after fwlens.git_history.compute_hotspots (for git_available / the git
    root check pattern) and fwlens.stats.distributions.run_stats_engine
    (structural_debt_index). Skips gracefully outside a git repo, same as compute_hotspots.
    """
    proj_root = config.project.source_dir or config.project.proj_dir
    git_root = _find_git_root(proj_root)
    if git_root is None:
        return

    commits = fetch_fix_commits(git_root, config.git.since, config.git.fix_keywords)

    fix_counts: dict[Path, int] = {}
    for c in commits:
        for f in set(c["files"]):
            fix_counts[f] = fix_counts.get(f, 0) + 1

    fp_modules = model.first_party_modules()
    for m in fp_modules:
        try:
            resolved = m.path.resolve()
        except OSError:
            resolved = m.path
        m.bugfix_commit_count = fix_counts.get(resolved, 0)

    fix_commit_counts = [m.bugfix_commit_count for m in fp_modules]
    module_by_path = {m.path: m for m in fp_modules}

    fp_funcs = model.first_party_functions()
    sdi_values = [f.structural_debt_index for f in fp_funcs]

    for f in fp_funcs:
        m = module_by_path.get(f.file)
        fix_churn = m.bugfix_commit_count if m else 0
        f.bugfix_hotspot_score = round(
            _percentile_rank(fix_churn, fix_commit_counts)
            * _percentile_rank(f.structural_debt_index, sdi_values),
            4,
        )

    model.bugfix_hotspots = sorted(fp_funcs, key=lambda f: f.bugfix_hotspot_score, reverse=True)
