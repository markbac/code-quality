"""
Git churn / hotspot analysis for fwlens.

Cross-references how often each first-party file has changed (commit count,
from git log) against its structural debt (fwlens.stats.distributions'
structural_debt_index). Files that are both frequently modified and
structurally risky are where defects cluster in practice -- more reliably
than complexity alone, per the "code as a crime scene" school of hotspot
analysis (churn x complexity).

This is git-log based, not clang-based: it works the same way whether the
project is parsed in .ewp mode or directory mode. If the project root isn't
a git repository, or `git` isn't on PATH, hotspot analysis is skipped with a
console note -- it's an enhancement, not a required part of the pipeline.

Must run after fwlens.stats.distributions.run_stats_engine, which is what
populates FunctionMetrics.structural_debt_index.
"""

from __future__ import annotations

import subprocess
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console

from fwlens.config import FwLensConfig
from fwlens.model.project import (
    ChurnHeatmapCell, CommitActivityCell, CouplingPair, LayerCouplingPair, ProjectModel,
)

console = Console()

# Change-coupling tuning
_MAX_FILES_PER_COMMIT = 20   # skip mega-commits (repo-wide reformat, branch merges) as noise
_MIN_CO_CHANGES = 3
_MIN_COUPLING = 0.3


def _find_git_root(start: Path) -> Optional[Path]:
    try:
        result = subprocess.run(
            ["git", "-C", str(start), "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return Path(result.stdout.strip())


def _commit_counts(git_root: Path, since: Optional[str]) -> dict[Path, int]:
    """One `git log --name-only` pass over the whole repo -> {absolute file path: commit count}."""
    cmd = ["git", "-C", str(git_root), "log", "--name-only", "--pretty=format:", "--no-renames"]
    if since:
        cmd += ["--since", since]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        return {}
    if result.returncode != 0:
        return {}

    counts: dict[Path, int] = {}
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            abs_path = (git_root / line).resolve()
        except OSError:
            continue
        counts[abs_path] = counts.get(abs_path, 0) + 1
    return counts


def _commits_file_lists(git_root: Path, since: Optional[str]) -> list[list[Path]]:
    """One `git log --name-only` pass -> list of per-commit absolute file path lists."""
    cmd = ["git", "-C", str(git_root), "log", "--name-only", "--pretty=format:__FWLENS_COMMIT__",
           "--no-renames"]
    if since:
        cmd += ["--since", since]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        return []
    if result.returncode != 0:
        return []

    commits: list[list[Path]] = []
    current: list[Path] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if line == "__FWLENS_COMMIT__":
            if current:
                commits.append(current)
            current = []
            continue
        if not line:
            continue
        try:
            current.append((git_root / line).resolve())
        except OSError:
            continue
    if current:
        commits.append(current)
    return commits


def _commits_with_dates(git_root: Path, since: Optional[str]) -> list[tuple[datetime, list[Path]]]:
    """One `git log --name-only` pass -> list of (commit author date, absolute file paths)."""
    cmd = ["git", "-C", str(git_root), "log", "--name-only",
           "--pretty=format:__FWLENS_COMMIT__%aI", "--no-renames"]
    if since:
        cmd += ["--since", since]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        return []
    if result.returncode != 0:
        return []

    commits: list[tuple[datetime, list[Path]]] = []
    current_date: Optional[datetime] = None
    current_files: list[Path] = []

    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if line.startswith("__FWLENS_COMMIT__"):
            if current_date is not None:
                commits.append((current_date, current_files))
            iso = line[len("__FWLENS_COMMIT__"):]
            try:
                current_date = datetime.fromisoformat(iso)
            except ValueError:
                current_date = None
            current_files = []
            continue
        if not line or current_date is None:
            continue
        try:
            current_files.append((git_root / line).resolve())
        except OSError:
            continue

    if current_date is not None:
        commits.append((current_date, current_files))
    return commits


def _commits_with_authors(git_root: Path, since: Optional[str]) -> list[tuple[str, list[Path]]]:
    """One `git log --name-only` pass -> list of (author name, absolute file paths).
    Shared plumbing for fwlens.ownership -- kept alongside the other _commits_with_*
    helpers rather than in ownership.py so all raw git-log parsing stays in one place."""
    cmd = ["git", "-C", str(git_root), "log", "--name-only",
           "--pretty=format:__FWLENS_COMMIT__%an", "--no-renames"]
    if since:
        cmd += ["--since", since]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        return []
    if result.returncode != 0:
        return []

    commits: list[tuple[str, list[Path]]] = []
    current_author: Optional[str] = None
    current_files: list[Path] = []

    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if line.startswith("__FWLENS_COMMIT__"):
            if current_author is not None:
                commits.append((current_author, current_files))
            current_author = line[len("__FWLENS_COMMIT__"):] or "(unknown)"
            current_files = []
            continue
        if not line or current_author is None:
            continue
        try:
            current_files.append((git_root / line).resolve())
        except OSError:
            continue

    if current_author is not None:
        commits.append((current_author, current_files))
    return commits


def _file_commit_snapshots(
    git_root: Path, abs_path: Path, since: Optional[str], max_samples: int,
) -> list[tuple[datetime, str]]:
    """
    Commits touching a single file, oldest-first, down-sampled to at most max_samples
    evenly-spaced points -- for fwlens.complexity_trend, where re-parsing every commit
    of a long-lived hotspot file would be prohibitively expensive. Returns
    (commit author date, commit hash) pairs; fetch content per hash with `git show
    <hash>:<path>`.
    """
    try:
        rel_path = abs_path.resolve().relative_to(git_root)
    except (OSError, ValueError):
        return []

    cmd = ["git", "-C", str(git_root), "log", "--no-renames", "--pretty=format:%aI\x1f%H"]
    if since:
        cmd += ["--since", since]
    cmd += ["--", str(rel_path)]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return []
    if result.returncode != 0:
        return []

    commits: list[tuple[datetime, str]] = []
    for line in result.stdout.splitlines():
        date_str, _, sha = line.strip().partition("\x1f")
        if not sha:
            continue
        try:
            dt = datetime.fromisoformat(date_str)
        except ValueError:
            continue
        commits.append((dt, sha))
    # git log returns newest-first; reverse before the stable sort below so that
    # commits sharing the same author-date second (common with scripted/rapid commits,
    # e.g. a squash-merge workflow) keep their true oldest-first order instead of the
    # reversed sub-order a stable sort over already-newest-first input would preserve.
    commits.reverse()
    commits.sort(key=lambda c: c[0])

    if len(commits) <= max_samples:
        return commits
    step = len(commits) / max_samples
    indices = sorted({int(i * step) for i in range(max_samples)} | {len(commits) - 1})
    return [commits[i] for i in indices]


def _show_file_at(git_root: Path, abs_path: Path, commit_hash: str) -> Optional[str]:
    """`git show <hash>:<path>` -> file content at that commit, or None on failure."""
    try:
        rel_path = abs_path.resolve().relative_to(git_root)
    except (OSError, ValueError):
        return None
    cmd = ["git", "-C", str(git_root), "show", f"{commit_hash}:{rel_path.as_posix()}"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30,
                                 encoding="utf-8", errors="replace")
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return result.stdout


def _bin_label(dt: datetime, bin_size: str) -> str:
    if bin_size == "week":
        iso = dt.isocalendar()
        return f"{iso[0]}-W{iso[1]:02d}"
    return dt.strftime("%Y-%m")


def compute_churn_heatmap(model: ProjectModel, config: FwLensConfig) -> None:
    """
    Populate model.churn_heatmap: commit count per first-party file per time bin
    (month or week, per config.git.heatmap_bin). Shows *when* a file was hot, not
    just that it currently is -- a file with heavy churn two years ago and none
    since reads very differently from one under active rework right now, but both
    would look identical in the plain aggregate commit_count hotspot score.
    """
    proj_root = config.project.source_dir or config.project.proj_dir
    git_root = _find_git_root(proj_root)
    if git_root is None:
        return

    commits = _commits_with_dates(git_root, config.git.since)
    if not commits:
        return

    fp_paths = {m.path.resolve() for m in model.first_party_modules()}
    bin_size = config.git.heatmap_bin if config.git.heatmap_bin in ("week", "month") else "month"

    counts: dict[tuple[Path, str], int] = defaultdict(int)
    for dt, files in commits:
        label = _bin_label(dt, bin_size)
        for f in set(files):
            if f in fp_paths:
                counts[(f, label)] += 1

    model.churn_heatmap = [
        ChurnHeatmapCell(file=f, bin_label=label, commit_count=c)
        for (f, label), c in counts.items()
    ]


def compute_change_coupling(model: ProjectModel, config: FwLensConfig) -> None:
    """
    Populate model.change_coupling with first-party file pairs that repeatedly change
    together in the same commit -- logical coupling the static call/include graph can
    miss entirely (e.g. two files that should probably be merged, or are missing a
    shared abstraction). Skips gracefully if the project isn't a git repo.
    """
    proj_root = config.project.source_dir or config.project.proj_dir
    git_root = _find_git_root(proj_root)
    if git_root is None:
        return

    commits = _commits_file_lists(git_root, config.git.since)
    if not commits:
        return

    fp_paths = {m.path.resolve() for m in model.first_party_modules()}

    change_counts: dict[Path, int] = {}
    co_change_counts: dict[tuple[Path, Path], int] = defaultdict(int)

    for files in commits:
        touched = sorted({f for f in files if f in fp_paths})
        if len(touched) < 2 or len(touched) > _MAX_FILES_PER_COMMIT:
            continue
        for f in touched:
            change_counts[f] = change_counts.get(f, 0) + 1
        for i in range(len(touched)):
            for j in range(i + 1, len(touched)):
                co_change_counts[(touched[i], touched[j])] += 1

    pairs: list[CouplingPair] = []
    for (a, b), co in co_change_counts.items():
        if co < _MIN_CO_CHANGES:
            continue
        ca = change_counts.get(a, co)
        cb = change_counts.get(b, co)
        denom = ca + cb - co
        coupling = co / denom if denom > 0 else 0.0
        if coupling >= _MIN_COUPLING:
            pairs.append(CouplingPair(
                file_a=a, file_b=b, co_changes=co, changes_a=ca, changes_b=cb,
                coupling=round(coupling, 3),
            ))

    pairs.sort(key=lambda p: (p.coupling, p.co_changes), reverse=True)
    model.change_coupling = pairs


def _percentile_rank(val: float, population: list[float]) -> float:
    """Fraction of population strictly less than val -- same convention as compute_zone_metrics."""
    if not population:
        return 0.0
    return sum(1 for v in population if v < val) / len(population)


def compute_commit_activity(model: ProjectModel, config: FwLensConfig) -> None:
    """
    Populate model.commit_activity: total commit count per calendar day, across the
    whole first-party codebase -- the classic "when did work happen" calendar heatmap
    (GitHub contribution-graph style), as opposed to compute_churn_heatmap's per-file,
    per-month breakdown. A commit touching several first-party files counts once here,
    not once per file, so this answers "how much happened on this day" rather than
    "which files were busy this month".

    Reuses the same _commits_with_dates git-log pass as compute_churn_heatmap. A commit
    counts if it touches at least one first-party file, matching that function's
    filtering so the two heatmaps agree about which commits are "first-party activity".
    """
    proj_root = config.project.source_dir or config.project.proj_dir
    git_root = _find_git_root(proj_root)
    if git_root is None:
        return

    commits = _commits_with_dates(git_root, config.git.since)
    if not commits:
        return

    fp_paths = {m.path.resolve() for m in model.first_party_modules()}

    counts: dict[str, int] = defaultdict(int)
    for dt, files in commits:
        if any(f in fp_paths for f in files):
            counts[dt.date().isoformat()] += 1

    model.commit_activity = [
        CommitActivityCell(date=date, commit_count=c) for date, c in counts.items()
    ]


def compute_hotspots(model: ProjectModel, config: FwLensConfig) -> None:
    """
    Populate ModuleMetrics.commit_count, FunctionMetrics.hotspot_score, and
    model.hotspots (all first-party functions sorted by hotspot_score descending).
    """
    proj_root = config.project.source_dir or config.project.proj_dir
    git_root = _find_git_root(proj_root)
    if git_root is None:
        console.print(
            "[dim][fwlens] Hotspot analysis skipped: "
            f"{proj_root} is not a git repository (or git is unavailable)[/dim]"
        )
        return

    counts = _commit_counts(git_root, config.git.since)
    model.git_available = True

    fp_modules = model.first_party_modules()
    for m in fp_modules:
        try:
            resolved = m.path.resolve()
        except OSError:
            resolved = m.path
        m.commit_count = counts.get(resolved, 0)

    commit_counts = [m.commit_count for m in fp_modules]
    module_by_path = {m.path: m for m in fp_modules}

    fp_funcs = model.first_party_functions()
    sdi_values = [f.structural_debt_index for f in fp_funcs]

    for f in fp_funcs:
        m = module_by_path.get(f.file)
        churn = m.commit_count if m else 0
        f.hotspot_score = round(
            _percentile_rank(churn, commit_counts)
            * _percentile_rank(f.structural_debt_index, sdi_values),
            4,
        )

    model.hotspots = sorted(fp_funcs, key=lambda f: f.hotspot_score, reverse=True)


def compute_architecture_coupling(model: ProjectModel, config: FwLensConfig) -> None:
    """
    Roll model.change_coupling up to the architecture-layer level (Tornhill Ch.8/10,
    "architectural decay" / "surprising change patterns"): file pairs that change
    together but live in different layers are exactly the kind of coupling a static
    layer-violation check (fwlens.graph.engines.detect_arch_violations) can't see, since
    that check only looks at the call graph, not git history.

    Each cross-layer CouplingPair is additionally flagged `surprising` if neither file
    directly #includes the other -- a best-effort static-dependency check (direct
    includes only, not transitive or call-graph), so treat `surprising` as a worklist
    signal rather than a definitive "this coupling is unjustified" verdict.

    Must run after assign_layers (fwlens.metrics.aggregates, populates ModuleMetrics.layer)
    and compute_change_coupling.
    """
    if not model.change_coupling:
        return

    module_by_resolved: dict[Path, object] = {}
    for m in model.first_party_modules():
        try:
            module_by_resolved[m.path.resolve()] = m
        except OSError:
            module_by_resolved[m.path] = m

    layer_pairs: dict[tuple[str, str], dict] = {}

    for p in model.change_coupling:
        mod_a = module_by_resolved.get(p.file_a)
        mod_b = module_by_resolved.get(p.file_b)
        if mod_a is None or mod_b is None:
            continue
        layer_a, layer_b = mod_a.layer or "Unknown", mod_b.layer or "Unknown"
        p.layer_a, p.layer_b = layer_a, layer_b
        if layer_a == "Unknown" or layer_b == "Unknown" or layer_a == layer_b:
            continue
        p.cross_layer = True
        # Direct-include check only; module.includes come from libclang's own resolved
        # #include paths, so a mismatch here just means "not directly related", not
        # "no relationship of any kind" (a transitive or call-graph link may still exist).
        p.surprising = p.file_b not in mod_a.includes and p.file_a not in mod_b.includes

        key = tuple(sorted((layer_a, layer_b)))
        bucket = layer_pairs.setdefault(key, {"pair_count": 0, "co_changes": 0,
                                                "coupling_sum": 0.0, "surprising": 0})
        bucket["pair_count"] += 1
        bucket["co_changes"] += p.co_changes
        bucket["coupling_sum"] += p.coupling
        if p.surprising:
            bucket["surprising"] += 1

    results = [
        LayerCouplingPair(
            layer_a=key[0], layer_b=key[1],
            file_pair_count=b["pair_count"],
            total_co_changes=b["co_changes"],
            avg_coupling=round(b["coupling_sum"] / b["pair_count"], 3),
            surprising_pair_count=b["surprising"],
        )
        for key, b in layer_pairs.items()
    ]
    results.sort(key=lambda r: (r.surprising_pair_count, r.avg_coupling), reverse=True)
    model.layer_coupling = results
