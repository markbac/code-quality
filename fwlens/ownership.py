"""
Code ownership / knowledge map analysis for fwlens.

Tornhill, A. (2015). Your Code as a Crime Scene, Ch.11-13 ("Norms, Groups, and False
Serial Killers" / "Discover Organizational Metrics in Your Codebase" / "Build a
Knowledge Map of Your System"). Diffuse ownership -- many contributors, no clear main
author -- correlates with defects independently of complexity: nobody holds the full
context needed to change the file safely, and coordination overhead between authors
introduces its own errors. This is the one book chapter fwlens didn't touch before --
git_history.py already mines commit dates and file lists, but discards author identity.

Git-log based, same "skip gracefully outside a git repo" contract as fwlens.git_history.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from fwlens.config import FwLensConfig
from fwlens.git_history import _commits_with_authors, _find_git_root
from fwlens.model.project import ProjectModel


def _percentile_rank(val: float, population: list[float]) -> float:
    if not population:
        return 0.0
    return sum(1 for v in population if v < val) / len(population)


def compute_ownership(model: ProjectModel, config: FwLensConfig) -> None:
    """
    Populate per-file ownership fields on ModuleMetrics (main_author, main_author_share,
    distinct_author_count, ownership_fragmentation, ownership_risk_score) and
    model.ownership_risks (first-party modules with commit history, sorted by
    ownership_risk_score descending).

    ownership_fragmentation = 1 - main_author_share: 0 means one person wrote every
    commit touching the file, ->1 means authorship is split roughly evenly across many
    people. ownership_risk_score multiplies that by the file's churn percentile, the
    same "churn x signal" shape as fwlens.git_history.compute_hotspots's hotspot_score --
    a file that's both frequently changed and diffusely owned is the bystander-effect
    risk case the book describes, distinct from (and not necessarily overlapping with)
    the structural-debt-driven hotspot list.

    Must run after fwlens.git_history.compute_hotspots (uses ModuleMetrics.commit_count
    for the churn side of ownership_risk_score). Skips gracefully outside a git repo,
    same as compute_hotspots.
    """
    proj_root = config.project.source_dir or config.project.proj_dir
    git_root = _find_git_root(proj_root)
    if git_root is None:
        return

    commits = _commits_with_authors(git_root, config.git.since)
    if not commits:
        return

    author_counts_by_file: dict[Path, Counter] = {}
    for author, files in commits:
        for f in set(files):
            author_counts_by_file.setdefault(f, Counter())[author] += 1

    fp_modules = model.first_party_modules()
    for m in fp_modules:
        try:
            resolved = m.path.resolve()
        except OSError:
            resolved = m.path
        counts = author_counts_by_file.get(resolved)
        if not counts:
            continue
        total = sum(counts.values())
        main_author, main_count = counts.most_common(1)[0]
        m.main_author = main_author
        m.main_author_share = round(main_count / total, 3)
        m.distinct_author_count = len(counts)
        m.ownership_fragmentation = round(1.0 - m.main_author_share, 3)

    commit_counts = [m.commit_count for m in fp_modules]
    for m in fp_modules:
        if m.commit_count <= 0 or not m.main_author:
            continue
        m.ownership_risk_score = round(
            _percentile_rank(m.commit_count, commit_counts) * m.ownership_fragmentation, 4,
        )

    model.ownership_risks = sorted(
        (m for m in fp_modules if m.main_author),
        key=lambda m: m.ownership_risk_score, reverse=True,
    )
