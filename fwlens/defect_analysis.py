"""
Complexity-vs-defect correlation and root-cause categorisation for fwlens.

Grady, R.B. (1992). Practical Software Metrics for Project Management and Process
Improvement, Ch. 6 ("Complexity Increases Costs") and Ch. 11 ("Dissecting Software
Failures", the root-cause pie chart). Hewlett-Packard Professional Books.

Both analyses reuse fwlens.reliability.fetch_fix_commits -- the same "fix"-keyword
commit classification, so the two feed the same underlying data through two different
lenses: correlation checks *which metric* predicts defects in this codebase, root-cause
checks *what kind* of defect keeps showing up.
"""

from __future__ import annotations

from scipy import stats

from fwlens.config import FwLensConfig
from fwlens.git_history import _find_git_root
from fwlens.model.project import DefectCorrelation, ProjectModel
from fwlens.reliability import fetch_fix_commits

_MIN_FILES_WITH_FIXES = 5

# module-level metric attribute -> display label, checked for correlation against
# each module's fix-commit touch count
_CANDIDATE_METRICS = [
    ("avg_cc", "Avg Cyclomatic Complexity"),
    ("max_cc", "Max Cyclomatic Complexity"),
    ("avg_halstead_effort", "Avg Halstead Effort"),
    ("file_sloc", "File SLOC"),
    ("pain_score", "Zone-of-Pain Score"),
    ("instability", "Instability"),
    ("main_sequence_distance", "Main Sequence Distance"),
    ("avg_magic_density", "Avg Magic Number Density"),
]

def compute_defect_correlation(model: ProjectModel, config: FwLensConfig) -> None:
    """
    Populate model.defect_correlations: Spearman rank correlation between each
    candidate module-level metric and that module's fix-commit touch count, sorted
    by |r| descending -- so the top of the list is whichever metric actually predicts
    defects in this specific codebase, rather than assuming the textbook thresholds
    transfer unchanged. Uses Spearman (not Pearson) since defect-touch counts are
    typically non-linear and outlier-heavy.
    """
    proj_root = config.project.source_dir or config.project.proj_dir
    git_root = _find_git_root(proj_root)
    if git_root is None:
        return

    commits = fetch_fix_commits(git_root, config.git.since, config.git.fix_keywords)
    if not commits:
        return

    fix_counts: dict = {}
    for c in commits:
        for f in set(c["files"]):
            fix_counts[f] = fix_counts.get(f, 0) + 1

    fp_modules = model.first_party_modules()
    fix_series = [fix_counts.get(m.path.resolve(), 0) for m in fp_modules]

    if sum(1 for c in fix_series if c > 0) < _MIN_FILES_WITH_FIXES:
        return

    results = []
    for attr, label in _CANDIDATE_METRICS:
        metric_series = [getattr(m, attr, 0.0) for m in fp_modules]
        if len(set(metric_series)) < 2:
            continue
        try:
            r, p = stats.spearmanr(metric_series, fix_series)
        except Exception:
            continue
        if r != r:  # NaN
            continue
        results.append(DefectCorrelation(
            metric=attr, label=label, spearman_r=round(float(r), 3),
            p_value=round(float(p), 4), n=len(fp_modules),
        ))

    results.sort(key=lambda c: abs(c.spearman_r), reverse=True)
    model.defect_correlations = results
