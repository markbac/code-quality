"""
Standalone PNG plots for fwlens.

Histograms, sorted-value bar charts, and heatmaps written directly to
`<reports_dir>/plots/`, in the same spirit as the plot set the older
ccccc/scc-based code_governance toolkit produced with matplotlib -- but
drawn from fwlens's own libclang-derived metrics rather than ccccc's.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from fwlens.config import FwLensConfig
from fwlens.model.project import ProjectModel

# slug, FunctionMetrics attribute, axis label, whether to also draw a sorted-bar chart
_FUNCTION_METRICS = [
    ("cyclomatic_complexity", "cyclomatic_complexity", "Cyclomatic Complexity", True),
    ("halstead_volume",       "halstead_volume",       "Halstead Volume",       True),
    ("halstead_effort",       "halstead_effort",       "Halstead Effort",       True),
    ("maintainability_index", "mi_woc",                "Maintainability Index", True),
    ("function_length",       "loc",                   "Function Length (LOC)", False),
    ("call_count",            "fan_out",               "Call Count (fan-out)",  True),
    ("caller_count",          "fan_in",                "Caller Count (fan-in)", True),
]


def _hist(values: list[float], title: str, xlabel: str, path: Path) -> None:
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.hist(values, bins=30, color="#4C72B0", edgecolor="black")
    ax.set_title(title)
    ax.set_xlabel(xlabel)
    ax.set_ylabel("Count")
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)


def _sorted_bar(values: list[float], title: str, ylabel: str, path: Path) -> None:
    ordered = sorted(values, reverse=True)
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.bar(range(len(ordered)), ordered, color="#DD8452", width=1.0)
    ax.set_title(title)
    ax.set_xlabel("Rank")
    ax.set_ylabel(ylabel)
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)


def _heatmap(x: list[float], y: list[float], title: str, xlabel: str, ylabel: str, path: Path) -> None:
    fig, ax = plt.subplots(figsize=(7, 6))
    hb = ax.hexbin(x, y, gridsize=30, cmap="viridis", mincnt=1)
    fig.colorbar(hb, ax=ax, label="Count")
    ax.set_title(title)
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)


def _generate_churn_heatmap(model: ProjectModel, config: FwLensConfig, plots_dir: Path) -> None:
    """File x time-bin commit-count matrix -- shows *when* a file was hot, not just
    that its aggregate commit count is high."""
    if not model.churn_heatmap:
        return

    totals: dict[Path, int] = {}
    for cell in model.churn_heatmap:
        totals[cell.file] = totals.get(cell.file, 0) + cell.commit_count
    top_n = config.output.top_n
    top_files = sorted(totals, key=lambda f: totals[f], reverse=True)[:top_n]
    if not top_files:
        return

    bin_labels = sorted({cell.bin_label for cell in model.churn_heatmap})
    file_idx = {f: i for i, f in enumerate(top_files)}
    bin_idx = {b: i for i, b in enumerate(bin_labels)}

    matrix = [[0] * len(bin_labels) for _ in top_files]
    for cell in model.churn_heatmap:
        if cell.file in file_idx:
            matrix[file_idx[cell.file]][bin_idx[cell.bin_label]] = cell.commit_count

    fig_w = max(8, len(bin_labels) * 0.4)
    fig_h = max(4, len(top_files) * 0.35)
    fig, ax = plt.subplots(figsize=(fig_w, fig_h))
    im = ax.imshow(matrix, cmap="YlOrRd", aspect="auto")
    fig.colorbar(im, ax=ax, label="Commits")
    ax.set_yticks(range(len(top_files)))
    ax.set_yticklabels([f.name for f in top_files], fontsize=8)
    ax.set_xticks(range(len(bin_labels)))
    ax.set_xticklabels(bin_labels, rotation=90, fontsize=7)
    ax.set_title(f"Churn Heatmap -- top {len(top_files)} files by commit count "
                 f"({config.git.heatmap_bin}ly bins)")
    fig.tight_layout()
    fig.savefig(plots_dir / "churn_heatmap.png", dpi=120)
    plt.close(fig)


def _generate_coupling_heatmap(model: ProjectModel, config: FwLensConfig, plots_dir: Path) -> None:
    """File x file change-coupling matrix, visualising model.change_coupling as a grid."""
    if not model.change_coupling:
        return

    files = sorted({p.file_a for p in model.change_coupling} | {p.file_b for p in model.change_coupling})
    idx = {f: i for i, f in enumerate(files)}
    n = len(files)
    matrix = [[0.0] * n for _ in range(n)]
    for p in model.change_coupling:
        i, j = idx[p.file_a], idx[p.file_b]
        matrix[i][j] = p.coupling
        matrix[j][i] = p.coupling

    size = max(6, n * 0.45)
    fig, ax = plt.subplots(figsize=(size, size))
    im = ax.imshow(matrix, cmap="YlOrRd", vmin=0, vmax=1, aspect="auto")
    fig.colorbar(im, ax=ax, label="Coupling (Jaccard)")
    labels = [f.name for f in files]
    ax.set_xticks(range(n))
    ax.set_xticklabels(labels, rotation=90, fontsize=8)
    ax.set_yticks(range(n))
    ax.set_yticklabels(labels, fontsize=8)
    ax.set_title("Change-Coupling Matrix -- files that commit together")
    fig.tight_layout()
    fig.savefig(plots_dir / "change_coupling_heatmap.png", dpi=120)
    plt.close(fig)


def _generate_hotspot_map(model: ProjectModel, config: FwLensConfig, plots_dir: Path) -> None:
    """
    File-level hotspot scatter map: x = churn (commit count), y = structural debt
    (summed per file across its functions), point size = file SLOC, colour = hotspot
    score. Tornhill Ch.4 ("Analyze Hotspots in Large-Scale Systems") visualises hotspots
    this way (there as circle-packing) specifically so the *distribution* is visible at
    a glance -- real codebases are typically skewed, with most of the risk concentrated
    in a handful of outliers rather than spread evenly, and a handful of extreme points
    sitting alone in the top-right are what's worth investigating first, as opposed to
    a merely-large file with unremarkable complexity, or a genuinely complex file that's
    barely ever touched (both of which read as false positives on either axis alone).
    """
    modules = model.first_party_modules()
    if not modules:
        return

    sdi_by_module: dict[Path, float] = {}
    for m in modules:
        sdi_by_module[m.path] = sum(f.structural_debt_index for f in m.functions)

    plot_modules = [m for m in modules if m.commit_count > 0 or sdi_by_module.get(m.path, 0) > 0]
    if not plot_modules:
        return

    churn = [m.commit_count for m in plot_modules]
    debt = [sdi_by_module.get(m.path, 0.0) for m in plot_modules]
    sizes = [max(20.0, min(m.file_sloc, 2000) / 3) for m in plot_modules]
    hotspot_score = [
        max((f.hotspot_score for f in m.functions), default=0.0) for m in plot_modules
    ]

    fig, ax = plt.subplots(figsize=(9, 7))
    sc = ax.scatter(churn, debt, s=sizes, c=hotspot_score, cmap="YlOrRd",
                     edgecolors="black", linewidths=0.5, alpha=0.85, vmin=0, vmax=1)
    fig.colorbar(sc, ax=ax, label="Hotspot score (max function in file)")

    top_n = config.output.top_n
    labelled = sorted(plot_modules, key=lambda m: max(
        (f.hotspot_score for f in m.functions), default=0.0), reverse=True)[:min(10, top_n)]
    for m in labelled:
        if max((f.hotspot_score for f in m.functions), default=0.0) <= 0:
            continue
        ax.annotate(m.path.name, (m.commit_count, sdi_by_module.get(m.path, 0.0)),
                    fontsize=7, xytext=(4, 4), textcoords="offset points")

    ax.set_xlabel("Commit count (churn)")
    ax.set_ylabel("Structural debt index (summed per file)")
    ax.set_title("Hotspot Map -- churn vs structural debt, point size = file SLOC\n"
                 "(top-right outliers are the real hotspots; large-but-simple or "
                 "complex-but-rarely-touched files are the false positives)")
    fig.tight_layout()
    fig.savefig(plots_dir / "hotspot_map.png", dpi=120)
    plt.close(fig)


def _generate_complexity_trend_plot(model: ProjectModel, plots_dir: Path) -> None:
    """
    Complexity-over-time line chart for the top hotspot files with enough history to
    fit a trend (fwlens.complexity_trend). One line per file; colour signals worsening
    vs improving vs stable so the reader can tell which hotspots are still getting
    worse without reading the CSV.
    """
    plottable = [t for t in model.complexity_trends if len(t.points) >= 2]
    if not plottable:
        return

    colour_by_trend = {"worsening": "#C44E52", "improving": "#55A868",
                        "stable": "#4C72B0", "insufficient_data": "#999999"}

    fig, ax = plt.subplots(figsize=(9, 6))
    for t in plottable:
        dates = [p.date for p in t.points]
        values = [p.complexity_proxy for p in t.points]
        ax.plot(dates, values, marker="o", markersize=3,
                color=colour_by_trend.get(t.trend, "#4C72B0"),
                label=f"{t.file.name} ({t.trend})")
    ax.set_xlabel("Commit date")
    ax.set_ylabel("Complexity proxy (decision-point count)")
    ax.set_title("Complexity Trend in Top Hotspots")
    ax.legend(fontsize=7, loc="upper left")
    fig.autofmt_xdate()
    fig.tight_layout()
    fig.savefig(plots_dir / "complexity_trend.png", dpi=120)
    plt.close(fig)


def _generate_commit_activity_calendar(model: ProjectModel, plots_dir: Path) -> None:
    """
    GitHub-style calendar heatmap: one column per week, one row per weekday, colour =
    commit count that day, for the whole first-party codebase (not per file) -- the
    "when did work happen" complement to _generate_churn_heatmap's per-file breakdown.
    Capped to the most recent 53 weeks (~1 year, matching the GitHub contribution-graph
    convention this is modelled on) for a readable width regardless of total project
    history; the full daily series is in commit_activity.csv regardless of this cap.
    """
    if not model.commit_activity:
        return

    from datetime import date as _date, timedelta as _timedelta

    counts = {
        _date.fromisoformat(c.date): c.commit_count for c in model.commit_activity
    }
    last_day = max(counts)
    first_day = last_day - _timedelta(weeks=52)
    first_day -= _timedelta(days=first_day.weekday())  # snap back to a Monday

    n_weeks = (last_day - first_day).days // 7 + 1
    matrix = np.zeros((7, n_weeks))
    for d, c in counts.items():
        if d < first_day:
            continue
        week_idx = (d - first_day).days // 7
        matrix[d.weekday(), week_idx] = c

    fig, ax = plt.subplots(figsize=(max(8, n_weeks * 0.22), 3))
    im = ax.imshow(matrix, cmap="Greens", aspect="auto")
    fig.colorbar(im, ax=ax, label="Commits", fraction=0.02, pad=0.02)
    ax.set_yticks(range(7))
    ax.set_yticklabels(["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"], fontsize=8)
    month_ticks, month_labels = [], []
    seen_months = set()
    for w in range(n_weeks):
        d = first_day + _timedelta(weeks=w)
        key = (d.year, d.month)
        if key not in seen_months:
            seen_months.add(key)
            month_ticks.append(w)
            month_labels.append(d.strftime("%b %Y"))
    ax.set_xticks(month_ticks)
    ax.set_xticklabels(month_labels, rotation=45, ha="right", fontsize=7)
    ax.set_title(f"Commit Activity -- {first_day.isoformat()} to {last_day.isoformat()}")
    fig.tight_layout()
    fig.savefig(plots_dir / "commit_activity_calendar.png", dpi=120)
    plt.close(fig)


def generate_plots(model: ProjectModel, config: FwLensConfig) -> Path:
    """Write histogram / sorted-bar / heatmap PNGs to <reports_dir>/plots/. Returns that dir."""
    plots_dir = config.output.reports_dir / "plots"
    plots_dir.mkdir(parents=True, exist_ok=True)

    funcs = model.first_party_functions()
    modules = model.first_party_modules()

    for slug, attr, label, want_sorted in _FUNCTION_METRICS:
        values = [getattr(f, attr) for f in funcs]
        if not values:
            continue
        _hist(values, f"{label} -- distribution", label, plots_dir / f"{slug}_hist.png")
        if want_sorted:
            _sorted_bar(values, f"{label} -- sorted", label, plots_dir / f"{slug}_sorted.png")

    # File-level SLOC (fwlens.metrics.file_metrics -- no external tool used)
    sloc_values = [m.file_sloc for m in modules if m.file_sloc]
    if sloc_values:
        _hist(sloc_values, "File Length (SLOC) -- distribution", "SLOC",
              plots_dir / "length_hist.png")
        _sorted_bar(sloc_values, "File Length (SLOC) -- sorted", "SLOC",
                    plots_dir / "length_sorted.png")

    if funcs:
        cc     = [f.cyclomatic_complexity for f in funcs]
        effort = [f.halstead_effort for f in funcs]
        loc    = [f.loc for f in funcs]
        mi     = [f.mi_woc for f in funcs]
        vol    = [f.halstead_volume for f in funcs]
        _heatmap(cc, effort, "Halstead Effort vs Cyclomatic Complexity",
                 "Cyclomatic Complexity", "Halstead Effort",
                 plots_dir / "heatmap_effort_vs_cyclomatic.png")
        _heatmap(cc, loc, "Function Length vs Cyclomatic Complexity",
                 "Cyclomatic Complexity", "Function Length (LOC)",
                 plots_dir / "heatmap_length_vs_cyclomatic.png")
        _heatmap(mi, vol, "Halstead Volume vs Maintainability Index",
                 "Maintainability Index", "Halstead Volume",
                 plots_dir / "heatmap_volume_vs_mi.png")

    _generate_churn_heatmap(model, config, plots_dir)
    _generate_coupling_heatmap(model, config, plots_dir)
    _generate_commit_activity_calendar(model, plots_dir)
    _generate_hotspot_map(model, config, plots_dir)
    _generate_complexity_trend_plot(model, plots_dir)

    return plots_dir
