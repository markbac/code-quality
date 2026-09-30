"""
Basic COCOMO 81 effort/schedule estimation for fwlens.

Boehm, B.W. (1981). Software Engineering Economics. Prentice-Hall.

> **Caveat:** the a/b/c/d constants below were empirically fitted to a dataset of
> ~60 1970s-80s business and systems-software projects. They are NOT calibrated to
> this codebase, this team, or embedded firmware specifically -- COCOMO's "embedded"
> mode (tight hardware/timing/interface constraints) is the closest built-in category
> to firmware, which is a reasonable qualitative fit, but the numeric output should be
> read as a rough historical-baseline estimate, not a committed schedule. If you have
> your own historical effort data for comparable projects, calibrating your own a/b
> constants against it (linear regression of ln(effort) vs ln(KLOC)) will be far more
> meaningful than the textbook defaults.
"""

from __future__ import annotations

from fwlens.config import FwLensConfig
from fwlens.model.project import EffortEstimate, ProjectModel

# mode -> (a, b, c, d)  where effort_pm = a * KLOC^b,  schedule_months = c * effort_pm^d
_COCOMO_CONSTANTS = {
    "organic":      (2.4, 1.05, 2.5, 0.38),
    "semidetached": (3.0, 1.12, 2.5, 0.35),
    "embedded":     (3.6, 1.20, 2.5, 0.32),
}


def compute_effort_estimate(model: ProjectModel, config: FwLensConfig) -> None:
    """Populate model.effort_estimate from total first-party SLOC (fwlens.metrics.file_metrics)."""
    fp_modules = model.first_party_modules()
    total_sloc = sum(m.file_sloc for m in fp_modules)
    if total_sloc <= 0:
        return

    mode = config.estimation.cocomo_mode
    if mode not in _COCOMO_CONSTANTS:
        mode = "embedded"
    a, b, c, d = _COCOMO_CONSTANTS[mode]

    kloc = total_sloc / 1000.0
    effort_pm = a * (kloc ** b)
    schedule_months = c * (effort_pm ** d)
    avg_staffing = effort_pm / schedule_months if schedule_months > 0 else 0.0

    model.effort_estimate = EffortEstimate(
        mode=mode,
        kloc=round(kloc, 2),
        effort_person_months=round(effort_pm, 1),
        schedule_months=round(schedule_months, 1),
        average_staffing=round(avg_staffing, 2),
    )
