"""
Cost/benefit estimate for catching defects statically vs. in the field.

Grady, R.B. (1992). Practical Software Metrics for Project Management and Process
Improvement, Ch. 5 ("Project Management to Minimize Defects", cost trade-offs) and
Ch. 14 ("Justifying Change"). Hewlett-Packard Professional Books.
Boehm, B.W. (1981). Software Engineering Economics, Prentice-Hall -- the well-known
finding that a defect found late costs far more to fix than one found early is the
foundation both of the above build the business case on.

fwlens has no way to know your organisation's actual cost figures -- both inputs are
config values you must supply (config.cost_benefit). The defaults are placeholder
order-of-magnitude figures (a conservative 10x found-early-vs-found-late ratio), not
real numbers, and this estimate is only as good as the two you provide.
"""

from __future__ import annotations

from fwlens.config import FwLensConfig
from fwlens.model.project import CostBenefitEstimate, ProjectModel


def compute_cost_benefit(model: ProjectModel, config: FwLensConfig) -> None:
    """
    Populate model.cost_benefit from reliability_growth.estimated_remaining (the
    Goel-Okumoto fit's estimate of undiscovered defects) and the configured per-defect
    cost figures. Requires a successful reliability_growth fit -- skipped otherwise.
    """
    rg = model.reliability_growth
    if rg is None or rg.trend == "insufficient_data" or rg.estimated_remaining <= 0:
        return

    cb = config.cost_benefit
    remaining = rg.estimated_remaining
    cost_static = remaining * cb.cost_per_defect_static_usd
    cost_field = remaining * cb.cost_per_defect_field_usd

    model.cost_benefit = CostBenefitEstimate(
        estimated_remaining_defects=remaining,
        cost_per_defect_static_usd=cb.cost_per_defect_static_usd,
        cost_per_defect_field_usd=cb.cost_per_defect_field_usd,
        cost_if_static_usd=round(cost_static, 2),
        cost_if_field_usd=round(cost_field, 2),
        potential_savings_usd=round(cost_field - cost_static, 2),
    )
