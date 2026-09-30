"""
Composite risk scoring for fwlens.

Fuses signals already computed elsewhere in the pipeline into a single ranked
"riskiest functions in the codebase" list, so the reader isn't left mentally
combining four separate tables (structural debt, hotspots, ISR latency, stack
depth) to work out where to look first. Every component is a percentile rank
within the first-party population before weighting, the same normalisation
approach fwlens.graph.engines.compute_zone_metrics uses for module pain score
-- keeps the composite self-calibrating regardless of codebase size.

Must run after: stats engine (structural_debt_index), graph engine (ISR risk,
stack risk, module pain_score), and fwlens.git_history.compute_hotspots
(hotspot_score) -- i.e. last in the pipeline.
"""

from __future__ import annotations

from fwlens.model.project import ProjectModel

# Weights sum to 1.0. structural_debt_index and hotspot_score dominate since they're
# meaningful for every function; ISR/stack risk only apply to entry points, so they're
# additive bonuses rather than being weighted as heavily as the always-available signals.
_W_SDI = 0.35
_W_HOTSPOT = 0.25
_W_MODULE_PAIN = 0.20
_W_ISR = 0.10
_W_STACK = 0.10


def _percentile_rank(val: float, population: list[float]) -> float:
    if not population:
        return 0.0
    return sum(1 for v in population if v < val) / len(population)


def compute_composite_risk(model: ProjectModel) -> None:
    """Populate FunctionMetrics.composite_risk_score and model.composite_risk."""
    fp_funcs = model.first_party_functions()
    if not fp_funcs:
        return

    sdi_values = [f.structural_debt_index for f in fp_funcs]
    hotspot_values = [f.hotspot_score for f in fp_funcs]

    module_pain = {m.path: m.pain_score for m in model.first_party_modules()}
    pain_values = list(module_pain.values())

    isr_risk_by_name = {r.isr_name: r.risk_score for r in model.isr_risks}
    isr_risk_values = list(isr_risk_by_name.values())

    stack_by_key = {
        (r.function_name, r.file): r.stack_depth_estimate
        for r in model.entry_point_stack_risks
        if r.stack_depth_estimate is not None
    }
    stack_values = [v for v in stack_by_key.values()]

    for f in fp_funcs:
        sdi_pr = _percentile_rank(f.structural_debt_index, sdi_values)
        hotspot_pr = _percentile_rank(f.hotspot_score, hotspot_values) if model.git_available else 0.0
        pain_pr = _percentile_rank(module_pain.get(f.file, 0.0), pain_values)

        isr_score = isr_risk_by_name.get(f.name)
        isr_pr = _percentile_rank(isr_score, isr_risk_values) if isr_score is not None else 0.0

        stack_depth = stack_by_key.get((f.name, f.file))
        stack_pr = _percentile_rank(stack_depth, stack_values) if stack_depth is not None else 0.0

        f.composite_risk_score = round(
            _W_SDI * sdi_pr
            + _W_HOTSPOT * hotspot_pr
            + _W_MODULE_PAIN * pain_pr
            + _W_ISR * isr_pr
            + _W_STACK * stack_pr,
            4,
        )

    model.composite_risk = sorted(fp_funcs, key=lambda f: f.composite_risk_score, reverse=True)
