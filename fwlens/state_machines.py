"""
State machine detection for fwlens.

Interprets the raw switch-transition candidates already captured during the AST walk
(FunctionMetrics.state_machines, from fwlens.parser.ast_walker._extract_switch_transitions)
into StateMachine records: distinct states, deduplicated transitions, and a case count.

This is a text-level heuristic, not semantic analysis -- state labels are raw case-value
and assigned-value text, not resolved enum/macro values, so `STATE_IDLE` and `0` would be
treated as different states even if they're the same enum constant under the hood. Good
enough to sketch a state machine's shape for review; not a substitute for reading the code.
"""

from __future__ import annotations

from fwlens.model.project import ProjectModel, StateMachine


def detect_state_machines(model: ProjectModel) -> None:
    """Populate model.state_machines from FunctionMetrics.state_machines raw candidates."""
    machines: list[StateMachine] = []

    for f in model.first_party_functions():
        for sm in f.state_machines:
            states: set[str] = set()
            edges: set[tuple] = set()
            for frm, to in sm["transitions"]:
                if frm:
                    states.add(frm)
                if to:
                    states.add(to)
                edges.add((frm or "?", to))

            machines.append(StateMachine(
                function_name=f.name,
                file=f.file,
                line=sm["line"],
                state_var=sm["state_var"],
                states=sorted(states),
                transitions=sorted(edges),
                case_count=sm["case_count"],
            ))

    machines.sort(key=lambda m: (str(m.file), m.line))
    model.state_machines = machines
