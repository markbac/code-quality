"""Write the recovered architecture as a starting point for the intended one: the components pinned by
name, the domains, and the inferred layers top to bottom, so the first rules describe what exists."""

from __future__ import annotations

import yaml

from fwlens.arch.model import ArchModel
from fwlens.identity import relative_posix


def adopted(arch: ArchModel, root) -> str:
    unit_path = {u: relative_posix(u, root) for u in arch.units}
    by_name = {c.name: c for c in arch.components}
    domain = {s.name: s.domain for s in arch.subsystems}
    section: dict = {
        "components": [{"name": c.name, "units": [unit_path[u] for u in c.units]} for c in arch.components],
        "subsystems": [{"domain": domain[c.name], "units": [unit_path[u] for u in c.units]}
                       for c in arch.components if domain.get(c.name) not in (None, "", "unclassified")],
        "intended_layers": [{"name": f"Level {layer['level']}", "components": list(layer["components"])}
                            for layer in arch.layering.layers if all(n in by_name for n in layer["components"])],
        "rules": [],
    }
    header = ("# Written by `fwlens architecture adopt`. Merge it into config.yaml under `architecture:`, then tighten it.\n"
              "# The layers are the inferred ones (top first), so the first run reports nothing the code does not already do.\n")
    return header + yaml.safe_dump({"architecture": section}, sort_keys=False, default_flow_style=False)
