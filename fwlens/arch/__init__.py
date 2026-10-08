"""Architecture recovery: typed dependencies, components, layers and patterns (docs/ARCHITECTURE_RECOVERY.md)."""

from __future__ import annotations

from fwlens.arch.edges import build_edges
from fwlens.arch.model import ArchModel


def build_architecture(model, config) -> ArchModel:
    """Build the architecture model from the parsed project. Stores it as `model.architecture`."""
    cfg = config.architecture
    arch = ArchModel(weights=dict(cfg.weights))
    arch.units, arch.edges = build_edges(model, cfg.weights)
    model.architecture = arch
    return arch


def run_architecture(model, config) -> None:
    if config.architecture.enabled:
        build_architecture(model, config)
