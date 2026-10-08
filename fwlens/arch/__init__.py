"""Architecture recovery: typed dependencies, components, layers and patterns (docs/ARCHITECTURE_RECOVERY.md)."""

from __future__ import annotations

from fwlens.arch.activity import compute as compute_activity
from fwlens.arch.components import infer
from fwlens.arch.domains import label, load_domains
from fwlens.arch.edges import Units, build_edges
from fwlens.arch.rules import evaluate as check_rules
from fwlens.arch.layers import infer_layers
from fwlens.arch.pubsub import map_events
from fwlens.arch.patterns import detect, load_patterns
from fwlens.arch.interfaces import analyse as analyse_interfaces
from fwlens.arch.model import ArchModel


def build_architecture(model, config) -> ArchModel:
    """Build the architecture model from the parsed project. Stores it as `model.architecture`."""
    cfg = config.architecture
    arch = ArchModel(weights=dict(cfg.weights))
    units = Units(model)
    arch.units, arch.edges = build_edges(model, cfg.weights, units)
    arch.interfaces, arch.leaks, arch.ops_headers = analyse_interfaces(model, units, cfg.private_headers)
    arch.components, arch.drift, arch.differences = infer(
        model, arch.units, arch.edges, cfg.components, cfg.resolution, cfg.max_component_units, cfg.drift_threshold)
    arch.subsystems = label(model, arch.components, load_domains(cfg.domains), cfg.subsystems)
    arch.layering = infer_layers(arch.components, arch.edges, [r.name for r in config.layers])
    arch.events = map_events(model, units, cfg.register_calls, cfg.publish_calls)
    arch.patterns = detect(model, arch, config, load_patterns(cfg.patterns))
    arch.violations = check_rules(arch, cfg)
    arch.activity = compute_activity(model, arch, units, cfg.teams)
    _compare_with_baseline(arch, config)
    model.architecture = arch
    return arch


def run_architecture(model, config) -> None:
    if config.architecture.enabled:
        build_architecture(model, config)


def _compare_with_baseline(arch: ArchModel, config) -> None:
    """Fill `arch.since_baseline` when architecture.baseline names a saved snapshot."""
    path = config.architecture.baseline
    if path is None:
        return
    from fwlens.arch import drift
    from fwlens.identity import project_root
    try:
        arch.since_baseline = drift.diff(drift.load(path), drift.snapshot(arch, project_root(config)))
    except ValueError as exc:
        arch.since_baseline = {"error": str(exc)}
