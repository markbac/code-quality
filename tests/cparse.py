"""Shared helper: parse small C snippets with the real libclang and return the project model.

libclang ships with FWLens (the `libclang` wheel is a hard dependency), so these helpers never
skip. If parsing is broken the test must fail, not silently disappear (#70).
"""

from __future__ import annotations

from pathlib import Path

from fwlens.config import FwLensConfig, OutputConfig, ProjectConfig, ScopeConfig, ThresholdConfig, ToolConfig
from fwlens.parser.pipeline import run_pipeline


def make_config(root: Path, formats=("json",)) -> FwLensConfig:
    return FwLensConfig(
        config_path=root / "config.yaml",
        tool=ToolConfig(libclang_path=None),
        project=ProjectConfig(
            ewp=None, configuration="Debug", proj_dir=root, toolkit_dir=None,
            mode="directory", source_dir=root,
        ),
        scope=ScopeConfig(first_party=["."], sdk=[], third_party_lib=[], analyse=["first_party"]),
        iar_compat_defines=[],
        layers=[],
        thresholds=ThresholdConfig(),
        output=OutputConfig(
            reports_dir=root / "output" / "reports",
            exports_dir=root / "output" / "exports",
            cache_dir=root / "output" / ".cache",
            db_path=root / "output" / "fwlens.db",
            formats=list(formats),
        ),
        entry_points=["main"],
    )


def parse_model(root: Path, sources: dict[str, str] | str):
    """Write the sources under root and run the real pipeline. `sources` is {name: text} or one text for a.c."""
    if isinstance(sources, str):
        sources = {"a.c": sources}
    for name, text in sources.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
    (root / "config.yaml").write_text("project:\n  source_dir: .\n")
    model = run_pipeline(make_config(root))
    assert model.first_party_functions(), "libclang parsed no functions"
    return model


def parse_functions(root: Path, sources: dict[str, str] | str) -> dict:
    return {f.name: f for f in parse_model(root, sources).first_party_functions()}
