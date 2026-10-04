"""Shared helper: parse small C snippets with the real libclang and return the project model.

libclang ships with FWLens (the `libclang` wheel is a hard dependency), so these helpers never
skip. If parsing is broken the test must fail, not silently disappear (#70).
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

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


# Parse functions used to exercise the worker pool. They live here, not in a test module, so the
# spawned worker processes can import them.

def slow_parse(tu_dict, config):
    import time
    from fwlens.parser.pipeline import _parse_one
    if "slow" in tu_dict["path"]:
        time.sleep(120)
    return _parse_one(tu_dict, config)


def crashing_parse(tu_dict, config):
    import os
    from fwlens.parser.pipeline import _parse_one
    if "boom" in tu_dict["path"]:
        os._exit(3)
    return _parse_one(tu_dict, config)


def echo_config_parse(tu_dict, config):
    """Report what the worker's config says, as the parse error text."""
    from fwlens.parser.pipeline import _failure_result
    return _failure_result(tu_dict, "Echo: " + ",".join(config.tool.clang_args) + "|" + config.tool.target, "")


def dying_worker_main(conn, config, parse_fn):
    import os
    os._exit(5)


def require_host_compiler() -> None:
    """Tests that need the host C compiler's headers. Mandatory in CI, skipped elsewhere."""
    if any(shutil.which(c) for c in ("gcc", "cc", "clang")):
        return
    if os.environ.get("FWLENS_REQUIRE_LIBCLANG"):
        pytest.fail("a host C compiler is required here (FWLENS_REQUIRE_LIBCLANG is set)")
    pytest.skip("no host C compiler to ask for include directories")
