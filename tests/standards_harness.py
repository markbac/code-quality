"""
Helpers for testing native standards rules against the real libclang.

A case is a C source in which every line that must be reported ends with ``/* BAD */``. The
harness runs one rule over it and returns the lines reported, so a test compares them with the
marked lines: nothing missed, nothing extra.
"""

from __future__ import annotations

import re
from pathlib import Path

import cparse

from fwlens.config import StandardsConfig, StandardSelection, ToolConfig
from fwlens.parser.pipeline import run_pipeline
from fwlens.standards import run_standards

MARK = re.compile(r"/\*\s*BAD\s*\*/|//\s*BAD\b")


def marked_lines(text: str) -> list[int]:
    return [i for i, line in enumerate(text.splitlines(), 1) if MARK.search(line)]


def _config(root: Path):
    from test_p0_regressions import _config as base
    config = base(root)
    config.tool = ToolConfig(libclang_path=None, target="native")
    return config


def analyse(root: Path, sources: dict[str, str] | str, standard: str, rule_ids: list[str] | None = None,
            **selection) -> dict[str, list]:
    """Run a standard (optionally only some of its rules) and return {rule id: [Breach, ...]}."""
    cparse.require_host_compiler()
    if isinstance(sources, str):
        sources = {"app.c": sources}
    for name, text in sources.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
    (root / "config.yaml").write_text("tool:\n  target: native\nproject:\n  source_dir: .\n")
    config = _config(root)
    model = run_pipeline(config)
    config.standards = StandardsConfig(enabled=[StandardSelection(standard, include_ids=rule_ids, **selection)])
    result = run_standards(model, config)
    out: dict[str, list] = {}
    for f in result.findings:
        out.setdefault(f.metric.split(":", 1)[1], []).append(f)
    return out


def reported(root: Path, sources: dict[str, str] | str, standard: str, rule_id: str, file: str = "app.c") -> list[int]:
    """Sorted lines a single rule reports in one file."""
    found = analyse(root, sources, standard, [rule_id]).get(rule_id, [])
    return sorted(f.line for f in found if f.file == file)
