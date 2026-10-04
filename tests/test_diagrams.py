"""Regression tests for #60: the dependency SVG must not fail on a missing matplotlib import."""

from pathlib import Path
from types import SimpleNamespace

from fwlens.output import diagrams


def _config(tmp_path: Path):
    return SimpleNamespace(output=SimpleNamespace(reports_dir=tmp_path))


def test_dependency_svg_for_an_empty_project(tmp_path):
    model = SimpleNamespace(first_party_modules=lambda: [])
    out = diagrams.generate_dependency_svg(model, _config(tmp_path))
    assert out.exists() and out.suffix == ".svg"


def test_dependency_svg_for_modules_with_edges(tmp_path):
    mods = [SimpleNamespace(path=Path(f"src/{n}.c"), loc=10 * (i + 1), zone="unknown")
            for i, n in enumerate("abc")]
    graph = SimpleNamespace(edges=lambda: [(str(mods[0].path), str(mods[1].path)),
                                           (str(mods[1].path), str(mods[2].path))])
    model = SimpleNamespace(first_party_modules=lambda: mods, _module_dep_graph=graph)
    out = diagrams.generate_dependency_svg(model, _config(tmp_path))
    assert out.read_text(encoding="utf-8").lstrip().startswith(("<?xml", "<svg"))
