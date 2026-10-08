"""PlantUML and Structurizr export, and the Architecture view in the report (#124)."""

from __future__ import annotations

import json

import pytest
from arch_helpers import project
from click.testing import CliRunner
from test_arch_layers import PINS, SOURCES

import main as fwlens_main
from fwlens.arch.export import plantuml, structurizr


def _arch(tmp_path):
    return project(tmp_path, SOURCES, components=PINS, subsystems=[{"domain": "hal", "units": ["hal/*"]}])[2]


def test_plantuml_has_a_package_per_level_and_a_dependency_per_pair(tmp_path):
    text = plantuml(_arch(tmp_path))
    assert text.startswith("@startuml") and text.rstrip().endswith("@enduml")
    assert 'package "Level 0"' in text and 'package "Level 2"' in text
    assert "c_App ..> c_Svc" in text and "c_Svc ..> c_Hal" in text
    assert "<<hal>>" in text


def test_a_cycle_is_drawn_in_red(tmp_path):
    pins = PINS[:3] + [{"name": "A", "units": ["net/a.*"]}, {"name": "B", "units": ["net/b.*"]}]
    text = plantuml(project(tmp_path, SOURCES, components=pins)[2])
    assert "(cycle)" in text
    assert ".[#red,thickness=2].>" in text and "<<violation: cycle>>" in text


def test_structurizr_has_containers_components_and_views(tmp_path):
    text = structurizr(_arch(tmp_path), "Meter")
    assert text.count("{") == text.count("}")
    assert 'softwareSystem "Meter"' in text and 'container "Hardware abstraction"' in text
    assert 'component "Hal"' in text and "c_App -> c_Svc" in text
    assert 'container system "Containers"' in text and "autoLayout lr" in text


@pytest.fixture
def built(tmp_path, monkeypatch):
    for name, text in SOURCES.items():
        f = tmp_path / "src" / name
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)
    cfg = tmp_path / "config.yaml"
    cfg.write_text("project:\n  source_dir: .\nscope:\n  first_party: [src]\ntool:\n  target: native\n"
                   "output:\n  formats: [html, json, architecture]\n"
                   "architecture:\n  components:\n    - {name: App, units: ['app/*']}\n    - {name: Svc, units: ['svc/*']}\n"
                   "    - {name: Hal, units: ['hal/*']}\n")
    monkeypatch.chdir(tmp_path)
    return tmp_path, cfg


def test_the_architecture_format_writes_both_files_and_the_report_gets_a_section(built):
    tmp_path, cfg = built
    result = CliRunner().invoke(fwlens_main.cli, ["report", "--config", str(cfg)])
    assert result.exit_code == 0, result.output
    folder = tmp_path / "output" / "reports" / "architecture"
    assert (folder / "architecture.puml").read_text(encoding="utf-8").startswith("@startuml")
    assert "workspace" in (folder / "architecture.dsl").read_text(encoding="utf-8")
    html = (tmp_path / "output" / "reports" / "fwlens_report.html").read_text(encoding="utf-8")
    assert "Recovered architecture" in html and 'id="arch-layers-table"' in html and 'id="arch-components-table"' in html
    data = json.loads((tmp_path / "output" / "exports" / "fwlens_results.json").read_text(encoding="utf-8"))
    assert data["architecture"]["layering"]["level_of"]["Hal"] == 0


def test_the_export_command_writes_the_files(built):
    tmp_path, cfg = built
    result = CliRunner().invoke(fwlens_main.cli, ["architecture", "export", "--config", str(cfg)])
    assert result.exit_code == 0, result.output
    assert (tmp_path / "output" / "reports" / "architecture" / "architecture.puml").exists()


def test_turning_the_stage_off_skips_the_export_with_a_message(built):
    tmp_path, cfg = built
    cfg.write_text(cfg.read_text() + "  enabled: false\n")
    result = CliRunner().invoke(fwlens_main.cli, ["architecture", "export", "--config", str(cfg)])
    assert result.exit_code == 0 and "nothing to export" in result.output
