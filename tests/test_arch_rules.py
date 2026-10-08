"""Dependency rules and intended-versus-implemented conformance (#125)."""

from __future__ import annotations

import pytest
import yaml
from arch_helpers import project
from click.testing import CliRunner
from test_arch_layers import PINS, SOURCES

import main as fwlens_main
from fwlens.arch import build_architecture
from fwlens.arch.adopt import adopted
from fwlens.arch.rules import validate
from fwlens.baseline import compute_breaches
from fwlens.config import ConfigError
from fwlens.identity import project_root

GOOD = ["App", "Svc", "Hal", "Net"]


def _violations(tmp_path, **cfg):
    return project(tmp_path, SOURCES, components=PINS, **cfg)[2].violations


def test_the_right_direction_is_not_a_violation(tmp_path):
    assert _violations(tmp_path, intended_layers=GOOD) == []


def test_an_upward_dependency_is_reported_with_a_file_and_line(tmp_path):
    found = _violations(tmp_path, intended_layers=["Hal", "Svc", "App"])
    assert {(v.source, v.target) for v in found} == {("App", "Svc"), ("App", "Hal"), ("Svc", "Hal")}
    v = next(v for v in found if (v.source, v.target) == ("Svc", "Hal"))
    assert v.rule == "intended-layers" and v.kind == "layer" and v.file.endswith("svc.c") and v.line > 0
    assert "a higher layer" in v.message


def test_skipping_a_layer_is_reported_only_when_strict(tmp_path):
    assert _violations(tmp_path, intended_layers=GOOD) == []
    found = _violations(tmp_path / "strict", intended_layers=GOOD, strict_layers=True)
    assert [(v.source, v.target) for v in found] == [("App", "Hal")]


def test_a_layer_can_collect_components_by_pattern_or_domain(tmp_path):
    layers = [{"name": "top", "components": ["App"]}, {"name": "mid", "components": ["S*"]}, {"name": "low", "domains": ["hal"]}]
    assert _violations(tmp_path, intended_layers=layers, subsystems=[{"domain": "hal", "units": ["hal/*"]}]) == []


def test_every_upward_dependency_inside_a_cycle_can_be_reported(tmp_path):
    pins = PINS[:3] + [{"name": "A", "units": ["net/a.*"]}, {"name": "B", "units": ["net/b.*"]}]
    assert project(tmp_path, SOURCES, components=pins)[2].violations == []
    found = project(tmp_path / "on", SOURCES, components=pins, forbid_cycles=True)[2].violations
    assert [(v.rule, v.source, v.target) for v in found] == [("no-cycles", "B", "A")]


def test_a_rule_forbids_a_dependency_between_domains(tmp_path):
    subs = [{"domain": "ui", "units": ["app/*"]}, {"domain": "hal", "units": ["hal/*"]}]
    rule = {"id": "ui-no-hal", "from": {"domain": "ui"}, "to": {"domain": "hal"}}
    found = project(tmp_path, SOURCES, components=PINS, subsystems=subs, rules=[rule])[2].violations
    assert [(v.rule, v.source_component, v.target_component) for v in found] == [("ui-no-hal", "App", "Hal")]
    assert "call" in found[0].kinds
    only_state = dict(rule, kinds=["state"])
    assert project(tmp_path / "k", SOURCES, components=PINS, subsystems=subs, rules=[only_state])[2].violations == []


def test_allow_true_means_nothing_else_may_be_used(tmp_path):
    rule = {"id": "app-only-svc", "from": {"component": "App"}, "to": {"component": "Svc"}, "allow": True}
    found = project(tmp_path, SOURCES, components=PINS, rules=[rule])[2].violations
    assert [(v.source_component, v.target_component) for v in found] == [("App", "Hal")]


def test_a_symbol_rule_finds_the_identifier_and_its_line(tmp_path):
    files = {"hal/hal.c": "#define HAL_REG_CTRL 1\nint hal_ok(void){ return HAL_REG_CTRL; }\n",
             "app/app.c": "#define HAL_REG_DATA 2\nint app(void){\n return HAL_REG_DATA;\n}\n"}
    rule = {"id": "hal-only-registers", "from": {"not": {"component": "Hal"}}, "to": {"symbol": "*_REG_*"}}
    pins = [{"name": "App", "units": ["app/*"]}, {"name": "Hal", "units": ["hal/*"]}]
    found = project(tmp_path, files, components=pins, rules=[rule])[2].violations
    assert [(v.source_component, v.target, v.line) for v in found] == [("App", "HAL_REG_DATA", 1)]


def test_violations_become_breaches_for_the_baseline(tmp_path):
    model, config, _arch = project(tmp_path, SOURCES, components=PINS, intended_layers=["Hal", "Svc", "App"])
    mine = [b for b in compute_breaches(model, config) if b.category == "architecture"]
    assert len(mine) == 3 and all(b.kind == "rule" and b.metric == "arch-intended-layers" for b in mine)
    assert len({b.id for b in mine}) == 3 and all(b.file.endswith(".c") for b in mine)


def test_adopting_the_recovered_architecture_reports_nothing(tmp_path):
    model, config, arch = project(tmp_path, SOURCES)
    section = yaml.safe_load(adopted(arch, project_root(config)))["architecture"]
    assert {c["name"] for c in section["components"]} == {c.name for c in arch.components}
    for key in ("components", "subsystems", "intended_layers", "rules"):
        setattr(config.architecture, key, section[key])
    again = build_architecture(model, config)
    assert again.violations == []


def test_the_adopt_command_writes_a_file(tmp_path, monkeypatch):
    for name, text in SOURCES.items():
        f = tmp_path / "src" / name
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)
    (tmp_path / "config.yaml").write_text("project:\n  source_dir: .\nscope:\n  first_party: [src]\ntool:\n  target: native\n")
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(fwlens_main.cli, ["architecture", "adopt", "--config", str(tmp_path / "config.yaml")])
    assert result.exit_code == 0, result.output
    assert "intended_layers" in (tmp_path / "architecture.adopted.yaml").read_text(encoding="utf-8")


@pytest.mark.parametrize("rules,intended,message", [
    ([{"id": "x", "from": {"colour": "red"}, "to": {"domain": "ui"}}], None, "colour"),
    ([{"id": "x", "from": {"domain": "ui"}}], None, "needs 'id', 'from' and 'to'"),
    ([{"id": "x", "from": {"domain": "ui"}, "to": {"domain": "hal"}}] * 2, None, "duplicate rule id"),
    ([{"id": "x", "from": {"symbol": "a*"}, "to": {"domain": "ui"}}], None, "only valid under 'to'"),
    ([{"id": "x", "from": {"domain": "ui"}, "to": {"symbol": "a*"}, "allow": True}], None, "cannot be combined"),
    (None, [{"components": ["a"]}], "must be a name"),
])
def test_bad_rules_are_config_errors(rules, intended, message):
    with pytest.raises(ConfigError, match=message):
        validate(rules, intended)
