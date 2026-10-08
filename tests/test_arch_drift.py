"""Architecture drift against a saved baseline or an earlier revision (#126)."""

from __future__ import annotations

import json
import subprocess

from arch_helpers import project
from click.testing import CliRunner
from test_arch_layers import PINS, SOURCES

import main as fwlens_main
from fwlens.arch import build_architecture, drift
from fwlens.identity import project_root


def _snap(tmp_path, sources=SOURCES, pins=PINS, **cfg):
    model, config, arch = project(tmp_path, sources, components=pins, **cfg)
    return drift.snapshot(arch, project_root(config)), model, config, arch


def test_nothing_changed(tmp_path):
    a = _snap(tmp_path / "a")[0]
    b = _snap(tmp_path / "b")[0]
    report = drift.diff(a, b)
    assert drift.lines(report) == ["No architectural change."] and not report["worse"]


def test_a_new_dependency_and_a_new_cycle_are_reported(tmp_path):
    old = _snap(tmp_path / "old")[0]
    changed = {**SOURCES, "hal/hal.c": '#include "hal.h"\n#include "../svc/svc.h"\nint hal_read(void){ return svc_run(); }\nint hal_raw(void){ return 2; }\n'}
    new = _snap(tmp_path / "new", changed)[0]
    report = drift.diff(old, new)
    assert report["worse"]
    assert {(e["source"], e["target"]) for e in report["edges_added"]} == {("Hal", "Svc")}
    assert report["cycles_new"] == [["Hal", "Svc"]]
    assert any(t["component"] == "Hal" and t["change"] > 0 for t in report["coupling_trend"])
    assert any("New cycles" in line for line in drift.lines(report))


def test_a_renamed_component_is_matched_by_its_files_not_its_name(tmp_path):
    old = _snap(tmp_path / "old")[0]
    pins = [dict(p, name=p["name"] + "X") if p["name"] == "App" else p for p in PINS]
    report = drift.diff(old, _snap(tmp_path / "new", pins=pins)[0])
    assert report["renamed"] == [["App", "AppX"]]
    assert report["components_added"] == [] and report["components_removed"] == []
    assert report["edges_added"] == [] and report["edges_removed"] == []


def test_a_file_moving_between_components_and_a_removed_component(tmp_path):
    more = {**SOURCES, "hal/extra.c": "int extra(void){ return 1; }\n", "hal/extra2.c": "int extra2(void){ return 2; }\n"}
    old = _snap(tmp_path / "old", more)[0]
    pins = [PINS[0], {"name": "Svc", "units": ["svc/*", "hal/extra2.c"]}, {"name": "Hal", "units": ["hal/*"]}, PINS[3]]
    report = drift.diff(old, _snap(tmp_path / "new", more, pins)[0])
    assert [(m["unit"], m["from"], m["to"]) for m in report["units_moved"]] == [("hal/extra2.c", "Hal", "Svc")]
    removed = _snap(tmp_path / "gone", {k: v for k, v in SOURCES.items() if not k.startswith("net/")})[0]
    assert "Net" in drift.diff(old, removed)["components_removed"]


def test_new_violations_and_leaks_are_listed(tmp_path):
    old = _snap(tmp_path / "old")[0]
    new = _snap(tmp_path / "new", intended_layers=["Hal", "Svc", "App"])[0]
    report = drift.diff(old, new)
    assert report["violations_new"] and report["worse"]
    assert drift.diff(new, old)["violations_resolved"] == report["violations_new"]


def test_a_baseline_in_the_config_fills_the_comparison_and_a_bad_file_is_an_error(tmp_path):
    snap, model, config, _arch = _snap(tmp_path)
    saved = tmp_path / "base.json"
    saved.write_text(json.dumps(snap))
    config.architecture.baseline = saved
    assert build_architecture(model, config).since_baseline["cycles_new"] == []
    saved.write_text("not json")
    assert "architecture baseline" in build_architecture(model, config).since_baseline["error"]
    config.architecture.baseline = tmp_path / "missing.json"
    assert "missing.json" in build_architecture(model, config).since_baseline["error"]


def _write(tmp_path, files):
    for name, text in files.items():
        f = tmp_path / "src" / name
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)
    (tmp_path / "config.yaml").write_text(
        "project:\n  source_dir: .\nscope:\n  first_party: [src]\ntool:\n  target: native\narchitecture:\n  components:\n"
        + "".join(f"    - {{name: {p['name']}, units: {p['units']}}}\n" for p in PINS))
    return tmp_path / "config.yaml"


def test_save_then_diff_from_the_command_line(tmp_path, monkeypatch):
    cfg = _write(tmp_path, SOURCES)
    monkeypatch.chdir(tmp_path)
    run = CliRunner().invoke
    assert run(fwlens_main.cli, ["architecture", "save", "--config", str(cfg), "--output", "base.json"]).exit_code == 0
    same = run(fwlens_main.cli, ["architecture", "diff", "--config", str(cfg), "--baseline", "base.json", "--fail-on-new"])
    assert same.exit_code == 0 and "No architectural change." in same.output
    _write(tmp_path, {"hal/hal.c": '#include "hal.h"\n#include "../svc/svc.h"\nint hal_read(void){ return svc_run(); }\nint hal_raw(void){ return 2; }\n'})
    worse = run(fwlens_main.cli, ["architecture", "diff", "--config", str(cfg), "--baseline", "base.json",
                                  "--fail-on-new", "--output", "diff.json"])
    assert worse.exit_code == 1 and "New cycles" in worse.output
    assert json.loads((tmp_path / "diff.json").read_text())["cycles_new"] == [["Hal", "Svc"]]


def test_diff_with_nothing_to_compare_with_is_a_clear_error(tmp_path, monkeypatch):
    cfg = _write(tmp_path, SOURCES)
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(fwlens_main.cli, ["architecture", "diff", "--config", str(cfg)])
    assert result.exit_code == 1 and "--baseline or --revision" in result.output


def test_diff_against_a_git_revision(tmp_path, monkeypatch):
    cfg = _write(tmp_path, SOURCES)
    git = ["git", "-C", str(tmp_path), "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"]
    subprocess.run([*git, "init", "-q"], check=True, capture_output=True)
    subprocess.run([*git, "add", "-A"], check=True, capture_output=True)
    subprocess.run([*git, "commit", "-q", "-m", "one"], check=True, capture_output=True)
    _write(tmp_path, {"hal/hal.c": '#include "hal.h"\n#include "../svc/svc.h"\nint hal_read(void){ return svc_run(); }\nint hal_raw(void){ return 2; }\n'})
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(fwlens_main.cli, ["architecture", "diff", "--config", str(cfg), "--revision", "HEAD"])
    assert result.exit_code == 0, result.output
    assert "compared with revision HEAD" in result.output and "New cycles" in result.output
