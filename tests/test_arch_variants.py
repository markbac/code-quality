"""Architecture of two variants of one code base (#127)."""

from __future__ import annotations

import json

from click.testing import CliRunner
from test_arch_layers import PINS, SOURCES

import main as fwlens_main
from fwlens.arch import drift
from fwlens.cli import commands

VARIANT_B = {**SOURCES, "app/extra.c": '#include "../hal/hal.h"\nint extra(void){ return hal_read(); }\n',
             "hal/hal.c": '#include "hal.h"\n#include "../svc/svc.h"\nint hal_read(void){ return svc_run(); }\nint hal_raw(void){ return 2; }\n'}


def _project(root, files, extra=""):
    for name, text in files.items():
        f = root / "src" / name
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)
    cfg = root / "config.yaml"
    cfg.write_text("project:\n  source_dir: .\nscope:\n  first_party: [src]\ntool:\n  target: native\narchitecture:\n  components:\n"
                   + "".join(f"    - {{name: {p['name']}, units: {p['units']}}}\n" for p in PINS) + extra)
    return cfg


def test_two_configs_show_what_only_one_variant_has(tmp_path, monkeypatch):
    a = _project(tmp_path / "a", SOURCES)
    b = _project(tmp_path / "b", VARIANT_B)
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(fwlens_main.cli, ["architecture", "variants", "--config", str(a), "--config", str(b),
                                                  "--output", "out.json"])
    assert result.exit_code == 0, result.output
    assert "Files only in b" in result.output and "app/extra.c" in result.output
    assert "Dependencies only in b" in result.output and "Hal -> Svc" in result.output
    assert "Cycles only in b" in result.output
    data = json.loads((tmp_path / "out.json").read_text())
    assert (data["a"], data["b"]) == ("a", "b")
    assert data["differences"]["cycles_new"] == [["Hal", "Svc"]]


def test_the_same_variant_twice_has_the_same_architecture(tmp_path, monkeypatch):
    a = _project(tmp_path / "a", SOURCES)
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(fwlens_main.cli, ["architecture", "variants", "--config", str(a), "--config", str(a)])
    assert result.exit_code == 0 and "have the same architecture" in result.output


def test_one_config_and_two_configuration_names_set_the_configuration_for_each_run(tmp_path, monkeypatch):
    a = _project(tmp_path / "a", SOURCES)
    monkeypatch.chdir(tmp_path)
    seen = []
    real = commands._run_pipeline
    monkeypatch.setattr(commands, "_run_pipeline", lambda path, **kw: (seen.append(kw.get("configuration")), real(path, **kw))[1])
    result = CliRunner().invoke(fwlens_main.cli, ["architecture", "variants", "--config", str(a),
                                                  "--configuration", "G460", "--configuration", "G480"])
    assert result.exit_code == 0, result.output
    assert seen == ["G460", "G480"] and "Architecture of G460 compared with G480" in result.output


def test_the_wrong_number_of_variants_is_a_clear_error(tmp_path, monkeypatch):
    a = _project(tmp_path / "a", SOURCES)
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(fwlens_main.cli, ["architecture", "variants", "--config", str(a)])
    assert result.exit_code == 1 and "two --config files" in result.output


def test_domain_differences_are_listed():
    old = {"components": [{"name": "X", "units": ["x.c"], "domain": "comms", "level": 0}], "edges": [], "cycles": [],
           "violations": [], "leaks": [], "patterns": []}
    new = {**old, "components": [{"name": "X", "units": ["x.c"], "domain": "ui", "level": 0}]}
    report = drift.diff(old, new)
    assert report["domain_changes"] == [{"component": "X", "before": "comms", "after": "ui"}]
    assert any("X: comms (a) -> ui (b)" in line for line in drift.variant_lines(report, "a", "b"))
