"""SARIF output reachable from the CLI and valid against the 2.1.0 schema (#79)."""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

import main as fwlens_main

SCHEMA = Path(__file__).parent / "fixtures" / "sarif-schema-2.1.0.json"

# One function over the default cyclomatic complexity threshold of 15, so there is a finding.
BRANCHY = "int f(int a) {\n" + "".join(f"  if (a == {i}) {{ return {i}; }}\n" for i in range(20)) + "  return 0;\n}\n"


def project(tmp_path, formats=None):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.c").write_text(BRANCHY)
    config = "project:\n  source_dir: src\ntool:\n  target: native\n"
    if formats:
        config += f"output:\n  formats: {formats}\n"
    (tmp_path / "config.yaml").write_text(config)
    return tmp_path / "config.yaml"


def run(monkeypatch, tmp_path, *args):
    monkeypatch.chdir(tmp_path)
    return CliRunner().invoke(fwlens_main.cli, list(args))


def validate(path):
    jsonschema = pytest.importorskip("jsonschema")
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    jsonschema.validate(document, json.loads(SCHEMA.read_text(encoding="utf-8")))
    return document


@pytest.mark.parametrize("command", ["analyze", "report", "export"])
def test_sarif_option_writes_a_valid_file(command, tmp_path, monkeypatch):
    cfg = project(tmp_path, formats="[json]")
    out = tmp_path / "out" / "result.sarif"
    result = run(monkeypatch, tmp_path, command, "--config", str(cfg), "--sarif", str(out))
    assert result.exit_code == 0, result.output
    document = validate(out)
    results = document["runs"][0]["results"]
    assert any(r["ruleId"] == "FWLENS-CYCLOMATIC_COMPLEXITY" for r in results)
    declared = {r["id"] for r in document["runs"][0]["tool"]["driver"]["rules"]}
    assert {r["ruleId"] for r in results} <= declared


def test_sarif_in_formats_writes_the_file_from_report(tmp_path, monkeypatch):
    cfg = project(tmp_path, formats="[sarif]")
    result = run(monkeypatch, tmp_path, "report", "--config", str(cfg))
    assert result.exit_code == 0, result.output
    validate(tmp_path / "output" / "exports" / "fwlens.sarif")


def test_misspelt_format_is_rejected(tmp_path, monkeypatch):
    cfg = project(tmp_path, formats="[sarfi]")
    result = run(monkeypatch, tmp_path, "report", "--config", str(cfg))
    assert result.exit_code != 0
    assert "sarfi" in result.output
