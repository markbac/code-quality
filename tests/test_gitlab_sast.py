"""GitLab SAST report for coding-standard findings (#91)."""

import json

from click.testing import CliRunner

import main as fwlens_main
from fwlens.baseline import compute_breaches
from fwlens.config import StandardSelection
from fwlens.output.gitlab_sast import SEVERITY, to_sast, write_sast_report
from tests.test_standards import enable, parsed  # noqa: F401  (fixture)


def _report(parsed, **selection):  # noqa: F811
    model, config, _ = parsed
    enable(config, StandardSelection("misra-c-2012", include_ids=["15.1"]))
    model._standards_result = None
    breaches = compute_breaches(model, config)
    return model, breaches, to_sast(model, breaches)


def test_rule_findings_become_vulnerabilities_with_a_severity_from_the_category(parsed):  # noqa: F811
    _m, breaches, report = _report(parsed)
    (finding,) = [b for b in breaches if b.kind == "rule"]
    (v,) = report["vulnerabilities"]
    assert report["version"].startswith("15.") and report["scan"]["type"] == "sast" and report["scan"]["status"] == "success"
    assert v["severity"] == SEVERITY[finding.category]
    assert v["location"] == {"file": finding.file, "start_line": finding.line}
    assert v["identifiers"][0]["type"] == "misra-c-2012" and v["identifiers"][0]["value"] == "15.1"


def test_ids_are_stable_between_runs(parsed):  # noqa: F811
    _m, _b, first = _report(parsed)
    assert first["vulnerabilities"][0]["id"] == _report(parsed)[2]["vulnerabilities"][0]["id"]


def test_metric_breaches_and_deviated_findings_are_left_out(parsed):  # noqa: F811
    model, breaches, _r = _report(parsed)
    deviated = [b for b in breaches]
    for b in deviated:
        b.deviation = "DEV-1"
    assert to_sast(model, deviated)["vulnerabilities"] == []


def test_the_report_is_written_as_json(parsed, tmp_path):  # noqa: F811
    model, breaches, _r = _report(parsed)
    path = write_sast_report(model, breaches, tmp_path / "out" / "gl-sast-report.json")
    assert json.loads(path.read_text())["vulnerabilities"]


def test_the_option_exists_on_analyze_and_report():
    for command in ("analyze", "report"):
        assert "--gitlab-sast" in CliRunner().invoke(fwlens_main.cli, [command, "--help"]).output
