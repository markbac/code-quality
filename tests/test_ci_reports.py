"""JUnit XML and Markdown summary from analyze/report (#76)."""

from pathlib import Path

import pytest

from fwlens.baseline import Breach
from fwlens.output.reporters import markdown_summary, to_junit
from tests.test_sarif_cli import project, run

XSD = Path(__file__).parent / "fixtures" / "junit-10.xsd"


def validate(xml_text: str) -> None:
    etree = pytest.importorskip("lxml.etree")
    schema = etree.XMLSchema(etree.parse(str(XSD)))
    doc = etree.fromstring(xml_text.encode("utf-8"))
    schema.assertValid(doc)


def breach(file="src/a.c", function="f", metric="cyclomatic_complexity", value=21.0, line=1):
    return Breach(f"{file}:{function}:{metric}", "function", file, metric, value, 15.0, line=line, function=function)


def test_junit_validates_against_the_schema_with_findings():
    xml = to_junit([breach(), breach(function="g", line=30), breach(file="src/b.c", metric="fan_out", value=40.0),
                    breach(function='h<&">', line=60)])
    validate(xml)
    assert xml.count("<failure ") == 4 and xml.count("<testsuite ") == 2
    assert 'failures="4"' in xml


def test_junit_for_a_clean_run_is_one_passing_case():
    xml = to_junit([])
    validate(xml)
    assert "<failure" not in xml and 'name="no findings"' in xml


def test_junit_covers_module_and_rule_findings():
    module = Breach("m", "module", "src/a.c", "main_sequence_distance", 0.9, 0.3)
    rule = Breach("r", "rule", "src/a.c", "misra-15.1", 1.0, 0.0, line=4, function="f",
                  category="required", description="goto used")
    xml = to_junit([module, rule])
    validate(xml)
    assert "&lt;module&gt;" in xml and "goto used" in xml


def test_markdown_summary_lists_counts_and_largest_findings():
    md = markdown_summary([breach(value=60.0), breach(function="g", value=16.0)], functions=10, modules=3, max_items=1)
    assert "2 finding(s) across 10 function(s) and 3 module(s)" in md
    assert "| cyclomatic_complexity | 2 |" in md and "1 more not shown" in md and "60" in md
    assert "0 finding(s)" in markdown_summary([], functions=1, modules=1)


@pytest.mark.parametrize("command", ["analyze", "report"])
def test_cli_writes_junit_and_summary_without_a_pr_context(command, tmp_path, monkeypatch):
    cfg = project(tmp_path)
    for var in ("GITHUB_ACTIONS", "GITLAB_CI", "GITHUB_STEP_SUMMARY"):
        monkeypatch.delenv(var, raising=False)
    res = run(monkeypatch, tmp_path, command, "--config", str(cfg), "--junit", "out/junit.xml",
              "--markdown-summary", "out/summary.md")
    assert res.exit_code == 0, res.output
    validate((tmp_path / "out" / "junit.xml").read_text(encoding="utf-8"))
    assert "<failure" in (tmp_path / "out" / "junit.xml").read_text(encoding="utf-8")
    assert "## FWLens analysis" in (tmp_path / "out" / "summary.md").read_text(encoding="utf-8")


def test_step_summary_is_appended_not_overwritten(tmp_path, monkeypatch):
    cfg = project(tmp_path)
    target = tmp_path / "step.md"
    target.write_text("earlier step\n")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(target))
    res = run(monkeypatch, tmp_path, "analyze", "--config", str(cfg), "--markdown-summary", str(target))
    assert res.exit_code == 0, res.output
    text = target.read_text()
    assert text.startswith("earlier step") and "## FWLens analysis" in text
