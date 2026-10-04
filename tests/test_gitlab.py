"""
GitLab Code Quality output and the reporter abstraction (#30).
"""

import json
from pathlib import Path

import pytest
import yaml

from fwlens.baseline import Breach
from fwlens.output.reporters import (
    GitHubReporter, GitLabReporter, default_gitlab_report_path, fingerprint_for, running_on_gitlab,
    severity_for, to_codequality,
)

REQUIRED = {"description", "check_name", "fingerprint", "severity", "location"}
SEVERITIES = {"info", "minor", "major", "critical", "blocker"}


def make(file="src/a.c", function="f", metric="cyclomatic_complexity", value=20.0, threshold=15.0, line=7):
    return Breach(f"{file}:{function}:{metric}", "function", file, metric, value, threshold,
                  line=line, function=function)


def validate(entries):
    """Structural check against the documented Code Quality fields."""
    assert isinstance(entries, list)
    for e in entries:
        assert REQUIRED <= set(e)
        assert e["severity"] in SEVERITIES
        assert isinstance(e["fingerprint"], str) and e["fingerprint"]
        assert isinstance(e["location"]["path"], str) and "\\" not in e["location"]["path"]
        assert isinstance(e["location"]["lines"]["begin"], int) and e["location"]["lines"]["begin"] >= 1
    assert len({e["fingerprint"] for e in entries}) == len(entries)


def test_codequality_entries_match_the_documented_shape():
    entries = to_codequality([make(), make(function="g", metric="fan_out", value=30, threshold=10)])
    validate(entries)
    assert entries[0]["check_name"] == "fwlens/cyclomatic_complexity"
    assert entries[0]["location"] == {"path": "src/a.c", "lines": {"begin": 7}}
    assert "in f" in entries[0]["description"]


def test_fingerprint_ignores_the_line_number():
    assert fingerprint_for(make(line=7)) == fingerprint_for(make(line=400))
    assert fingerprint_for(make(function="f")) != fingerprint_for(make(function="g"))


def test_windows_style_path_and_line_are_kept():
    b = Breach("C:/proj/src/a.c:f:cyclomatic_complexity", "function", "C:/proj/src/a.c",
               "cyclomatic_complexity", 20, 15, line=42, function="f")
    entry = to_codequality([b])[0]
    assert entry["location"] == {"path": "C:/proj/src/a.c", "lines": {"begin": 42}}


def test_module_breach_without_a_line_starts_at_line_one():
    b = Breach("src/a.c:main_sequence_distance", "module", "src/a.c", "main_sequence_distance", 0.9, 0.5)
    assert to_codequality([b])[0]["location"]["lines"]["begin"] == 1


@pytest.mark.parametrize("value, expected", [(16, "minor"), (20, "major"), (31, "critical")])
def test_severity_follows_how_far_over_the_threshold(value, expected):
    assert severity_for(make(value=value, threshold=15)) == expected


def test_note_level_metrics_are_one_step_quieter():
    assert severity_for(make(metric="fan_out", value=11, threshold=10)) == "info"
    assert severity_for(make(metric="fan_out", value=25, threshold=10)) == "major"


def test_zero_threshold_does_not_divide_by_zero():
    assert severity_for(make(value=1, threshold=0)) == "critical"


def test_gitlab_reporter_writes_valid_json(tmp_path):
    path = GitLabReporter().emit([make(), make(function="g")], tmp_path / "out" / "gl-code-quality-report.json")
    entries = json.loads(path.read_text())
    validate(entries)
    assert len(entries) == 2


def test_empty_report_is_an_empty_array(tmp_path):
    path = GitLabReporter().emit([], tmp_path / "r.json")
    assert json.loads(path.read_text()) == []


def test_github_reporter_prints_workflow_commands(capsys):
    GitHubReporter().emit([make()])
    assert capsys.readouterr().out.startswith("::warning file=src/a.c,line=7,title=FWLens Breach [cyclomatic_complexity]::")


def test_gitlab_environment_detection(monkeypatch, tmp_path):
    monkeypatch.delenv("GITLAB_CI", raising=False)
    assert running_on_gitlab() is False
    monkeypatch.setenv("GITLAB_CI", "true")
    assert running_on_gitlab() is True
    monkeypatch.setenv("CI_PROJECT_DIR", str(tmp_path))
    assert default_gitlab_report_path() == tmp_path / "gl-code-quality-report.json"


def test_project_root_prefers_ci_project_dir(monkeypatch, tmp_path):
    from types import SimpleNamespace
    from fwlens.identity import project_root
    monkeypatch.setenv("CI_PROJECT_DIR", str(tmp_path))
    cfg = SimpleNamespace(project=SimpleNamespace(source_dir=Path("/x"), proj_dir=Path("/x")),
                          config_path=Path("/x/config.yaml"))
    assert project_root(cfg) == tmp_path


def test_ci_template_is_valid_yaml_and_publishes_the_report():
    template = Path(__file__).resolve().parent.parent / "ci" / "gitlab" / "fwlens.gitlab-ci.yml"
    job = yaml.safe_load(template.read_text())[".fwlens"]
    assert job["artifacts"]["reports"]["codequality"] == "gl-code-quality-report.json"
    assert job["artifacts"]["when"] == "always"
    assert any("fwlens analyze" in line for line in job["script"])
