"""
Regression tests for the P0 bugs: #23 (CLI crash), #46 (CC inflation), #47 (HTML layout).
"""

from html.parser import HTMLParser
from pathlib import Path

import pytest
from click.testing import CliRunner

import cparse
import main as fwlens_main
from fwlens.config import FwLensConfig, OutputConfig, ProjectConfig, ScopeConfig, ThresholdConfig, ToolConfig


def _config(tmp_path: Path, formats=("json",)) -> FwLensConfig:
    return FwLensConfig(
        config_path=tmp_path / "config.yaml",
        tool=ToolConfig(libclang_path=None),
        project=ProjectConfig(
            ewp=None, configuration="Debug", proj_dir=tmp_path, toolkit_dir=None,
            mode="directory", source_dir=tmp_path,
        ),
        scope=ScopeConfig(first_party=["."], sdk=[], third_party_lib=[], analyse=["first_party"]),
        iar_compat_defines=[],
        layers=[],
        thresholds=ThresholdConfig(),
        output=OutputConfig(
            reports_dir=tmp_path / "output" / "reports",
            exports_dir=tmp_path / "output" / "exports",
            cache_dir=tmp_path / "output" / ".cache",
            db_path=tmp_path / "output" / "fwlens.db",
            formats=list(formats),
        ),
        entry_points=["main"],
    )


# --- #23: analyze/report must accept --github-annotations ---------------------

@pytest.mark.parametrize("command", ["analyze", "report"])
def test_github_annotations_flag_reaches_baseline_handler(command, tmp_path, monkeypatch):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text("project:\n  source_dir: .\n")
    seen = {}

    monkeypatch.setattr("fwlens.cli.commands._run_pipeline", lambda *a, **k: ("model", _config(tmp_path, formats=())))
    monkeypatch.setattr("fwlens.output.console.print_summary", lambda *a, **k: None)
    monkeypatch.setattr("fwlens.cli.commands._handle_baseline", lambda *a, **k: seen.update(k) or False)

    result = CliRunner().invoke(fwlens_main.cli, [command, "--config", str(cfg_file), "--github-annotations"])

    assert result.exit_code == 0, result.output
    assert seen["github_annotations"] is True


# --- #46: complexity must not be inflated by chained or macro operators --------

_parse_functions = cparse.parse_functions


def test_cyclomatic_complexity_counts_each_logical_operator_once(tmp_path):
    funcs = _parse_functions(tmp_path, """
#define MK(a, b) (((a) << 20) | ((b) << 10))
int chain(int a, int b, int c, int d) { return a && b && c && d; }
int mixed(int a, int b, int c) { if ((a || b) && c) { return 1; } return 0; }
int macro_bits(int a, int b) { return MK(a, b); }
""")
    assert funcs["chain"].cyclomatic_complexity == 4      # 1 + three &&
    assert funcs["mixed"].cyclomatic_complexity == 4      # 1 + if + || + &&
    assert funcs["macro_bits"].cyclomatic_complexity == 1  # bitwise macro adds nothing


def test_issue_46_reproduction(tmp_path):
    """The literal reproduction from #46: a macro, 30 padding functions, then the function under test."""
    pads = "\n".join(
        f"int pad{i}(int a, int b, int c) {{ if (a && b && c) {{ return 1; }} if (a || b) {{ return 2; }} return 0; }}"
        for i in range(30))
    funcs = _parse_functions(tmp_path, f"""
#define MK(a,b) (((a) << 20) | ((b) << 10))

{pads}

int target(int x, int y) {{
  int r = MK(x, y);
  if (x) {{ r++; }}
  return r;
}}
""")
    assert funcs["target"].cyclomatic_complexity == 2
    assert funcs["pad0"].cyclomatic_complexity == 6
    assert funcs["pad29"].cyclomatic_complexity == 6


# --- #47: every Overview/cheat-sheet div must be balanced ----------------------

class _DivBalance(HTMLParser):
    def __init__(self):
        super().__init__()
        self.depth = 0
        self.min_depth = 0

    def handle_starttag(self, tag, attrs):
        if tag == "div":
            self.depth += 1

    def handle_endtag(self, tag):
        if tag == "div":
            self.depth -= 1
            self.min_depth = min(self.min_depth, self.depth)


def test_html_report_divs_are_balanced(tmp_path):
    from fwlens.model.project import ProjectModel
    from fwlens.output.html_report import generate_html_report

    config = _config(tmp_path, formats=("html",))
    path = generate_html_report(ProjectModel(ewp_path=tmp_path / "x.ewp", configuration="Debug"), config)
    checker = _DivBalance()
    checker.feed(Path(path).read_text(encoding="utf-8"))
    assert checker.min_depth >= 0, "a </div> closed more than was opened"
    assert checker.depth == 0, "unbalanced <div> tags"
