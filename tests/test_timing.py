"""Run timing: phases and the slowest files, printed at the end, kept in the JSON export and the report."""

from __future__ import annotations

import io
import json
import time

import pytest
from click.testing import CliRunner
from rich.console import Console

import main as fwlens_main
from fwlens.timing import Phase, RunTimer


def test_phases_nest_in_start_order_and_add_up():
    t = RunTimer()
    with t.phase("outer"):
        with t.phase("inner", "3 files"):
            time.sleep(0.02)
        time.sleep(0.01)
    with t.phase("after"):
        pass
    assert [(p.name, p.depth) for p in t.phases] == [("outer", 0), ("inner", 1), ("after", 0)]
    outer, inner = t.phases[0], t.phases[1]
    assert inner.seconds >= 0.02 and outer.seconds >= inner.seconds + 0.01 and inner.detail == "3 files"


def test_a_phase_that_raises_still_closes():
    t = RunTimer()
    with pytest.raises(ValueError):
        with t.phase("boom"):
            raise ValueError
    with t.phase("next"):
        pass
    assert [p.depth for p in t.phases] == [0, 0] and t.phases[0].seconds >= 0


def test_the_table_hides_short_phases_and_lists_slow_files():
    t = RunTimer()
    t.phases.extend([Phase("Parse", 0, 8.0), Phase("Child", 1, 7.0), Phase("Tiny", 0, 0.001)])
    t.note_files({"a.c": 5.0, "b.c": 0.2, "c.c": 3.0})
    out = io.StringIO()
    t.render(Console(file=out, width=100))
    text = out.getvalue()
    assert "Parse" in text and "  Child" in text and "Tiny" not in text and "1 shorter phases" in text
    assert text.index("a.c") < text.index("c.c") and "b.c" not in text            # slowest first, under a second dropped
    assert t.as_dict()["slowest_files"][0] == {"file": "a.c", "seconds": 5.0}


@pytest.fixture
def run(tmp_path, monkeypatch):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.c").write_text("int main(void) { return 0; }\n")

    def go(extra=""):
        cfg = tmp_path / "config.yaml"
        cfg.write_text("project:\n  source_dir: .\nscope:\n  first_party: [src]\ntool:\n  target: native\n"
                       "output:\n  formats: [html, json]\n" + extra)
        monkeypatch.chdir(tmp_path)
        result = CliRunner().invoke(fwlens_main.cli, ["report", "--config", str(cfg)])
        assert result.exit_code == 0, result.output
        return result.output, tmp_path
    return go


def test_a_report_run_prints_where_the_time_went_and_keeps_it(run):
    output, root = run()
    assert "Run time" in output and "Parse project" in output          # phases under 0.05s are summed, so only big ones show
    timing = json.loads((root / "output" / "exports" / "fwlens_results.json").read_text(encoding="utf-8"))["meta"]["timing"]
    names = [p["phase"] for p in timing["phases"]]
    assert {"Parse project", "Read project description", "Parse source files", "Call graph", "Aggregate metrics"} <= set(names)
    assert names.index("Parse project") < names.index("Call graph")
    assert next(p for p in timing["phases"] if p["phase"] == "Read project description")["depth"] == 1
    assert timing["total_seconds"] > 0 and timing["slowest_files"][0]["file"].endswith("main.c")
    html = (root / "output" / "reports" / "fwlens_report.html").read_text(encoding="utf-8")
    assert "Run time so far" in html


def test_the_table_can_be_switched_off(run):
    output, _ = run("  show_timing: false\n")
    assert "Run time" not in output and "Analysis complete" in output
