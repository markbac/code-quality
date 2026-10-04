"""Run history, trends in the report and the ratchet (#74)."""

import re
import sqlite3
from pathlib import Path

import pytest
from click.testing import CliRunner

import main as fwlens_main
from fwlens.baseline import Breach
from fwlens.history_db import (
    HistoryError,
    previous_accepted,
    ratchet_failures,
    recent_runs,
    record_run,
)
from tests.test_sarif_cli import BRANCHY, project


def summary(total=1, layers=0, avg=3.0):
    return {"functions": 2, "modules": 1, "total_breaches": total, "avg_complexity": avg,
            "layer_violations": layers, "flash_bytes": None, "ram_bytes": None}


def breach(i=1):
    return Breach(f"src/a.c:f:cyclomatic_complexity:{i}", "function", "src/a.c", "cyclomatic_complexity",
                  20.0, 15.0, line=1, function="f", fingerprint={"body_hash": "abc"})


def test_runs_and_findings_are_stored_with_the_shared_identity(tmp_path):
    db = tmp_path / "h.db"
    run = record_run(db, summary(2), [breach(1), breach(2)], label="v1")
    conn = sqlite3.connect(db)
    ids = {r[0] for r in conn.execute("SELECT finding_id FROM findings WHERE run_id = ?", (run,))}
    assert ids == {breach(1).id, breach(2).id}
    assert conn.execute("SELECT label, total_breaches FROM runs").fetchone() == ("v1", 2)


def test_two_runs_give_two_summaries_with_a_delta(tmp_path):
    db = tmp_path / "h.db"
    record_run(db, summary(5), [])
    record_run(db, summary(3), [])
    rows = recent_runs(db)
    assert [r["total_breaches"] for r in rows] == [5, 3]
    assert rows[1]["delta_breaches"] == -2 and "delta_breaches" not in rows[0]


def test_ratchet_fails_when_findings_rise_and_passes_when_they_fall(tmp_path):
    db = tmp_path / "h.db"
    record_run(db, summary(5, layers=1), [])
    prev = previous_accepted(db)
    assert ratchet_failures(summary(6, layers=1), prev) == ["total breaches rose from 5 to 6"]
    assert ratchet_failures(summary(5, layers=2), prev) == ["layer violations rose from 1 to 2"]
    assert ratchet_failures(summary(4, layers=0), prev) == []
    assert ratchet_failures(summary(9), None) == []


def test_a_failed_run_does_not_move_the_bar(tmp_path):
    db = tmp_path / "h.db"
    record_run(db, summary(5), [])
    record_run(db, summary(8), [], accepted=False)
    assert previous_accepted(db)["total_breaches"] == 5


def test_a_database_from_a_newer_version_is_refused(tmp_path):
    db = tmp_path / "h.db"
    record_run(db, summary(), [])
    conn = sqlite3.connect(db)
    conn.execute("PRAGMA user_version = 99")
    conn.commit()
    conn.close()
    with pytest.raises(HistoryError, match="newer FWLens"):
        recent_runs(db)


def _run(monkeypatch, tmp_path, *args):
    monkeypatch.chdir(tmp_path)
    res = CliRunner().invoke(fwlens_main.cli, list(args))
    res.text = " ".join(res.output.split())     # rich wraps long lines
    return res


def test_cli_records_runs_gates_with_the_ratchet_and_shows_the_trend(tmp_path, monkeypatch):
    cfg = project(tmp_path)
    src = tmp_path / "src" / "a.c"
    base = ["analyze", "--config", str(cfg), "--record-run", "--ratchet"]

    first = _run(monkeypatch, tmp_path, *base, "--run-label", "one")
    assert first.exit_code == 0 and "no earlier accepted run" in first.text

    src.write_text(BRANCHY + BRANCHY.replace("int f(", "int g("))       # one more breach
    worse = _run(monkeypatch, tmp_path, *base, "--run-label", "two")
    assert worse.exit_code == 1
    rose = re.search(r"total breaches rose from (\d+) to (\d+)", worse.text)
    assert rose and int(rose.group(2)) > int(rose.group(1))

    src.write_text("int f(int a) { return a; }\n")                        # all breaches fixed
    better = _run(monkeypatch, tmp_path, *base, "--run-label", "three")
    assert better.exit_code == 0 and "no worse than run #1" in better.text

    db = Path(tmp_path / "output" / "fwlens.db")
    rows = recent_runs(db)
    assert [r["label"] for r in rows] == ["one", "two", "three"]
    assert [r["accepted"] for r in rows] == [1, 0, 1]

    res = _run(monkeypatch, tmp_path, "report", "--config", str(cfg))
    assert res.exit_code == 0, res.output
    html = (tmp_path / "output" / "reports" / "fwlens_report.html").read_text(encoding="utf-8")
    assert ">Trend" in html and "this run" in html and "(not accepted)" in html


def test_ratchet_without_record_run_does_not_write_a_database(tmp_path, monkeypatch):
    cfg = project(tmp_path)
    res = _run(monkeypatch, tmp_path, "analyze", "--config", str(cfg), "--ratchet")
    assert res.exit_code == 0 and not (tmp_path / "output" / "fwlens.db").exists()
