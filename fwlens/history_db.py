"""
Run history (#74): a small SQLite file with one summary per run and the findings of each run,
keyed by the shared finding identity (fwlens.identity), so trends and the ratchet speak the same
language as baselines and `compare`.

The file is `output.db_path`. It is a single file with no server and no write-ahead log, so it
can be kept as a CI artefact or cache between runs; restore it before the run, upload it after.
"""

from __future__ import annotations

import json
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = 1

_SUMMARY_COLUMNS = ("functions", "modules", "total_breaches", "avg_complexity", "layer_violations",
                    "flash_bytes", "ram_bytes")
# Metrics the ratchet watches: a run is worse when any of them goes up.
RATCHET_METRICS = ("total_breaches", "layer_violations")


class HistoryError(RuntimeError):
    pass


def _connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = DELETE")   # one file, safe to copy
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version > SCHEMA_VERSION:
        conn.close()
        raise HistoryError(f"{path} was written by a newer FWLens (schema {version}, this one reads "
                           f"{SCHEMA_VERSION}). Upgrade FWLens or use another output.db_path.")
    if version < SCHEMA_VERSION:
        conn.executescript("""
            CREATE TABLE runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recorded_at TEXT NOT NULL,
                label TEXT,
                commit_sha TEXT,
                accepted INTEGER NOT NULL DEFAULT 1,
                functions INTEGER, modules INTEGER, total_breaches INTEGER,
                avg_complexity REAL, layer_violations INTEGER,
                flash_bytes INTEGER, ram_bytes INTEGER
            );
            CREATE TABLE findings (
                run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
                finding_id TEXT NOT NULL,
                kind TEXT, file TEXT, metric TEXT, value REAL, threshold REAL, fingerprint TEXT
            );
            CREATE INDEX findings_run ON findings(run_id);
        """)
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        conn.commit()
    return conn


def summarise(model, breaches) -> dict:
    """The numbers stored per run."""
    funcs = model.first_party_functions()
    footprint = getattr(model, "footprint", None) or {}
    return {
        "functions": len(funcs),
        "modules": len(model.first_party_modules()),
        "total_breaches": len(breaches),
        "avg_complexity": round(sum(f.cyclomatic_complexity for f in funcs) / len(funcs), 2) if funcs else 0.0,
        "layer_violations": len(model.arch_violations),
        "flash_bytes": footprint.get("flash_bytes"),
        "ram_bytes": footprint.get("ram_bytes"),
    }


def _head_commit(root: Path) -> str | None:
    try:
        out = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return out.stdout.decode().strip() or None if out.returncode == 0 else None


def record_run(db_path: Path, summary: dict, breaches, *, label: str | None = None,
               accepted: bool = True, root: Path | None = None) -> int:
    """Store one run. `accepted=False` keeps a failed ratchet run on record without moving the bar."""
    conn = _connect(db_path)
    try:
        with conn:
            cur = conn.execute(
                "INSERT INTO runs (recorded_at, label, commit_sha, accepted, "
                + ", ".join(_SUMMARY_COLUMNS) + ") VALUES (?, ?, ?, ?, " + ", ".join("?" * len(_SUMMARY_COLUMNS)) + ")",
                (datetime.now(timezone.utc).isoformat(timespec="seconds"), label,
                 _head_commit(root) if root else None, int(accepted), *[summary.get(c) for c in _SUMMARY_COLUMNS]))
            run_id = cur.lastrowid
            assert run_id is not None
            conn.executemany(
                "INSERT INTO findings (run_id, finding_id, kind, file, metric, value, threshold, fingerprint) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                [(run_id, b.id, b.kind, b.file, b.metric, b.value, b.threshold,
                  json.dumps(b.fingerprint) if b.fingerprint else None) for b in breaches])
        return run_id
    finally:
        conn.close()


def previous_accepted(db_path: Path) -> dict | None:
    """The most recent run that passed the ratchet (or was recorded without one)."""
    if not Path(db_path).exists():
        return None
    conn = _connect(db_path)
    try:
        row = conn.execute("SELECT * FROM runs WHERE accepted = 1 ORDER BY id DESC LIMIT 1").fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def ratchet_failures(current: dict, previous: dict | None) -> list[str]:
    """Messages for each tracked metric that is worse than in the previous accepted run."""
    if previous is None:
        return []
    out = []
    for metric in RATCHET_METRICS:
        before, now = previous.get(metric), current.get(metric)
        if before is not None and now is not None and now > before:
            out.append(f"{metric.replace('_', ' ')} rose from {before} to {now}")
    return out


def recent_runs(db_path: Path, limit: int = 10) -> list[dict]:
    """The last `limit` runs, oldest first, each with `delta_breaches` against the run before it."""
    if not Path(db_path).exists():
        return []
    conn = _connect(db_path)
    try:
        rows = [dict(r) for r in conn.execute("SELECT * FROM runs ORDER BY id DESC LIMIT ?", (limit + 1,))]
    finally:
        conn.close()
    rows.reverse()
    for before, now in zip(rows, rows[1:]):
        now["delta_breaches"] = (now["total_breaches"] or 0) - (before["total_breaches"] or 0)
    return rows[-limit:] if len(rows) > limit else rows
