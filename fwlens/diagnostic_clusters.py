"""
Diagnostic clustering for fwlens.

When many unrelated files hit the exact same parse diagnostic at the exact same line
number, that's not N independent problems -- it's one shared root cause (a missing
compiler-compat define, a broken header, an unresolved macro) whose parse-failure
recovery point happens to land at the same spot in every affected file. This has been the
single most time-consuming pattern to debug across every parse-diagnostics session on this
project so far: the diagnostic text itself ("unknown type name 'FI_NUM_FILES'", "type
specifier missing") rarely names the real cause, only where the parser gave up and
resynchronised, and confirming the theory previously meant a full round trip -- export the
CSV, grep it, ask what's actually on that line, wait for the file to be pasted back.

This module closes that loop automatically: cluster diagnostics by (message shape, actual
physical file, line) -- not just line number, since libclang tracks the true location
precisely, including inside an #included header, and the file that error is *reported
against* (the .c translation unit) is very often not the file it actually occurred in.
Grouping by line alone would risk merging coincidentally-matching lines from unrelated
files' own content with a genuine shared-header cluster, and reading context from the
wrong file (an earlier version of this module did exactly that) shows source that has
nothing to do with the real problem. For any cluster large enough to be a shared cause
rather than coincidence, this reads the actual source at that location from disk (fwlens
already has the real files in front of it during a normal run, unlike a chat session
working from a pasted CSV) and surfaces it directly in the console/HTML output. "108 files
hit this" becomes "108 files hit this -- here's the line, in the header it's really in"
without needing to ask.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from fwlens.model.project import ProjectModel

# Only surface a cluster if it spans at least this many distinct files -- below this,
# it's more likely to be a handful of genuinely separate problems than one shared cause,
# and isn't worth displacing space that could go to a real cluster.
_MIN_CLUSTER_FILES = 5
_CONTEXT_RADIUS = 3  # lines of source shown above/below the flagged line

_QUOTED_RE = re.compile(r"'[^']*'")


@dataclass
class DiagnosticCluster:
    message_pattern: str   # e.g. "unknown type name '…'" -- quoted identifiers collapsed
    line: int
    file_count: int
    sample_tu: Path         # the .c translation unit the sample diagnostic was reported for
    sample_file: Path       # where the diagnostic actually occurred -- may be a header
                             # #included by sample_tu, not sample_tu itself
    sample_message: str    # the actual message from the sample file, quotes intact
    context: list[tuple[int, str]] = field(default_factory=list)  # (line_no, source_line)


def _normalise(msg: str) -> str:
    """Collapse quoted identifiers so the same underlying diagnostic from different
    files/names groups into one cluster, e.g. "unknown type name 'FOO'" and "unknown type
    name 'BAR'" both become "unknown type name '…'"."""
    return _QUOTED_RE.sub("'…'", msg)


def _read_context(path: Path, line: int) -> list[tuple[int, str]]:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    if line <= 0 or line > len(lines):
        return []
    start = max(0, line - 1 - _CONTEXT_RADIUS)
    end = min(len(lines), line + _CONTEXT_RADIUS)
    return [(i + 1, lines[i]) for i in range(start, end)]


def compute_diagnostic_clusters(model: ProjectModel) -> list[DiagnosticCluster]:
    """
    Populate model.diagnostic_clusters: parse-diagnostic patterns shared across at least
    _MIN_CLUSTER_FILES distinct translation units at the same line, sorted by file count
    descending, each with source context read from wherever the diagnostic actually
    occurred -- which is frequently a shared header pulled in by every affected TU, not
    any of the TUs themselves. Grouping and reading context by (message, line) *without*
    also distinguishing which physical file that line belongs to would silently show the
    wrong source whenever the real location is a header: many unrelated .c files can
    legitimately share the same line number in their own content by coincidence, but what
    actually makes them a genuine cluster is landing on the same line of the *same*
    header, which is why in_file is part of the grouping key, not just line.

    Cheap -- this is pure aggregation over diagnostics already collected during parsing,
    plus a handful of small file reads for context (bounded by however many clusters clear
    the threshold, not by total diagnostic count).
    """
    groups: dict[tuple[str, str, int], set[Path]] = defaultdict(set)
    sample_message: dict[tuple[str, str, int], str] = {}
    sample_tu: dict[tuple[str, str, int], Path] = {}

    for m in model.modules:
        for diag in m.parse_diagnostics:
            msg = diag.get("message", "")
            line = diag.get("line", 0)
            in_file = diag.get("in_file", "") or str(m.path)  # fall back to the TU itself
            if not msg or not line:
                continue
            key = (_normalise(msg), in_file, line)
            groups[key].add(m.path)
            sample_message.setdefault(key, msg)
            sample_tu.setdefault(key, m.path)

    clusters: list[DiagnosticCluster] = []
    for (pattern, in_file, line), tus in groups.items():
        if len(tus) < _MIN_CLUSTER_FILES:
            continue
        sample_path = Path(in_file)
        clusters.append(DiagnosticCluster(
            message_pattern=pattern,
            line=line,
            file_count=len(tus),
            sample_tu=sample_tu[(pattern, in_file, line)],
            sample_file=sample_path,
            sample_message=sample_message[(pattern, in_file, line)],
            context=_read_context(sample_path, line),
        ))

    clusters.sort(key=lambda c: c.file_count, reverse=True)
    return clusters
