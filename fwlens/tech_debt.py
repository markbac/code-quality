"""
Text-based tech-debt scanning for fwlens: marker comments, commented-out code,
and preprocessor complexity.

Like fwlens.metrics.file_metrics, this shells out to no external tool -- it's
a handful of regexes over the raw source text, run on every module regardless
of whether it parsed cleanly with libclang. Cheap, best-effort, and tolerant
of the same false-positive/false-negative trade-offs any line-based (not
lexer-based) scanner has: a `//` inside a string literal can throw off the
comment-block heuristic, same caveat as file_metrics.
"""

from __future__ import annotations

import re
from pathlib import Path

from fwlens.model.project import CommentedCodeBlock, ModuleMetrics, ProjectModel, TodoMarker

_MARKER_RE = re.compile(r'(?://|/\*)\s*(TODO|FIXME|HACK|XXX)\b[:\-]?\s*(.*)', re.IGNORECASE)

# A comment line "looks like code" if it has code-shaped punctuation density:
# semicolons, braces, assignment/comparison operators, or a trailing paren-call shape.
_CODE_SHAPE_RE = re.compile(r'[;{}]|[=!<>]=|\b\w+\s*\(.*\)\s*;?\s*$')

_IFDEF_OPEN_RE  = re.compile(r'^\s*#\s*(ifdef|ifndef|if)\b\s*(.*)')
_IFDEF_ELSE_RE  = re.compile(r'^\s*#\s*(elif|else)\b')
_IFDEF_CLOSE_RE = re.compile(r'^\s*#\s*endif\b')
_MACRO_TOKEN_RE = re.compile(r'\b([A-Z_][A-Z0-9_]{2,})\b')

# Macros too common/structural to count as "feature flags"
_FLAG_EXEMPT = frozenset([
    "DEFINED", "NULL", "TRUE", "FALSE", "VOID", "CONST", "STATIC",
])


def _strip_comment_marker(line: str) -> str:
    """Strip a leading // or /* and trailing */ for display purposes."""
    s = line.strip()
    s = re.sub(r'^/\*+', '', s)
    s = re.sub(r'\*+/$', '', s)
    s = re.sub(r'^//+', '', s)
    return s.strip()


def scan_todo_markers(model: ProjectModel) -> None:
    """Collect TODO/FIXME/HACK/XXX comments across all modules into model.todo_markers."""
    markers: list[TodoMarker] = []
    for m in model.modules:
        try:
            lines = m.path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for i, line in enumerate(lines, start=1):
            match = _MARKER_RE.search(line)
            if match:
                markers.append(TodoMarker(
                    file=m.path, line=i,
                    tag=match.group(1).upper(),
                    text=match.group(2).strip(),
                ))
    markers.sort(key=lambda t: (str(t.file), t.line))
    model.todo_markers = markers


def detect_commented_code(model: ProjectModel) -> None:
    """
    Flag runs of >=3 consecutive comment-only lines that look code-shaped rather
    than prose -- a decent proxy for "commented-out code left behind" without a
    full C lexer. Single-line comments and short runs are treated as normal
    documentation, not flagged.

    A `/* */` block (however many lines it spans) and a run of consecutive `//`
    line comments are evaluated as separate runs even when adjacent with no
    blank line between them -- merging them would let unrelated trailing prose
    comments (e.g. a version-history `//` line right after a commented-out
    `/* */` function) dilute the code-line density below the flag threshold.
    """
    blocks: list[CommentedCodeBlock] = []

    for m in model.modules:
        try:
            lines = m.path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue

        runs: list[tuple[int, int, int, int]] = []  # start, end, length, code_line_count
        current_style = None
        run_start = None
        run_len = 0
        run_code = 0
        in_block_comment = False

        def flush(end_line: int):
            nonlocal current_style, run_start, run_len, run_code
            if run_start is not None:
                runs.append((run_start, end_line, run_len, run_code))
            current_style = None
            run_start = None
            run_len = 0
            run_code = 0

        for idx, raw_line in enumerate(lines, start=1):
            stripped = raw_line.strip()

            if in_block_comment:
                style = "block"
                if "*/" in stripped:
                    in_block_comment = False
            elif stripped.startswith("/*"):
                style = "block"
                if "*/" not in stripped[2:]:
                    in_block_comment = True
            elif stripped.startswith("//"):
                style = "line"
            else:
                style = None

            if style is None:
                flush(idx - 1)
                continue

            if current_style is not None and style != current_style:
                flush(idx - 1)

            if run_start is None:
                run_start = idx
                current_style = style
            run_len += 1
            if _CODE_SHAPE_RE.search(_strip_comment_marker(raw_line)):
                run_code += 1

        flush(len(lines))

        for start, end, length, code_lines in runs:
            if length >= 3 and code_lines >= max(2, length // 2):
                blocks.append(CommentedCodeBlock(
                    file=m.path, start_line=start, end_line=end, line_count=length,
                ))

    blocks.sort(key=lambda b: (str(b.file), b.start_line))
    model.commented_code_blocks = blocks


def _preprocessor_complexity_for_text(text: str) -> tuple[int, int, set[str]]:
    """Returns (max_depth, directive_count, distinct_flag_names)."""
    depth = 0
    max_depth = 0
    directive_count = 0
    flags: set[str] = set()

    for line in text.splitlines():
        open_m = _IFDEF_OPEN_RE.match(line)
        if open_m:
            depth += 1
            max_depth = max(max_depth, depth)
            directive_count += 1
            for tok in _MACRO_TOKEN_RE.findall(open_m.group(2)):
                if tok not in _FLAG_EXEMPT:
                    flags.add(tok)
            continue
        if _IFDEF_ELSE_RE.match(line):
            directive_count += 1
            continue
        if _IFDEF_CLOSE_RE.match(line):
            depth = max(0, depth - 1)
            directive_count += 1
            continue

    return max_depth, directive_count, flags


def compute_all_preprocessor_complexity(model: ProjectModel) -> None:
    """Populate preprocessor complexity fields on every module."""
    for m in model.modules:
        try:
            text = m.path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        max_depth, directive_count, flags = _preprocessor_complexity_for_text(text)
        m.max_ifdef_depth = max_depth
        m.ifdef_directive_count = directive_count
        m.distinct_feature_flags = len(flags)


def run_tech_debt_scan(model: ProjectModel) -> None:
    """Run all text-based tech-debt scans in order."""
    scan_todo_markers(model)
    detect_commented_code(model)
    compute_all_preprocessor_complexity(model)
