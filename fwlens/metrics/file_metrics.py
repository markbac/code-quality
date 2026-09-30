"""
File-level line metrics for fwlens modules.

Computes SLOC / comment lines / blank lines per file, the same broad shape of
metric the older ccccc+scc code_governance toolkit got from the external
`scc` binary. This version does not shell out to `scc` or `ccccc` -- it is a
small state machine over the raw source text: track `/* */` block comments
and `//` line comments, classify each physical line as code, comment-only,
or blank, and derive SLOC and a comment ratio from that.

> **Known limitation:** this is a line classifier, not a full C lexer. It
> does not track string/char literal contents, so a `//` or `/*` sequence
> inside a string literal will be (incorrectly) treated as the start of a
> comment. This is the same trade-off `scc` and similar line-counting tools
> make in exchange for not needing a full parse; treat file_sloc as
> indicative, not exact.
"""

from __future__ import annotations

from dataclasses import dataclass

from fwlens.model.project import ProjectModel


@dataclass
class FileLineCounts:
    total_lines: int = 0
    blank_lines: int = 0
    comment_lines: int = 0   # lines that are comment-only
    code_lines: int = 0      # SLOC -- lines containing at least one token of code


def _classify_lines(text: str) -> FileLineCounts:
    counts = FileLineCounts()
    in_block_comment = False

    for raw_line in text.splitlines():
        counts.total_lines += 1

        if not raw_line.strip() and not in_block_comment:
            counts.blank_lines += 1
            continue

        has_comment = False
        code_seen = False
        i = 0
        n = len(raw_line)

        while i < n:
            if in_block_comment:
                end = raw_line.find("*/", i)
                has_comment = True
                if end == -1:
                    i = n
                else:
                    in_block_comment = False
                    i = end + 2
                continue

            two = raw_line[i:i + 2]
            if two == "/*":
                has_comment = True
                in_block_comment = True
                i += 2
                continue
            if two == "//":
                has_comment = True
                break  # rest of the physical line is a line comment

            if not raw_line[i].isspace():
                code_seen = True
            i += 1

        if code_seen:
            counts.code_lines += 1
        elif has_comment:
            counts.comment_lines += 1
        else:
            counts.blank_lines += 1

    return counts


def compute_file_metrics(model: ProjectModel) -> None:
    """Populate file_* line-count fields on every module in the model."""
    for m in model.modules:
        try:
            text = m.path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        counts = _classify_lines(text)
        m.file_total_lines = counts.total_lines
        m.file_blank_lines = counts.blank_lines
        m.file_comment_lines = counts.comment_lines
        m.file_sloc = counts.code_lines

        commented_denom = counts.code_lines + counts.comment_lines
        m.file_comment_ratio = (counts.comment_lines / commented_denom) if commented_denom else 0.0
