"""
Diff mode: judge a pull or merge request on the code it touches (#73).

The whole project is still parsed, so cross-file metrics and project totals stay correct.
Only the *findings* (breaches, standards findings) are filtered to changed files, or to
functions whose line range overlaps a changed hunk.
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from fwlens.baseline import Breach

_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


@dataclass
class Changes:
    base: str
    # repo-relative posix path -> changed line ranges (new side), empty list for deleted/binary
    files: dict[str, list[tuple[int, int]]] = field(default_factory=dict)


def detect_base(explicit: str | None) -> str | None:
    """--changed-since, else the pull or merge request base from the CI environment."""
    if explicit:
        return explicit
    sha = os.environ.get("CI_MERGE_REQUEST_DIFF_BASE_SHA")
    if sha:
        return sha
    base_ref = os.environ.get("GITHUB_BASE_REF")
    if base_ref:
        return f"origin/{base_ref}"
    return None


def _git(root: Path, *args: str) -> tuple[int, str]:
    try:
        r = subprocess.run(["git", "-c", "core.quotePath=false", "-C", str(root), *args],
                           capture_output=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as e:
        return 1, str(e)
    return r.returncode, r.stdout.decode("utf-8", errors="replace") or r.stderr.decode("utf-8", errors="replace")


def changed_lines(root: Path, base: str) -> tuple[Changes | None, str | None]:
    """
    Files and changed line ranges between the merge base of `base` and the working tree.
    Returns (None, message) when the base cannot be resolved, for example in a shallow clone
    that does not contain it; callers then fall back to reporting everything.
    """
    code, out = _git(root, "merge-base", base, "HEAD")
    if code != 0:
        shallow = _git(root, "rev-parse", "--is-shallow-repository")[1].strip() == "true"
        hint = (" The clone is shallow: fetch the base branch (git fetch --deepen or "
                "actions/checkout with fetch-depth: 0)." if shallow else "")
        return None, f"cannot find a merge base with '{base}'.{hint}"
    merge_base = out.strip()

    code, diff = _git(root, "diff", "--unified=0", "--no-renames", "--no-color", merge_base)
    if code != 0:
        return None, f"git diff against '{base}' failed: {diff.strip()}"

    changes = Changes(base=base)
    current: str | None = None
    for line in diff.splitlines():
        if line.startswith("+++ "):
            target = line[4:].split("\t")[0]
            current = target[2:] if target.startswith("b/") else None
            if current is not None:
                changes.files.setdefault(current, [])
        elif line.startswith("--- ") and line.endswith("/dev/null"):
            continue
        elif current is not None:
            m = _HUNK.match(line)
            if m:
                start = int(m.group(1))
                count = int(m.group(2)) if m.group(2) is not None else 1
                if count:
                    changes.files[current].append((start, start + count - 1))
    return changes, None


def filter_breaches(breaches: list[Breach], changes: Changes, mode: str = "file",
                    function_lengths: dict[tuple[str, str], int] | None = None) -> list[Breach]:
    """Keep findings in changed files, or (mode "function") in functions touching a changed hunk."""
    kept = []
    for b in breaches:
        ranges = changes.files.get(b.file)
        if ranges is None:
            continue
        if mode == "function" and b.kind == "function" and b.line:
            length = (function_lengths or {}).get((b.file, b.function or ""), 1)
            start, end = b.line, b.line + max(length, 1) - 1
            if not any(lo <= end and hi >= start for lo, hi in ranges):
                continue
        kept.append(b)
    return kept
