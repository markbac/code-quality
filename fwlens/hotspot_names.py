"""
Judge hotspots by the power of names, for fwlens.

Tornhill, A. (2015). Your Code as a Crime Scene, Ch.5 ("Judge Hotspots with the Power
of Names"). A good function/file name states its responsibility; a hotspot named
`utils`, `misc`, or `handler` gives the reader no hint what that responsibility is,
which is itself a maintainability smell independent of any complexity metric -- and it
also means the *other* hotspot metrics (structural debt, churn) are a weaker guide to
what to actually change, since "the utils file" is often a dumping ground rather than
one coherent responsibility.

Purely a string heuristic over names already extracted by the AST walk -- no new
parsing, no git, no config surface (the vague-word list is intentionally small and
generic; project-specific naming conventions vary too much for a one-size config
default to be worth adding).
"""

from __future__ import annotations

import re

from fwlens.model.project import ProjectModel

# Tokens that describe *how* code is organised, not *what* it's responsible for --
# a hotspot whose name is only this doesn't tell a reader where to look for the
# behaviour they're trying to understand.
_VAGUE_TOKENS = {
    "utils", "util", "misc", "miscellaneous", "common", "helper", "helpers",
    "manager", "mgr", "handler", "generic", "temp", "tmp", "tools", "core",
    "base", "general", "stuff", "process", "data", "obj", "object", "impl",
    "internal", "shared", "global", "globals", "main",
}

_SPLIT_RE = re.compile(r"[_\W]+|(?<=[a-z0-9])(?=[A-Z])")


def _tokens(name: str) -> list[str]:
    return [t.lower() for t in _SPLIT_RE.split(name) if t]


def _judge(name: str) -> str:
    """Returns a short reason string if every token in `name` is vague, else ''."""
    tokens = _tokens(name)
    if not tokens:
        return ""
    vague = [t for t in tokens if t in _VAGUE_TOKENS]
    if len(vague) == len(tokens):
        return f"name reveals no responsibility ({'/'.join(tokens)})"
    return ""


def flag_hotspot_names(model: ProjectModel) -> None:
    """
    Populate FunctionMetrics.vague_name_flag for functions in model.hotspots -- checks
    both the function name and its containing file's stem, since a well-named function
    in a vaguely-named dumping-ground file ("processData" in "Utils.c") is still worth
    flagging. Must run after fwlens.git_history.compute_hotspots.
    """
    for f in model.hotspots:
        reason = _judge(f.name)
        if not reason:
            file_reason = _judge(f.file.stem)
            if file_reason:
                reason = f"file {file_reason}"
        f.vague_name_flag = reason
