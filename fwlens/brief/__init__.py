"""The architecture brief: one JSON file describing a code base for a reader or an LLM (fwlens architecture brief)."""

from __future__ import annotations

import json
from pathlib import Path

from fwlens.brief.build import SCHEMA, build_brief

__all__ = ["SCHEMA", "build_brief", "write_brief"]


def write_brief(model, config, path: Path) -> Path:
    """Write the brief as JSON to `path` and return it."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(build_brief(model, config), indent=1, default=_default, ensure_ascii=False) + "\n",
                    encoding="utf-8")
    return path


def _default(obj):
    if isinstance(obj, Path):
        return obj.as_posix()
    if isinstance(obj, (set, frozenset)):
        return sorted(obj)
    if hasattr(obj, "value"):
        return obj.value
    return str(obj)
