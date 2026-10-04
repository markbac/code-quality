"""
Single place that decides which libclang shared library FWLens uses, so that
preflight and the parser cannot disagree (issue #26).

Order:
1. ``tool.libclang_path`` from config. If it is set but does not exist that is an
   error, never a silent fall-through.
2. the ``LIBCLANG_PATH`` environment variable (same rule).
3. the shared library bundled in the ``libclang`` wheel (``clang/native``).
4. nothing: the bindings fall back to their own default lookup on the system.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


class LibclangError(RuntimeError):
    """An explicitly requested libclang could not be used."""


@dataclass
class LibclangLocation:
    path: Optional[Path]   # None means "let the bindings search the system"
    source: str            # "config" | "env" | "bundled" | "system"


def _bundled_library() -> Optional[Path]:
    try:
        import clang  # type: ignore
    except Exception:
        return None
    native = Path(clang.__file__).parent / "native"
    if not native.is_dir():
        return None
    for pattern in ("libclang*.so*", "libclang*.dylib", "libclang*.dll", "libclang.*"):
        for candidate in sorted(native.glob(pattern)):
            if candidate.is_file():
                return candidate
    return None


def locate_libclang(configured: Optional[Path]) -> LibclangLocation:
    if configured:
        if not Path(configured).exists():
            raise LibclangError(
                f"tool.libclang_path does not exist: {configured}. "
                "Fix the path, or remove it to use LIBCLANG_PATH or the bundled libclang."
            )
        return LibclangLocation(Path(configured), "config")

    env = os.environ.get("LIBCLANG_PATH")
    if env:
        if not Path(env).exists():
            raise LibclangError(f"LIBCLANG_PATH does not exist: {env}")
        return LibclangLocation(Path(env), "env")

    bundled = _bundled_library()
    if bundled:
        return LibclangLocation(bundled, "bundled")

    return LibclangLocation(None, "system")
