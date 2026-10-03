"""
Discover compiler and system include directories and the clang target arguments
(issue #48).

The libclang wheel ships no resource headers, so ``stddef.h`` and friends are not
found unless we ask a real compiler where they are. We never mix compilers and
targets: an ARM target only uses ``arm-none-eabi-gcc``, a native target uses the
host ``gcc``, ``cc`` or ``clang``.
"""

from __future__ import annotations

import functools
import shutil
import subprocess
from pathlib import Path

_NATIVE_TARGETS = {"", "native", "host"}
_CANDIDATES_NATIVE = ("gcc", "cc", "clang")


def is_native(target: str) -> bool:
    return (target or "").strip().lower() in _NATIVE_TARGETS


def _compiler_candidates(target: str) -> tuple[str, ...]:
    if is_native(target):
        return _CANDIDATES_NATIVE
    return (f"{target}-gcc",)


def parse_include_search_list(stderr: str) -> list[str]:
    """Extract the directories from ``gcc -E -v`` output."""
    dirs: list[str] = []
    active = False
    for line in stderr.splitlines():
        if line.startswith("#include <...> search starts here:"):
            active = True
            continue
        if line.startswith("End of search list."):
            break
        if active:
            path = line.strip()
            if path.endswith("(framework directory)"):
                continue
            if path:
                dirs.append(path)
    return dirs


@functools.lru_cache(maxsize=16)
def detect_system_includes(target: str, sysroot: str = "") -> tuple[tuple[str, ...], str]:
    """Return (include dirs, compiler used or ""). Empty when no compiler is found."""
    for name in _compiler_candidates(target):
        exe = shutil.which(name)
        if not exe:
            continue
        cmd = [exe, "-E", "-x", "c", "-", "-v"]
        if sysroot:
            cmd.insert(1, f"--sysroot={sysroot}")
        try:
            proc = subprocess.run(cmd, input="", capture_output=True, text=True, timeout=20)
        except (OSError, subprocess.SubprocessError):
            continue
        found = [d for d in parse_include_search_list(proc.stderr) if Path(d).is_dir()]
        if found:
            return tuple(found), name
    return (), ""


def target_args(target: str) -> list[str]:
    return [] if is_native(target) else [f"--target={target}"]
