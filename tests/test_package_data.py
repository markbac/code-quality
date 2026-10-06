"""Every file the package ships as data must be tracked by git, not swallowed by .gitignore."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

if sys.version_info >= (3, 11):
    import tomllib
else:                                  # Python 3.10 has no tomllib; tomli is the same parser
    import tomli as tomllib

ROOT = Path(__file__).resolve().parent.parent


def test_package_data_files_are_tracked():
    if not (ROOT / ".git").exists():
        pytest.skip("not a git checkout")
    patterns = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["setuptools"]["package-data"]["fwlens"]
    files = sorted(p for pattern in patterns for p in (ROOT / "fwlens").glob(pattern) if p.is_file())
    assert files, "package-data patterns matched nothing"
    tracked = set(subprocess.run(["git", "-C", str(ROOT), "ls-files", "fwlens"], capture_output=True, text=True,
                                 check=True).stdout.splitlines())
    untracked = [str(p.relative_to(ROOT).as_posix()) for p in files if p.relative_to(ROOT).as_posix() not in tracked]
    assert not untracked, f"package data not in git (check .gitignore): {untracked}"
