"""
Tests for release package verification and CLI entry points.
"""

import subprocess
import sys
from fwlens.cli.commands import __version__


def test_version_string():
    assert __version__ == "0.29.0"


def test_cli_help_execution():
    res = subprocess.run([sys.executable, "main.py", "--help"], capture_output=True, text=True)
    assert res.returncode == 0
    assert "fwlens -- Embedded C Architecture & Static Analysis Platform" in res.stdout
