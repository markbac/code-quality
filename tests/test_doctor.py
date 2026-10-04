"""
Tests for fwlens doctor command (Issue #40).
"""

from click.testing import CliRunner

from fwlens.cli.commands import cli


def test_doctor_command_runs_cleanly():
    runner = CliRunner()
    result = runner.invoke(cli, ["doctor"])
    assert result.exit_code == 0
    assert "fwlens doctor" in result.output
    assert "Python version" in result.output
