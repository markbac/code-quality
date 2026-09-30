"""
Tests for GitHub Actions inline annotations output and breach processing.
"""

from fwlens.baseline import Breach
from fwlens.cli.commands import emit_github_annotations


def test_emit_github_annotations(capsys):
    breaches = [
        Breach(
            id="src/main.c:42:process_data:cyclomatic_complexity",
            kind="function",
            file="src/main.c",
            metric="cyclomatic_complexity",
            value=25.0,
            threshold=15.0,
        )
    ]

    emit_github_annotations(breaches)
    captured = capsys.readouterr()

    assert "::warning file=src/main.c,line=42,title=FWLens Breach [cyclomatic_complexity]::" in captured.out
    assert "cyclomatic_complexity is 25.0 (threshold 15.0)" in captured.out
