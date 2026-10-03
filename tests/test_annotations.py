"""
Tests for GitHub Actions inline annotations output and breach processing.
"""

from fwlens.baseline import Breach
from fwlens.cli.commands import emit_github_annotations


def test_emit_github_annotations(capsys):
    breaches = [
        Breach(
            id="src/main.c:process_data:cyclomatic_complexity",
            kind="function",
            file="src/main.c",
            metric="cyclomatic_complexity",
            value=25.0,
            threshold=15.0,
            line=42,
        )
    ]

    emit_github_annotations(breaches)
    captured = capsys.readouterr()

    assert "::warning file=src/main.c,line=42,title=FWLens Breach [cyclomatic_complexity]::" in captured.out
    assert "cyclomatic_complexity is 25.0 (threshold 15.0)" in captured.out


def test_annotation_line_comes_from_the_field_for_windows_paths(capsys):
    """The line is never recovered from the id string, so a drive letter cannot break it (#28)."""
    b = Breach(id="C:/proj/src/a.c:big:cyclomatic_complexity", kind="function", file="C:/proj/src/a.c",
               metric="cyclomatic_complexity", value=30.0, threshold=15.0, line=77, function="big")
    emit_github_annotations([b])
    assert "::warning file=C:/proj/src/a.c,line=77," in capsys.readouterr().out
