"""
The fwlens-hides rules: MISRA C findings that were probably hidden rather than fixed.

The fixtures come from misra_hide_scan, where the checks were ported from: hides.c holds one hide
per commented line and hides.expected.txt is that tool's output for it; fixed.c and acceptable.c
hold proper fixes and legitimate look-alikes and must give nothing.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from fwlens.standards.hides import CHECKS, analyse
from fwlens.standards.rules import load_standards
from fwlens.standards.sourcechecks import SourceFile

FIXTURES = Path(__file__).parent / "fixtures" / "hides"
LEVEL = {"error": "high", "warning": "medium", "note": "low"}


def expected() -> list[tuple[int, str, str]]:
    out = []
    for line in (FIXTURES / "hides.expected.txt").read_text().splitlines():
        m = re.match(r"[^:]+:(\d+):\d+: (\w+): .*\[([\w-]+), MISRA", line)
        assert m, line
        out.append((int(m.group(1)), m.group(3), LEVEL[m.group(2)]))
    return sorted(out)


def found(name: str, **params) -> list[tuple[int, str, str]]:
    return sorted((f.line, f.check, f.severity) for f in analyse(SourceFile.read(FIXTURES / name), **params))


def test_hides_c_gives_the_original_tools_findings():
    assert found("hides.c") == expected()


@pytest.mark.parametrize("name", ["fixed.c", "acceptable.c"])
def test_fixes_and_legitimate_look_alikes_give_nothing(name):
    assert found(name) == []


def test_every_finding_has_a_rule_and_every_rule_a_check():
    std = load_standards([])["fwlens-hides"]
    rules = {(r.match["check"], r.match["severity"]): r for r in std.rules.values()}
    assert len(rules) == len(std.rules)
    for _, check, severity in expected():
        assert (check, severity) in rules, (check, severity)
        assert rules[(check, severity)].category == severity
    assert len(CHECKS) == 13


def test_deviation_pattern_can_be_replaced():
    # hides.c cites DEV-011 above UART0_DATA, so only UART0_CTRL is reported with the default pattern
    default = [f for f in found("hides.c") if f[1] == "int-to-pointer-undocumented"]
    assert [f[0] for f in default] == [9]
    other = [f for f in found("hides.c", deviation_pattern=r"\bWAIVER-\d+") if f[1] == "int-to-pointer-undocumented"]
    assert [f[0] for f in other] == [9, 14]


def test_rules_run_through_the_standards_engine(tmp_path):
    from standards_harness import analyse as run

    std = load_standards([])["fwlens-hides"]
    text = (FIXTURES / "hides.c").read_text()
    by_rule = run(tmp_path, text, "fwlens-hides")
    got = {(f.line, std.rules[rid].match["check"], f.category) for rid, fs in by_rule.items() for f in fs}
    assert got == set(expected())

    high = run(tmp_path, text, "fwlens-hides", include_categories=["high"])
    assert {f.category for fs in high.values() for f in fs} == {"high"}


def test_hidden_findings_tab_groups_by_rule_most_severe_first(tmp_path):
    import cparse
    from standards_harness import _config

    from fwlens.config import StandardsConfig, StandardSelection
    from fwlens.output.html_report import _hidden_context
    from fwlens.parser.pipeline import run_pipeline

    cparse.require_host_compiler()
    (tmp_path / "app.c").write_text((FIXTURES / "hides.c").read_text())
    (tmp_path / "config.yaml").write_text("tool:\n  target: native\nproject:\n  source_dir: .\n")
    config = _config(tmp_path)
    model = run_pipeline(config)
    config.standards = StandardsConfig(enabled=[StandardSelection("fwlens-hides")])
    view = _hidden_context(model, config)
    assert view["error"] is None and view["total"] == len(set(expected()))
    severities = [g["severity"] for g in view["groups"]]
    assert severities == sorted(severities, key=["high", "medium", "low"].index)
    unchecked = next(g for g in view["groups"] if g["check"] == "unchecked-result" and g["severity"] == "high")
    row = unchecked["findings"][0]
    assert row["function"] and "Nvm_Write" in row["message"] and "Nvm_Write" in row["source"]

    config.standards = StandardsConfig(enabled=[StandardSelection("cert-c")])
    assert _hidden_context(model, config) is None
