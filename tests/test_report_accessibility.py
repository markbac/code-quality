"""Structure and colour checks for the HTML report (#78).

The scripted browser audit (axe-core, keyboard, 390 px overflow) is not part of CI; these
tests keep the parts of it that can be checked from the generated HTML.
"""

import re
from html.parser import HTMLParser

import pytest

from tests.test_sarif_cli import project


class Collector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags: list[tuple[str, dict]] = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


@pytest.fixture(scope="module")
def report_html(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("report")
    cfg = project(tmp)
    import os

    from click.testing import CliRunner

    import main as fwlens_main
    cwd = os.getcwd()
    os.chdir(tmp)
    try:
        res = CliRunner().invoke(fwlens_main.cli, ["report", "--config", str(cfg)])
    finally:
        os.chdir(cwd)
    assert res.exit_code == 0, res.output
    return (tmp / "output" / "reports" / "fwlens_report.html").read_text(encoding="utf-8")


def tags(html, name):
    c = Collector()
    c.feed(html)
    return [a for t, a in c.tags if t == name]


def test_viewport_meta_is_present(report_html):
    metas = tags(report_html, "meta")
    assert any(m.get("name") == "viewport" and "width=device-width" in m.get("content", "") for m in metas)


def test_tabs_are_a_keyboard_reachable_tablist(report_html):
    c = Collector()
    c.feed(report_html)
    tabs = [(t, a) for t, a in c.tags if a.get("role") == "tab"]
    assert len(tabs) == 15
    assert all(t == "button" for t, _ in tabs)
    assert sum(1 for _, a in tabs if a.get("aria-selected") == "true") == 1
    assert sum(1 for _, a in tabs if a.get("tabindex") == "0") == 1
    assert any(a.get("role") == "tablist" for _, a in c.tags)
    panes = {a["id"]: a for t, a in c.tags if a.get("role") == "tabpanel"}
    for _, a in tabs:
        pane = panes[a["aria-controls"]]
        assert pane["aria-labelledby"] == a["id"]


def test_every_pane_is_a_pane(report_html):
    assert "paneNone" not in report_html
    assert len(re.findall(r'class="pane( active)?" id="pane-', report_html)) == 15


def test_about_panel_does_not_push_the_scorecards_down(report_html):
    about = re.search(r"<details[^>]*>\s*<summary>About fwlens", report_html)
    assert about and " open" not in about.group(0)


def _luminance(hex_colour: str) -> float:
    rgb = [int(hex_colour[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    lin = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in rgb]
    return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]


def _contrast(a: str, b: str) -> float:
    hi, lo = sorted((_luminance(a), _luminance(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def _theme_vars(html, selector):
    block = re.search(re.escape(selector) + r" \{(.*?)\}", html, re.S).group(1)
    return dict(re.findall(r"--([a-z-]+):\s*(#[0-9a-fA-F]{6})", block))


@pytest.mark.parametrize("selector", [":root", ":root.light"])
def test_text_colours_reach_4_5_to_1_on_both_backgrounds(report_html, selector):
    v = _theme_vars(report_html, selector)
    for colour in ("dim", "text", "red", "yellow", "green", "accent"):
        for background in ("bg", "surface"):
            assert _contrast(v[colour], v[background]) >= 4.5, (selector, colour, background)
