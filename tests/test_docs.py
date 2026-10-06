"""The user guide, README and example config cover every command, option and config key (#94)."""

from __future__ import annotations

import dataclasses
import re
from pathlib import Path

import pytest

import main as fwlens_main
from fwlens import config_schema

ROOT = Path(__file__).resolve().parent.parent
GUIDE = (ROOT / "FWLENS_GUIDE.md").read_text(encoding="utf-8")
README = (ROOT / "README.md").read_text(encoding="utf-8")
EXAMPLE = (ROOT / "config.example.yaml").read_text(encoding="utf-8")


def _commands(cmd=fwlens_main.cli, path=()):
    for name, sub in sorted(getattr(cmd, "commands", {}).items()):
        yield (*path, name), sub
        yield from _commands(sub, (*path, name))


def test_every_command_and_option_is_in_the_guide():
    missing = []
    for path, cmd in _commands():
        name = " ".join(path)
        if name not in GUIDE and path[-1] not in GUIDE:
            missing.append(name)
        for param in cmd.params:
            missing += [f"{name} {o}" for o in param.opts if o.startswith("--") and o not in GUIDE]
    assert not missing, f"not in FWLENS_GUIDE.md: {missing}"


def test_every_top_level_command_is_in_the_readme():
    missing = [path[0] for path, _ in _commands() if len(path) == 1 and path[0] not in README]
    assert not missing, f"not in README.md: {missing}"


def _keys():
    for section, cls in config_schema._SECTIONS.items():
        for f in dataclasses.fields(cls):
            yield f"{section}.{f.name}", f.name
    for key in (*config_schema._TOP_LEVEL_SCALARS, "layers"):
        yield key, key


@pytest.mark.parametrize("where,text", [("FWLENS_GUIDE.md", GUIDE), ("config.example.yaml", EXAMPLE)],
                         ids=["guide", "example"])   # not the file text: a 100 KB test id breaks the Windows runner
def test_every_config_key_is_documented(where, text):
    missing = [full for full, key in _keys() if key not in text]
    assert not missing, f"not in {where}: {missing}"


def test_guide_contents_links_resolve():
    def slug(heading: str) -> str:
        s = re.sub(r"[^\w\s-]", "", heading.strip().lower())
        return re.sub(r"\s", "-", s)

    anchors = {slug(m.group(2)) for m in re.finditer(r"^(#{1,6}) (.+?)\s*$", GUIDE, re.MULTILINE)}
    links = set(re.findall(r"\]\(#([^)]+)\)", GUIDE))
    assert sorted(links - anchors) == []


def test_example_config_is_valid_and_shows_every_output_format():
    import yaml
    assert isinstance(yaml.safe_load(EXAMPLE), dict)
    assert all(fmt in EXAMPLE for fmt in config_schema.SUPPORTED_FORMATS)
