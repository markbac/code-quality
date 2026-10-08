"""The MISRA rule sets are a plugin that can be left out (#87, #81)."""

import pytest

from fwlens.config import StandardSelection, StandardsConfig
from fwlens.standards import RuleFileError, select_rules
from fwlens.standards import rules as rules_module
from fwlens.standards.rules import PLUGINS_DIR, load_standards, plugin_dirs


def test_misra_is_installed_as_a_plugin_not_a_built_in():
    assert (PLUGINS_DIR / "misra" / "misra-c-2012.yaml").is_file() and (PLUGINS_DIR / "misra" / "misra-c-2023.yaml").is_file()
    assert not list(rules_module.BUILTIN_DIR.glob("misra*"))
    assert {"misra-c-2012", "misra-c-2023", "cert-c"} <= set(load_standards([]))


def test_a_disabled_plugin_leaves_everything_else_working():
    standards = load_standards([], disabled_plugins=["misra"])
    assert not [s for s in standards if s.startswith("misra")]
    assert {"cert-c", "power-of-10", "barr-c-2018", "fwlens"} <= set(standards)
    assert all(d.name != "misra" for d in plugin_dirs(["misra"]))


def test_a_removed_plugin_directory_works_the_same_way(tmp_path, monkeypatch):
    monkeypatch.setattr(rules_module, "PLUGINS_DIR", tmp_path / "absent")
    standards = load_standards([])
    assert "cert-c" in standards and "misra-c-2012" not in standards


def test_asking_for_misra_without_the_plugin_says_why():
    standards = load_standards([], disabled_plugins=["misra"])
    cfg = StandardsConfig(enabled=[StandardSelection("misra-c-2023")])
    with pytest.raises(RuleFileError, match="MISRA plugin"):
        select_rules(standards, cfg.enabled)


def test_a_project_file_can_still_supply_its_own_misra_data(tmp_path):
    source = (PLUGINS_DIR / "misra" / "misra-c-2012.yaml").read_text()
    (tmp_path / "misra-c-2012.yaml").write_text(source)
    standards = load_standards([tmp_path], disabled_plugins=["misra"])
    assert "misra-c-2012" in standards and "misra-c-2023" not in standards
