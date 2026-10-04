"""
Tests for ConfigError and edge cases in config loading (#32).
"""

from pathlib import Path
import pytest
from fwlens.config import load_config, ConfigError


def test_missing_config_raises_config_error(tmp_path):
    missing_file = tmp_path / "nonexistent_config.yaml"
    with pytest.raises(ConfigError, match="Config file not found"):
        load_config(missing_file)


def test_empty_config_raises_config_error(tmp_path):
    empty_file = tmp_path / "config.yaml"
    empty_file.write_text("")
    with pytest.raises(ConfigError, match="project.ewp, project.source_dir, or project.compile_commands"):
        load_config(empty_file)


def test_config_without_project_section_raises_config_error(tmp_path):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text("tool:\n  target: native\n")
    with pytest.raises(ConfigError, match="project.ewp, project.source_dir, or project.compile_commands"):
        load_config(cfg_file)
