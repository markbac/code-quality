"""
Tests for fwlens init command.
"""

import tempfile
from pathlib import Path

from fwlens.config import load_config
from fwlens.cli.commands import _CONFIG_TEMPLATES


def test_init_templates_exist():
    assert "cmake" in _CONFIG_TEMPLATES
    assert "make" in _CONFIG_TEMPLATES
    assert "ewp" in _CONFIG_TEMPLATES
    assert "directory" in _CONFIG_TEMPLATES


def test_init_config_generation():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        cfg_path = tmp_path / "config.yaml"
        cfg_path.write_text(_CONFIG_TEMPLATES["directory"], encoding="utf-8")

        config = load_config(cfg_path)
        assert config.project.mode == "directory"
