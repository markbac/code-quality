"""
Tests for configuration schema validation and pre-flight diagnostics.
"""

import tempfile
from pathlib import Path

from fwlens.config import load_config


def test_load_config_valid():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir).resolve()
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text("""
tool:
  libclang_path: null

project:
  source_dir: "."

scope:
  first_party: ["."]
  sdk: []
  third_party_lib: []
  analyse: ["first_party"]
""")

        config = load_config(cfg_file)
        assert config.project.mode == "directory"
        assert config.project.source_dir == tmp_path
