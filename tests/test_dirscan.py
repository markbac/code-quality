"""Directory-mode include directories: explicit list, 'used' mode, duplicate header warning (#84)."""

from __future__ import annotations

from dataclasses import replace

import pytest

from fwlens.config import ConfigError, load_config
from fwlens.parser.dirscan import scan_directory
from tests.cparse import make_config


@pytest.fixture
def two_ports(tmp_path):
    """app/main.c includes port.h; ports/a and ports/b each provide one. unused/ is never included."""
    files = {
        "app/main.c": '#include "port.h"\n#include "drv/uart.h"\nint main(void) { return PORT_ID; }\n',
        "ports/a/port.h": "#define PORT_ID 1\n",
        "ports/b/port.h": "#define PORT_ID 2\n",
        "inc/drv/uart.h": "#define UART 1\n",
        "unused/other.h": "#define OTHER 1\n",
    }
    for name, text in files.items():
        f = tmp_path / name
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)
    return tmp_path


def _cfg(root, **project):
    cfg = make_config(root)
    cfg.project = replace(cfg.project, **project)
    return cfg



def test_default_mode_warns_and_names_the_winner(two_ports):
    result = scan_directory(_cfg(two_ports))
    assert len(result.warnings) == 1
    w = result.warnings[0]
    assert "'port.h'" in w and "'ports/a' wins" in w and "'ports/b'" in w


def test_explicit_include_dirs_pick_one_port_and_the_warning_lists_the_other(two_ports):
    cfg = _cfg(two_ports, include_dirs=[two_ports / "ports" / "b", two_ports / "inc"])
    result = scan_directory(cfg)
    paths = result.source_files[0].include_paths
    assert two_ports / "ports" / "b" in paths and two_ports / "ports" / "a" not in paths
    assert len(result.warnings) == 1
    assert "'ports/b' wins" in result.warnings[0] and "'ports/a'" in result.warnings[0]


def test_used_mode_keeps_only_directories_reached_by_include(two_ports):
    (two_ports / "ports" / "b" / "port.h").unlink()
    result = scan_directory(_cfg(two_ports, include_mode="used"))
    names = {p.relative_to(two_ports).as_posix() for p in result.source_files[0].include_paths}
    assert names == {".", "ports/a", "inc"}
    assert result.warnings == []


def test_used_mode_follows_nested_includes(two_ports):
    (two_ports / "inc" / "drv" / "uart.h").write_text('#include "deep.h"\n')
    (two_ports / "deep" ).mkdir()
    (two_ports / "deep" / "deep.h").write_text("#define DEEP 1\n")
    result = scan_directory(_cfg(two_ports, include_mode="used"))
    assert two_ports / "deep" in result.source_files[0].include_paths


def test_exclude_drops_a_port_and_the_warning(two_ports):
    cfg = make_config(two_ports)
    cfg.scope.exclude = ["ports/b"]
    result = scan_directory(cfg)
    assert result.warnings == []


def test_config_reads_and_validates_the_keys(tmp_path):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text("project:\n  source_dir: src\n  include_dirs: [inc, ports/a]\n  include_mode: used\n")
    cfg = load_config(cfg_file)
    assert cfg.project.include_dirs == [tmp_path / "inc", tmp_path / "ports" / "a"]
    assert cfg.project.include_mode == "used"
    cfg_file.write_text("project:\n  source_dir: src\n  include_mode: some\n")
    with pytest.raises(ConfigError):
        load_config(cfg_file)
