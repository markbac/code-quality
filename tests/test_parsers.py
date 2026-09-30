"""
Tests for FWLens project parsers (IAR .ewp, CMake / Make compile_commands.json, and directory scanning).
"""

import json
import tempfile
from pathlib import Path

from fwlens.config import FwLensConfig, ProjectConfig, ScopeConfig, ToolConfig, ThresholdConfig, OutputConfig
from fwlens.parser.compile_commands import parse_compile_commands, parse_compiler_flags
from fwlens.parser.dirscan import scan_directory


def test_parse_compiler_flags():
    base_dir = Path(".").resolve()
    cmd_str = "gcc -I/usr/include -Irelative/inc -DFOO -DBAR=42 -isystem /system/inc -c src/main.c"
    defines, includes = parse_compiler_flags(cmd_str, base_dir)

    assert "FOO" in defines
    assert "BAR=42" in defines
    inc_strs = [str(p).replace("\\", "/") for p in includes]
    assert any("usr/include" in p for p in inc_strs)
    assert any("relative/inc" in p for p in inc_strs)
    assert any("system/inc" in p for p in inc_strs)


def test_compile_commands_parser_mock():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        src_file = tmp_path / "main.c"
        src_file.write_text("int main(void) { return 0; }")

        comp_db = tmp_path / "compile_commands.json"
        comp_db_data = [
            {
                "directory": str(tmp_path),
                "command": f"gcc -I{tmp_path} -DTEST_DEF=1 -c main.c -o main.o",
                "file": str(src_file),
            }
        ]
        comp_db.write_text(json.dumps(comp_db_data))

        config = FwLensConfig(
            config_path=tmp_path / "config.yaml",
            tool=ToolConfig(libclang_path=None),
            project=ProjectConfig(
                ewp=None,
                configuration="Debug",
                proj_dir=tmp_path,
                toolkit_dir=None,
                mode="cmake",
                compile_commands=comp_db,
            ),
            scope=ScopeConfig(
                first_party=["."],
                sdk=[],
                third_party_lib=[],
                analyse=["first_party"],
            ),
            iar_compat_defines=[],
            layers=[],
            thresholds=ThresholdConfig(),
            output=OutputConfig(
                reports_dir=tmp_path / "output" / "reports",
                exports_dir=tmp_path / "output" / "exports",
                cache_dir=tmp_path / "output" / ".cache",
                db_path=tmp_path / "output" / "fwlens.db",
                formats=["json"],
            ),
            entry_points=["main"],
        )

        res = parse_compile_commands(config)

        assert len(res.source_files) == 1
        assert res.source_files[0].path.resolve() == src_file.resolve()
        assert "TEST_DEF=1" in res.source_files[0].defines


def test_scan_directory_mock():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        src_file = tmp_path / "app.c"
        hdr_file = tmp_path / "app.h"
        src_file.write_text("void app(void) {}")
        hdr_file.write_text("void app(void);")

        config = FwLensConfig(
            config_path=tmp_path / "config.yaml",
            tool=ToolConfig(libclang_path=None),
            project=ProjectConfig(
                ewp=None,
                configuration="Debug",
                proj_dir=tmp_path,
                toolkit_dir=None,
                mode="directory",
                source_dir=tmp_path,
            ),
            scope=ScopeConfig(
                first_party=["."],
                sdk=[],
                third_party_lib=[],
                analyse=["first_party"],
            ),
            iar_compat_defines=["__ICCARM__=1"],
            layers=[],
            thresholds=ThresholdConfig(),
            output=OutputConfig(
                reports_dir=tmp_path / "output" / "reports",
                exports_dir=tmp_path / "output" / "exports",
                cache_dir=tmp_path / "output" / ".cache",
                db_path=tmp_path / "output" / "fwlens.db",
                formats=["json"],
            ),
            entry_points=["main"],
        )

        res = scan_directory(config)

        assert len(res.source_files) == 1
        assert res.source_files[0].path.resolve() == src_file.resolve()
        assert "__ICCARM__=1" in res.source_files[0].defines
