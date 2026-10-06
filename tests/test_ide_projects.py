"""Keil .uvprojx and STM32CubeIDE .cproject readers, and the west / PlatformIO routes (#75)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

import main as fwlens_main
from fwlens.config import load_config
from fwlens.parser.compile_commands import parse_compile_commands
from fwlens.parser.ide_projects import parse_cproject, parse_uvprojx

FIXTURES = Path(__file__).parent / "fixtures"


def config_for(tmp_path: Path, project_lines: str) -> Path:
    cfg = tmp_path / "config.yaml"
    cfg.write_text("project:\n" + project_lines + "scope:\n  first_party: [Core, Drivers]\ntool:\n  target: native\n")
    return cfg


def names(result):
    return sorted(tu.path.name for tu in result.source_files)


# --- Keil -----------------------------------------------------------------------------

def keil_config(tmp_path, configuration="Debug"):
    cfg = config_for(tmp_path, f"  uvprojx: {FIXTURES / 'keil' / 'MDK-ARM' / 'project.uvprojx'}\n"
                               f"  configuration: {configuration}\n")
    return load_config(cfg)


def test_keil_reads_defines_includes_and_c_files_of_the_chosen_target(tmp_path):
    config = keil_config(tmp_path)
    assert config.project.mode == "keil"
    result = parse_uvprojx(config)
    assert names(result) == ["main.c", "uart.c"]                  # startup.s is assembler, skipped
    main = next(tu for tu in result.source_files if tu.path.name == "main.c")
    assert {"USE_HAL_DRIVER", "STM32F407xx"} <= set(main.defines)
    assert FIXTURES / "keil" / "Core" / "Inc" in main.include_paths    # '..\Core\Inc' resolved from MDK-ARM
    assert main.iar_group == "Application"
    assert result.configuration_name == "Debug"


def test_keil_other_target_has_its_own_settings(tmp_path):
    result = parse_uvprojx(keil_config(tmp_path, "Release"))
    assert names(result) == ["main.c"]
    assert {"USE_HAL_DRIVER", "NDEBUG"} <= set(result.source_files[0].defines)   # space separated


def test_keil_unknown_target_lists_the_available_ones(tmp_path):
    with pytest.raises(ValueError, match=r"Available: \['Debug', 'Release'\]"):
        parse_uvprojx(keil_config(tmp_path, "Nope"))


def test_keil_project_runs_through_the_pipeline_with_its_defines(tmp_path, monkeypatch):
    cfg = config_for(tmp_path, f"  uvprojx: {FIXTURES / 'keil' / 'MDK-ARM' / 'project.uvprojx'}\n")
    monkeypatch.chdir(tmp_path)
    res = CliRunner().invoke(fwlens_main.cli, ["export", "--config", str(cfg)])
    assert res.exit_code == 0, res.output
    assert "Parsing Keil project" in res.output
    functions = (tmp_path / "output" / "exports" / "functions.csv").read_text()
    for name in ("main", "board_clock_mhz", "uart_baud"):
        assert name in functions


# --- STM32CubeIDE / Eclipse CDT ---------------------------------------------------------

def cproject_config(tmp_path):
    return load_config(config_for(tmp_path, f"  cproject: {FIXTURES / 'cubeide' / '.cproject'}\n"))


def test_cproject_reads_defines_includes_and_source_entries(tmp_path):
    config = cproject_config(tmp_path)
    assert config.project.mode == "cproject"
    result = parse_cproject(config)
    assert names(result) == ["hal.c", "main.c"]                    # Core/Generated is excluded
    main = next(tu for tu in result.source_files if tu.path.name == "main.c")
    assert {"USE_HAL_DRIVER", "STM32F407xx"} <= set(main.defines)
    cube = FIXTURES / "cubeide"
    assert cube / "Core" / "Inc" in main.include_paths             # ../Core/Inc from the Debug directory
    assert cube / "Drivers" / "HAL" / "Inc" in main.include_paths  # ${workspace_loc:/${ProjName}/...}
    assert not any("STM32_PACK" in str(p) for p in main.include_paths)   # unknown variables are left out
    assert result.configuration_name == "Debug"


def test_cproject_project_runs_through_the_pipeline(tmp_path, monkeypatch):
    cfg = config_for(tmp_path, f"  cproject: {FIXTURES / 'cubeide' / '.cproject'}\n")
    monkeypatch.chdir(tmp_path)
    res = CliRunner().invoke(fwlens_main.cli, ["analyze", "--config", str(cfg)])
    assert res.exit_code == 0, res.output
    assert "Parsing .cproject" in res.output


# --- west and PlatformIO: both write compile_commands.json -------------------------------

def compile_db(tmp_path: Path, entries: list[dict]) -> Path:
    db = tmp_path / "build" / "compile_commands.json"
    db.parent.mkdir(parents=True)
    db.write_text(json.dumps(entries))
    return db


def db_config(tmp_path, db):
    return load_config(config_for(tmp_path, f"  compile_commands: {db}\n  source_dir: {tmp_path}\n"))


def test_west_build_database_with_zephyr_flags(tmp_path):
    """Shape of `west build -- -DCMAKE_EXPORT_COMPILE_COMMANDS=ON` (Zephyr, CMake + Ninja)."""
    src = tmp_path / "app" / "src"
    src.mkdir(parents=True)
    (src / "main.c").write_text("int main(void) { return 0; }\n")
    here = tmp_path.as_posix()                 # a command line is shell syntax: backslashes would be escapes
    cmd = ("/opt/zephyr-sdk/arm-zephyr-eabi/bin/arm-zephyr-eabi-gcc -DKERNEL -D__ZEPHYR__=1 "
           f"-DNRF52840_XXAA -I{here}/app/src -isystem /opt/zephyr/include "
           f"-imacros {here}/build/zephyr/include/generated/autoconf.h -mcpu=cortex-m4 -mthumb "
           f"-std=c99 -o CMakeFiles/app.dir/src/main.c.obj -c {here}/app/src/main.c")
    config = db_config(tmp_path, compile_db(tmp_path, [{"directory": str(tmp_path / "build"), "command": cmd,
                                                         "file": str(src / "main.c")}]))
    result = parse_compile_commands(config)
    tu = result.source_files[0]
    assert tu.path == src / "main.c"
    assert {"KERNEL", "__ZEPHYR__=1", "NRF52840_XXAA"} <= set(tu.defines)
    assert src in tu.include_paths and Path("/opt/zephyr/include") in tu.include_paths


def test_platformio_compiledb_with_relative_files(tmp_path):
    """Shape of `pio run -t compiledb`: arguments list, file relative to directory."""
    (tmp_path / "src").mkdir()
    (tmp_path / "include").mkdir()
    (tmp_path / "src" / "main.c").write_text("int main(void) { return 0; }\n")
    args = ["arm-none-eabi-gcc", "-o", ".pio/build/nucleo/src/main.o", "-c", "-std=gnu11", "-mcpu=cortex-m4",
            "-mthumb", "-DPLATFORMIO=60111", "-DSTM32F4xx", "-DUSE_HAL_DRIVER", "-Iinclude", "src/main.c"]
    config = db_config(tmp_path, compile_db(tmp_path, [{"directory": str(tmp_path), "arguments": args,
                                                         "file": "src/main.c"}]))
    tu = parse_compile_commands(config).source_files[0]
    assert tu.path == tmp_path / "src" / "main.c"
    assert {"PLATFORMIO=60111", "STM32F4xx", "USE_HAL_DRIVER"} <= set(tu.defines)
    assert tmp_path / "include" in tu.include_paths
