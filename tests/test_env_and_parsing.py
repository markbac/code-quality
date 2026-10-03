"""
Tests for libclang discovery (#26), system include and target handling (#48).
"""

from pathlib import Path
from types import SimpleNamespace

import pytest

import main as fwlens_main
from fwlens.config import load_config
from fwlens.libclang_locate import LibclangError, locate_libclang
from fwlens.parser.compile_commands import extract_clang_flags
from fwlens.sysinc import is_native, parse_include_search_list, target_args


# --- #26 -----------------------------------------------------------------------

def test_explicit_missing_libclang_path_is_an_error(tmp_path):
    with pytest.raises(LibclangError, match="does not exist"):
        locate_libclang(tmp_path / "nope.so")


def test_explicit_libclang_path_wins_over_env(tmp_path, monkeypatch):
    explicit = tmp_path / "libclang.so"
    explicit.write_text("")
    monkeypatch.setenv("LIBCLANG_PATH", str(tmp_path / "other.so"))
    loc = locate_libclang(explicit)
    assert loc.source == "config" and loc.path == explicit


def test_env_var_used_when_no_explicit_path(tmp_path, monkeypatch):
    env_lib = tmp_path / "libclang-env.so"
    env_lib.write_text("")
    monkeypatch.setenv("LIBCLANG_PATH", str(env_lib))
    loc = locate_libclang(None)
    assert loc.source == "env" and loc.path == env_lib


def test_bad_env_var_is_an_error(tmp_path, monkeypatch):
    monkeypatch.setenv("LIBCLANG_PATH", str(tmp_path / "missing.so"))
    with pytest.raises(LibclangError, match="LIBCLANG_PATH"):
        locate_libclang(None)


def test_bundled_library_is_found_without_config(monkeypatch):
    monkeypatch.delenv("LIBCLANG_PATH", raising=False)
    pytest.importorskip("clang.cindex")
    loc = locate_libclang(None)
    assert loc.source in ("bundled", "system")


# --- #48 -----------------------------------------------------------------------

GCC_VERBOSE = """\
ignoring nonexistent directory "/usr/local/include/x86_64-linux-gnu"
#include "..." search starts here:
#include <...> search starts here:
 /usr/lib/gcc/x86_64-linux-gnu/13/include
 /usr/local/include
 /usr/include
End of search list.
"""


def test_parse_include_search_list():
    assert parse_include_search_list(GCC_VERBOSE) == [
        "/usr/lib/gcc/x86_64-linux-gnu/13/include", "/usr/local/include", "/usr/include",
    ]


def test_target_args():
    assert target_args("arm-none-eabi") == ["--target=arm-none-eabi"]
    assert target_args("native") == [] and target_args("host") == [] and target_args("") == []
    assert is_native("Native") and not is_native("arm-none-eabi")


def test_extract_clang_flags_from_compile_command(tmp_path):
    flags = extract_clang_flags(
        "arm-none-eabi-gcc -std=gnu11 -mcpu=cortex-m4 -mthumb -DFOO -Iinc -include cfg.h -O2 -c a.c",
        tmp_path,
    )
    assert "-std=gnu11" in flags and "-mcpu=cortex-m4" in flags and "-mthumb" in flags
    assert flags[flags.index("-include") + 1] == str((tmp_path / "cfg.h").resolve())
    assert "-DFOO" not in flags and "-O2" not in flags


def test_extract_clang_flags_target_forms(tmp_path):
    assert extract_clang_flags(["clang", "-target", "aarch64-linux-gnu", "-c", "a.c"], tmp_path) == [
        "--target=aarch64-linux-gnu"
    ]
    assert extract_clang_flags(["clang", "--target=riscv32", "-c", "a.c"], tmp_path) == ["--target=riscv32"]


def test_tool_config_keys_are_loaded(tmp_path):
    (tmp_path / "src").mkdir()
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "tool:\n  target: native\n  sysroot: /opt/sys\n  system_include_dirs: [/a, /b]\n"
        "  clang_args: ['-std=c11']\n  auto_detect_includes: false\n  parse_error_threshold: 0.1\n"
        "project:\n  source_dir: src\n"
    )
    tool = load_config(cfg).tool
    assert tool.target == "native" and tool.sysroot == Path("/opt/sys")
    assert tool.system_include_dirs == [Path("/a"), Path("/b")]
    assert tool.clang_args == ["-std=c11"] and tool.auto_detect_includes is False
    assert tool.parse_error_threshold == 0.1


def test_tool_config_defaults_keep_arm_target(tmp_path):
    (tmp_path / "src").mkdir()
    cfg = tmp_path / "config.yaml"
    cfg.write_text("project:\n  source_dir: src\n")
    tool = load_config(cfg).tool
    assert tool.target == "arm-none-eabi" and tool.libclang_path is None


def _cfg(threshold=0.0):
    return SimpleNamespace(tool=SimpleNamespace(parse_error_threshold=threshold))


def test_parse_health_nothing_parsed_always_fails():
    model = SimpleNamespace(parse_stats={"in_scope": 5, "parsed_ok": 0, "files_with_errors": 0})
    assert fwlens_main._parse_health_failed(model, _cfg(), False) is True


def test_parse_health_errors_only_fail_when_requested():
    model = SimpleNamespace(parse_stats={"in_scope": 10, "parsed_ok": 10, "files_with_errors": 3})
    assert fwlens_main._parse_health_failed(model, _cfg(), False) is False
    assert fwlens_main._parse_health_failed(model, _cfg(0.0), True) is True
    assert fwlens_main._parse_health_failed(model, _cfg(0.5), True) is False


def test_parse_health_clean_run_passes():
    model = SimpleNamespace(parse_stats={"in_scope": 10, "parsed_ok": 10, "files_with_errors": 0})
    assert fwlens_main._parse_health_failed(model, _cfg(), True) is False
    assert fwlens_main._parse_health_failed(SimpleNamespace(parse_stats={}), _cfg(), True) is False


def test_native_target_finds_system_headers(tmp_path):
    """End to end: with target native the host compiler's headers are located."""
    import shutil
    cindex = pytest.importorskip("clang.cindex")
    if not shutil.which("gcc") and not shutil.which("cc") and not shutil.which("clang"):
        pytest.skip("no host C compiler to ask for include directories")
    from test_p0_regressions import _config
    from fwlens.config import ToolConfig
    from fwlens.parser.pipeline import run_pipeline

    (tmp_path / "a.c").write_text("#include <stddef.h>\n#include <stdlib.h>\nsize_t f(void) { return sizeof(int); }\n")
    (tmp_path / "config.yaml").write_text("project:\n  source_dir: .\ntool:\n  target: native\n")
    config = _config(tmp_path)
    config.tool = ToolConfig(libclang_path=None, target="native")
    model = run_pipeline(config)
    assert model.parse_stats["parsed_ok"] == 1
    assert model.parse_stats["files_with_errors"] == 0
