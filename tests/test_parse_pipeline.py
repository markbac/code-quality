"""Worker pool: timeouts, crashes, in-memory config and the parse cache (#62, #63)."""

import time

import pytest
from click.testing import CliRunner

import cparse
import main as fwlens_main
from fwlens.parser.pipeline import run_pipeline

GOOD = "int ok(int a) { return a + 1; }\n"


def _write(root, sources):
    for name, text in sources.items():
        (root / name).write_text(text)
    (root / "config.yaml").write_text("project:\n  source_dir: .\n")




def test_hung_parse_is_killed_and_reported_as_timeout(tmp_path, capsys):
    _write(tmp_path, {"good.c": GOOD, "slow.c": GOOD})
    config = cparse.make_config(tmp_path)
    start = time.monotonic()
    model = run_pipeline(config, jobs=2, timeout=3, use_cache=False, _parse_fn=cparse.slow_parse)
    assert time.monotonic() - start < 60
    assert model.parse_stats["parsed_ok"] == 1
    assert model.parse_stats["failed"] == 1
    assert model.parse_stats["files_with_errors"] == 1  # what --fail-on-parse-error gates on
    assert "good.c" in {m.path.name for m in model.modules if m.functions}
    out = capsys.readouterr().out
    assert "timeout" in out and "slow.c" in out


def test_crashing_worker_fails_only_its_file(tmp_path):
    _write(tmp_path, {"a.c": GOOD, "boom.c": GOOD, "b.c": "int other(void) { return 2; }\n"})
    model = run_pipeline(cparse.make_config(tmp_path), jobs=1, timeout=30, use_cache=False,
                         _parse_fn=cparse.crashing_parse)
    assert model.parse_stats["failed"] == 1
    assert model.parse_stats["parsed_ok"] == 2


def test_workers_use_the_in_memory_config(tmp_path):
    _write(tmp_path, {"a.c": GOOD})
    config = cparse.make_config(tmp_path)
    config.tool.clang_args = ["-DONLY_IN_MEMORY"]
    config.tool.target = "native"
    model = run_pipeline(config, jobs=1, use_cache=False, _parse_fn=cparse.echo_config_parse)
    messages = [d["message"] for m in model.modules for d in m.parse_diagnostics]
    assert messages == ["Echo: -DONLY_IN_MEMORY|native"]


def test_second_run_uses_cache_and_changed_define_invalidates(tmp_path, capsys):
    _write(tmp_path, {"a.c": "int f(void) {\n#ifdef X\n return 1;\n#else\n return 2;\n#endif\n}\n"})
    config = cparse.make_config(tmp_path)

    run_pipeline(config, jobs=1)
    assert "from cache" not in capsys.readouterr().out

    run_pipeline(config, jobs=1)
    assert "1 from cache" in capsys.readouterr().out

    config.tool.clang_args = ["-DX"]
    run_pipeline(config, jobs=1)
    assert "from cache" not in capsys.readouterr().out


def test_cache_invalidated_by_changed_header(tmp_path, capsys):
    _write(tmp_path, {"a.c": '#include "h.h"\nint f(void) { return K; }\n', "h.h": "#define K 1\n"})
    config = cparse.make_config(tmp_path)
    run_pipeline(config, jobs=1)
    capsys.readouterr()
    (tmp_path / "h.h").write_text("#define K 2\n")
    run_pipeline(config, jobs=1)
    assert "from cache" not in capsys.readouterr().out


def test_no_cache_option_skips_cache(tmp_path, capsys):
    _write(tmp_path, {"a.c": GOOD})
    config = cparse.make_config(tmp_path)
    run_pipeline(config, jobs=1)
    capsys.readouterr()
    run_pipeline(config, jobs=1, use_cache=False)
    assert "from cache" not in capsys.readouterr().out


@pytest.mark.parametrize("command", ["analyze", "report", "export"])
def test_cli_accepts_jobs_timeout_no_cache(command, tmp_path, monkeypatch):
    (tmp_path / "config.yaml").write_text("project:\n  source_dir: .\n")
    seen = {}

    def fake(*a, **k):
        seen.update(k)
        raise SystemExit(0)

    monkeypatch.setattr("fwlens.cli.commands._run_pipeline", fake)
    result = CliRunner().invoke(fwlens_main.cli, [command, "--config", str(tmp_path / "config.yaml"),
                                                  "--jobs", "1", "--timeout", "5", "--no-cache"])
    assert result.exit_code == 0, result.output
    assert (seen["jobs"], seen["timeout"], seen["no_cache"]) == (1, 5.0, True)


def test_workers_that_cannot_start_fail_the_run_instead_of_hanging(tmp_path, monkeypatch):
    _write(tmp_path, {"a.c": GOOD, "b.c": GOOD})
    monkeypatch.setattr("fwlens.parser.pipeline._worker_main", cparse.dying_worker_main)
    start = time.monotonic()
    model = run_pipeline(cparse.make_config(tmp_path), jobs=2, use_cache=False)
    assert time.monotonic() - start < 60
    assert model.parse_stats["parsed_ok"] == 0
    assert model.parse_stats["failed"] == 2
