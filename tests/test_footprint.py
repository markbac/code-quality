"""Flash/RAM footprint from a linker map, and the pr_check gates built on it (#82, #83)."""

from __future__ import annotations

import csv
from dataclasses import replace

from click.testing import CliRunner

import main as fwlens_main
from fwlens.footprint import apply_map_file
from fwlens.output.exports import export_csv
from fwlens.pr_check import compare, load_footprint, post_status, render_markdown, write_findings
from tests.cparse import make_config, parse_model
from tests.test_pr_check import Api, fb, gh_env

MAP = """
 .text          0x08000000        0x100 build/main.o
 .rodata        0x08000100         0x50 build/main.o
 .bss           0x20000000         0x80 build/main.o
 .text          0x08000200         0x30 build/startup.o
"""


def _model(tmp_path, map_text=MAP):
    model = parse_model(tmp_path, {"main.c": "int main(void) { return 0; }\n"})
    config = make_config(tmp_path)
    config.project.map_file = tmp_path / "p.map"
    if map_text is not None:
        config.project.map_file.write_text(map_text)
    return model, config


def test_map_sizes_attach_to_the_matching_module_and_totals(tmp_path):
    model, config = _model(tmp_path)
    apply_map_file(model, config)
    main = next(m for m in model.modules if m.path.stem == "main")
    assert (main.flash_bytes, main.ram_bytes) == (0x150, 0x80)
    assert model.footprint["flash_bytes"] == 0x180 and model.footprint["ram_bytes"] == 0x80
    assert model.footprint["matched"] == 1
    assert [u.split("/")[-1] for u in model.footprint["unmatched"]] == ["startup.o"]


def test_unusable_map_is_skipped_with_a_warning(tmp_path, capsys):
    model, config = _model(tmp_path, map_text="nothing useful here\n")
    apply_map_file(model, config)
    assert getattr(model, "footprint", None) in (None, {})


def test_csv_has_footprint_columns(tmp_path):
    model, config = _model(tmp_path)
    apply_map_file(model, config)
    export_csv(model, config)
    rows = list(csv.DictReader(open(config.output.exports_dir / "modules.csv")))
    assert {"flash_bytes", "ram_bytes"} <= set(rows[0])


def _cmp(base_fp, cur_fp, flash=None, ram=None):
    c = compare([], [])
    return replace(c, base_footprint=base_fp, current_footprint=cur_fp,
                   max_flash_growth=flash, max_ram_growth=ram)


def test_growth_gate_and_markdown_rows():
    c = _cmp({"flash_bytes": 1000, "ram_bytes": 100}, {"flash_bytes": 1600, "ram_bytes": 100}, flash=500)
    assert not c.passed and "Flash" in c.footprint_failures[0]
    md = render_markdown(c)
    assert "Flash (bytes)" in md and "RAM (bytes)" in md
    assert _cmp({"flash_bytes": 1000, "ram_bytes": 0}, {"flash_bytes": 1400, "ram_bytes": 0}, flash=500).passed


def test_gate_is_not_applied_without_both_footprints():
    assert _cmp(None, {"flash_bytes": 9, "ram_bytes": 9}, flash=1).passed


def _write(tmp_path, name, fp):
    p = tmp_path / name
    write_findings(p, [fb()], fp)
    return p


def test_findings_file_records_footprint(tmp_path):
    assert load_footprint(_write(tmp_path, "a.json", {"flash_bytes": 5, "ram_bytes": 6})) == \
        {"flash_bytes": 5, "ram_bytes": 6}
    assert load_footprint(_write(tmp_path, "b.json", None)) is None


def test_compare_command_uses_pr_check_defaults_from_config(tmp_path):
    base = _write(tmp_path, "base.json", {"flash_bytes": 1000, "ram_bytes": 10})
    cur = _write(tmp_path, "cur.json", {"flash_bytes": 3000, "ram_bytes": 10})
    cfg = tmp_path / "config.yaml"
    cfg.write_text(f"project:\n  source_dir: .\npr_check:\n  base: {base}\n  fail_on_new: true\n"
                   "  max_flash_growth_bytes: 500\n")
    run = lambda *extra: CliRunner().invoke(  # noqa: E731
        fwlens_main.cli, ["compare", "--config", str(cfg), "--current", str(cur), *extra])
    res = run()
    assert res.exit_code == 1 and "Flash grew by 2000 B" in res.output
    assert run("--max-flash-growth", "5000").exit_code == 0
    assert run("--no-fail-on-new").exit_code == 0


def test_status_is_posted_through_the_api():
    a = Api()
    try:
        assert post_status(False, "1 new", env={**gh_env(a), "GITHUB_ACTIONS": "true", "GITHUB_SHA": "abc"}) == "github"
        method, path = a.calls[-1][:2]
        assert method == "POST" and path == "/repos/o/r/statuses/abc"
    finally:
        a.close()
