"""
CLI smoke tests and end-to-end integration tests (Issue #34).
"""

from click.testing import CliRunner

from fwlens.cli.commands import cli


def test_cli_full_workflow_smoke(tmp_path):
    runner = CliRunner()
    cfg_file = tmp_path / "config.yaml"
    reports_dir = tmp_path / "output" / "reports"
    exports_dir = tmp_path / "output" / "exports"

    cfg_content = (
        "project:\n"
        f"  source_dir: {tmp_path.as_posix()}\n"
        "output:\n"
        f"  reports_dir: {reports_dir.as_posix()}\n"
        f"  exports_dir: {exports_dir.as_posix()}\n"
        "  formats: [html, csv, json]\n"
    )
    cfg_file.write_text(cfg_content)
    (tmp_path / "main.c").write_text("int main(void) { return 0; }\n")

    # 1. doctor
    res_doc = runner.invoke(cli, ["doctor", "--config", str(cfg_file)])
    assert res_doc.exit_code == 0, res_doc.output

    # 2. analyze
    res_an = runner.invoke(cli, ["analyze", "--config", str(cfg_file)])
    assert res_an.exit_code == 0, res_an.output

    # 3. report
    res_rep = runner.invoke(cli, ["report", "--config", str(cfg_file)])
    assert res_rep.exit_code == 0, res_rep.output
    assert (reports_dir / "fwlens_report.html").exists()
    assert (exports_dir / "fwlens_results.json").exists()
