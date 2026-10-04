"""Path keys resolve the same way regardless of the working directory (#64)."""

import os

from fwlens.config import load_config


CONFIG = """\
project:
  source_dir: src
  proj_dir: proj
  toolkit_dir: kit
tool:
  libclang_path: libs/libclang.so
  sysroot: sysroot
  system_include_dirs: [inc/a, ../inc/b]
"""


def _load_from(cwd, config_file):
    old = os.getcwd()
    os.chdir(cwd)
    try:
        return load_config(config_file)
    finally:
        os.chdir(old)


def test_input_paths_resolve_relative_to_config_not_cwd(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "config.yaml").write_text(CONFIG)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()

    a = _load_from(project, project / "config.yaml")
    b = _load_from(elsewhere, project / "config.yaml")

    def inputs(c):
        return (c.project.source_dir, c.project.proj_dir, c.project.toolkit_dir,
                c.tool.libclang_path, c.tool.sysroot, c.tool.system_include_dirs)

    assert inputs(a) == inputs(b)
    assert a.tool.libclang_path == (project / "libs" / "libclang.so").resolve()
    assert a.project.toolkit_dir == (project / "kit").resolve()
    assert a.project.proj_dir == (project / "proj").resolve()
    assert a.tool.system_include_dirs == [(project / "inc" / "a").resolve(), (tmp_path / "inc" / "b").resolve()]


def test_output_paths_stay_relative_to_cwd(tmp_path):
    (tmp_path / "config.yaml").write_text("project:\n  source_dir: .\n")
    elsewhere = tmp_path / "run"
    elsewhere.mkdir()
    cfg = _load_from(elsewhere, tmp_path / "config.yaml")
    assert cfg.output.reports_dir == (elsewhere / "output" / "reports").resolve()
