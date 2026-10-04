"""SBOM generation (#92): CycloneDX 1.6 output, version and licence detection, unknowns marked."""

from __future__ import annotations

import json
import subprocess

import pytest
from click.testing import CliRunner

import main as fwlens_main
from fwlens.config import load_config
from fwlens.sbom import build_sbom, detect_licenses, detect_version
from tests.cyclonedx import validate_bom

FILES = {
    "src/main.c": '#include "app.h"\n#include "lfs.h"\n#include "FreeRTOS.h"\nint main(void) { return app(); }\n',
    "Inc/app.h": "int app(void);\n",
    "src/app.c": '#include "app.h"\nint app(void) { return 0; }\n',
    "Lib/littlefs/lfs.h": "#define LFS_VERSION_MAJOR 2\n#define LFS_VERSION_MINOR 9\nint lfs_mount(void);\n",
    "Lib/littlefs/lfs.c": '#include "lfs.h"\nint lfs_mount(void) { return 0; }\n',
    "Lib/littlefs/LICENSE.md": ("Copyright (c) 2022 Example\n\nRedistribution and use in source and binary forms, with or "
                                "without modification, are permitted provided that the following conditions are met:\n"
                                "Neither the name of the copyright holder nor the names of its contributors may be used.\n"),
    "Lib/FreeRTOS/VERSION": "10.4.3\n",
    "Lib/FreeRTOS/FreeRTOS.h": "/* SPDX-License-Identifier: MIT */\nint rtos(void);\n",
    "Lib/FreeRTOS/tasks.c": "/* SPDX-License-Identifier: MIT */\n#include \"FreeRTOS.h\"\nint rtos(void) { return 0; }\n",
    "Drivers/mystery/mystery.c": "int mystery(void) { return 1; }\n",
}


@pytest.fixture
def project(tmp_path):
    for name, text in FILES.items():
        f = tmp_path / name
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)
    return tmp_path


def make_config(root, extra=""):
    cfg = root / "config.yaml"
    cfg.write_text("project:\n  source_dir: .\nscope:\n  first_party: [src, Inc]\n  sdk: [Drivers]\n"
                   "  third_party_lib: [Lib]\ntool:\n  target: native\n" + extra)
    return load_config(cfg)


def by_name(doc):
    return {c["name"]: c for c in doc["components"]}


def prop(component, name):
    return next(p["value"] for p in component["properties"] if p["name"] == name)


def test_sbom_validates_against_the_cyclonedx_1_6_schema(project):
    doc = build_sbom(make_config(project))
    validate_bom(doc)
    assert doc["bomFormat"] == "CycloneDX" and doc["specVersion"] == "1.6"


def test_the_schema_check_actually_rejects_bad_documents(project):
    doc = build_sbom(make_config(project))
    doc["components"][0]["type"] = "not-a-type"
    with pytest.raises(Exception):
        validate_bom(doc)


def test_components_versions_and_licences_are_read_from_the_tree(project):
    comps = by_name(build_sbom(make_config(project)))
    assert set(comps) == {"littlefs", "FreeRTOS", "mystery"}
    assert comps["FreeRTOS"]["version"] == "10.4.3" and prop(comps["FreeRTOS"], "fwlens:version-source") == "VERSION"
    assert comps["FreeRTOS"]["licenses"] == [{"license": {"id": "MIT"}}]
    assert comps["littlefs"]["version"] == "2.9"
    assert comps["littlefs"]["licenses"] == [{"license": {"id": "BSD-3-Clause"}}]
    assert comps["FreeRTOS"]["type"] == "library" and comps["mystery"]["type"] == "framework"


def test_unknown_version_and_licence_are_marked_not_guessed(project):
    mystery = by_name(build_sbom(make_config(project)))["mystery"]
    assert "version" not in mystery and "licenses" not in mystery
    assert prop(mystery, "fwlens:version-source") == "unknown" and prop(mystery, "fwlens:license-source") == "unknown"


def test_hashes_are_stable_and_change_with_content(project):
    config = make_config(project)
    first = by_name(build_sbom(config))["FreeRTOS"]["hashes"][0]["content"]
    assert by_name(build_sbom(config))["FreeRTOS"]["hashes"][0]["content"] == first
    (project / "Lib/FreeRTOS/tasks.c").write_text("/* SPDX-License-Identifier: MIT */\nint rtos(void) { return 2; }\n")
    assert by_name(build_sbom(config))["FreeRTOS"]["hashes"][0]["content"] != first


def test_dependencies_follow_includes(project):
    doc = build_sbom(make_config(project))
    refs = {c["name"]: c["bom-ref"] for c in doc["components"]}
    app = next(d for d in doc["dependencies"] if d["ref"] == "application")
    assert set(app["dependsOn"]) == {refs["littlefs"], refs["FreeRTOS"]}
    assert doc["metadata"]["component"]["type"] == "firmware"


def test_linked_is_unknown_without_a_map_and_follows_a_map(project):
    assert prop(by_name(build_sbom(make_config(project)))["littlefs"], "fwlens:linked") == "unknown"
    (project / "p.map").write_text(" .text 0x08000000 0x100 build/lfs.o\n .text 0x08000100 0x10 build/main.o\n")
    config = make_config(project)
    config.project.map_file = project / "p.map"
    comps = by_name(build_sbom(config))
    assert prop(comps["littlefs"], "fwlens:linked") == "true"
    assert prop(comps["FreeRTOS"], "fwlens:linked") == "false"


def test_declared_components_override_detection(project):
    extra = ("sbom:\n  application_version: 4.2.0\n  components:\n    - name: mystery-driver\n      path: Drivers/mystery\n"
             "      version: '1.0'\n      license: 'MIT OR Apache-2.0'\n      supplier: Example Ltd\n"
             "      purl: pkg:generic/mystery@1.0\n")
    doc = build_sbom(make_config(project, extra))
    validate_bom(doc)
    comps = by_name(doc)
    assert "mystery" not in comps and comps["mystery-driver"]["version"] == "1.0"
    assert comps["mystery-driver"]["licenses"] == [{"expression": "MIT OR Apache-2.0"}]
    assert comps["mystery-driver"]["supplier"] == {"name": "Example Ltd"}
    assert doc["metadata"]["component"]["version"] == "4.2.0"


def test_include_files_lists_hashed_file_components_and_still_validates(project):
    doc = build_sbom(make_config(project, "sbom:\n  include_files: true\n"))
    validate_bom(doc)
    assert {c["name"] for c in by_name(doc)["FreeRTOS"]["components"]} == {"Lib/FreeRTOS/FreeRTOS.h", "Lib/FreeRTOS/tasks.c"}


def test_git_submodule_style_directory_uses_git_describe(project):
    sub = project / "Lib" / "FreeRTOS"
    (sub / "VERSION").unlink()
    for args in (["init", "-q"], ["add", "-A"], ["-c", "user.name=t", "-c", "user.email=t@e.x", "commit", "-qm", "x"],
                 ["tag", "V10.5.0"]):
        subprocess.run(["git", *args], cwd=sub, check=True, capture_output=True)
    version, source = detect_version(sub, [sub / "FreeRTOS.h"])
    assert (version, source) == ("V10.5.0", "git describe")


def test_licence_detection_helpers(tmp_path):
    (tmp_path / "LICENSE").write_text("Apache License\nVersion 2.0, January 2004\n")
    assert detect_licenses(tmp_path, []) == (["Apache-2.0"], "LICENSE (text matched)")
    other = tmp_path / "x"
    other.mkdir()
    (other / "COPYING").write_text("some custom terms\n")
    assert detect_licenses(other, []) == ([], "COPYING present but not recognised")


def test_cli_writes_the_file_and_the_report_format_does_too(project, monkeypatch):
    make_config(project)
    monkeypatch.chdir(project)
    res = CliRunner().invoke(fwlens_main.cli, ["sbom", "--config", "config.yaml", "--output", "out/sbom.json"])
    assert res.exit_code == 0, res.output
    doc = json.loads((project / "out" / "sbom.json").read_text())
    validate_bom(doc)
    assert "3 component(s), 1 without a version" in " ".join(res.output.split())
