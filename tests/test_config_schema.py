"""Unknown-key warnings, format validation, the JSON Schema and config discovery (#77)."""

import inspect
import json
import re
import warnings
from pathlib import Path

import pytest
import yaml

from fwlens import config as config_module
from fwlens.config import ConfigError, ConfigWarning, load_config
from fwlens.config_schema import json_schema, known_keys, unknown_key_messages

ROOT = Path(__file__).resolve().parent.parent

SECTION_VARIABLES = {
    "tool_raw": "tool", "proj_raw": "project", "scope_raw": "scope", "thresh_raw": "thresholds",
    "out_raw": "output", "git_raw": "git", "est_raw": "estimation", "cb_raw": "cost_benefit",
    "rtos_raw": "rtos", "std_raw": "standards",
}


def write(tmp_path, text):
    path = tmp_path / "config.yaml"
    path.write_text(text)
    return path


def test_misspelt_and_unknown_keys_each_warn(tmp_path):
    path = write(tmp_path, "project:\n  source_dir: .\nthresholds:\n  cyclomatic_complexty: 5\nbogus_top: 1\n")
    with pytest.warns(ConfigWarning) as record:
        config = load_config(path)
    messages = [str(w.message) for w in record]
    assert len(messages) == 2
    assert any("thresholds.cyclomatic_complexty" in m and "cyclomatic_complexity" in m for m in messages)
    assert any("'bogus_top'" in m for m in messages)
    assert len(config.warnings) == 2


def test_valid_config_is_silent(tmp_path):
    path = write(tmp_path, "project:\n  source_dir: .\nthresholds:\n  cyclomatic_complexity: 5\n")
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        load_config(path)


def test_nested_list_item_keys_are_checked():
    raw = {"layers": [{"name": "A", "pathz": ["x"]}], "standards": {"enabled": [{"standard": "x", "oops": 1}]}}
    messages = unknown_key_messages(raw)
    assert any("layers[0].pathz" in m and "paths" in m for m in messages)
    assert any("standards.enabled[0].oops" in m for m in messages)


def test_unsupported_output_format_is_rejected(tmp_path):
    path = write(tmp_path, "project:\n  source_dir: .\noutput:\n  formats: [html, hmtl]\n")
    with pytest.raises(ConfigError, match="hmtl"):
        load_config(path)


def test_unsupported_analyse_value_is_rejected(tmp_path):
    path = write(tmp_path, "project:\n  source_dir: .\nscope:\n  analyse: [first-party]\n")
    with pytest.raises(ConfigError, match="first-party"):
        load_config(path)


def test_every_key_load_config_reads_is_a_known_key():
    """Fails when load_config starts reading a key that the schema does not know about."""
    source = inspect.getsource(config_module.load_config)
    known = known_keys()
    missing = []
    for var, section in SECTION_VARIABLES.items():
        for key in re.findall(rf'{var}(?:\.get\(|\[)"(\w+)"', source):
            if key not in known[section]:
                missing.append(f"{section}.{key}")
    for key in re.findall(r'\braw\.get\("(\w+)"', source):
        if key not in known:
            missing.append(key)
    assert not missing, f"load_config reads keys the schema does not list: {missing}"


def test_schema_file_matches_the_dataclasses():
    shipped = json.loads((ROOT / "fwlens" / "config.schema.json").read_text(encoding="utf-8"))
    assert shipped == json_schema(), "regenerate with: fwlens config-schema -o fwlens/config.schema.json"


def test_example_config_validates_against_the_schema():
    jsonschema = pytest.importorskip("jsonschema")
    example = yaml.safe_load((ROOT / "config.example.yaml").read_text(encoding="utf-8"))
    jsonschema.validate(example, json_schema())


def test_schema_rejects_a_typo():
    jsonschema = pytest.importorskip("jsonschema")
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate({"thresholds": {"cyclomatic_complexty": 5}}, json_schema())


def test_example_config_loads_without_warnings(tmp_path):
    (tmp_path / "config.yaml").write_text((ROOT / "config.example.yaml").read_text(encoding="utf-8"))
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        load_config(tmp_path / "config.yaml")


def test_config_is_found_from_a_subdirectory(tmp_path, monkeypatch):
    from fwlens.cli.commands import _CONFIG_FILE

    (tmp_path / ".fwlens.yaml").write_text("project:\n  source_dir: .\n")
    sub = tmp_path / "a" / "b"
    sub.mkdir(parents=True)
    monkeypatch.chdir(sub)
    assert Path(_CONFIG_FILE.convert("config.yaml", None, None)) == tmp_path / ".fwlens.yaml"


def test_explicit_missing_config_still_fails(tmp_path, monkeypatch):
    import click

    from fwlens.cli.commands import _CONFIG_FILE

    monkeypatch.chdir(tmp_path)
    with pytest.raises(click.BadParameter):
        _CONFIG_FILE.convert("other.yaml", None, None)
