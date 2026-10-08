"""
Config key checking and the JSON Schema for config.yaml.

Both are generated from the dataclasses in fwlens.config, so a field added there becomes a
known key and a schema property without a second edit. tests/test_config_schema.py keeps
load_config and this module in step.
"""

from __future__ import annotations

import dataclasses
import difflib
import types
import typing
from pathlib import Path
from typing import Any

from fwlens import config as _cfg

# config.yaml section -> dataclass whose fields are the section's keys.
_SECTIONS: dict[str, type] = {
    "tool": _cfg.ToolConfig,
    "project": _cfg.ProjectConfig,
    "scope": _cfg.ScopeConfig,
    "thresholds": _cfg.ThresholdConfig,
    "output": _cfg.OutputConfig,
    "git": _cfg.GitConfig,
    "estimation": _cfg.EstimationConfig,
    "cost_benefit": _cfg.CostBenefitConfig,
    "rtos": _cfg.RTOSConfig,
    "standards": _cfg.StandardsConfig,
    "pr_check": _cfg.PRCheckConfig,
    "match": _cfg.MatchConfig,
    "sbom": _cfg.SbomConfig,
    "cbom": _cfg.CbomConfig,
    "architecture": _cfg.ArchitectureConfig,
}

# Top-level keys that are not a section: FwLensConfig fields with a direct YAML key, and
# `layers`, which is a list of LayerRule.
_TOP_LEVEL_SCALARS = ("iar_compat_defines", "entry_points", "assert_names")

# Keys inside list items of a section.
_ITEM_KEYS: dict[tuple[str, ...], type | tuple[str, ...]] = {
    ("layers",): _cfg.LayerRule,
    ("standards", "enabled"): _cfg.StandardSelection,
    ("standards", "imports"): ("tool", "path"),
    ("sbom", "components"): _cfg.SbomComponent,
    ("architecture", "components"): ("name", "units"),
}

SUPPORTED_FORMATS = ("html", "csv", "json", "plots", "diagrams", "sarif", "sbom", "cbom")


def _fields(cls: type) -> list[str]:
    return [f.name for f in dataclasses.fields(cls)]


def known_keys() -> dict[str, Any]:
    """The accepted structure: {top-level key: None (scalar) | [section keys] | nested}."""
    known: dict[str, Any] = {name: _fields(cls) for name, cls in _SECTIONS.items()}
    for key in _TOP_LEVEL_SCALARS:
        known[key] = None
    known["layers"] = None
    return known


def _suggest(key: str, candidates: list[str]) -> str:
    match = difflib.get_close_matches(key, candidates, n=1, cutoff=0.6)
    return f" Did you mean '{match[0]}'?" if match else ""


def unknown_key_messages(raw: Any) -> list[str]:
    """One message per key in the raw YAML that FWLens does not read."""
    messages: list[str] = []
    if not isinstance(raw, dict):
        return messages
    known = known_keys()
    top = list(known)

    for key, value in raw.items():
        if key not in known:
            messages.append(f"Unknown config key '{key}'.{_suggest(str(key), top)}")
            continue
        names = known[key]
        if names is None or not isinstance(value, dict):
            continue
        for sub in value:
            if sub not in names:
                messages.append(f"Unknown config key '{key}.{sub}'.{_suggest(str(sub), names)}")

    def check_items(path: tuple[str, ...], spec) -> None:
        node: Any = raw
        for part in path:
            node = node.get(part) if isinstance(node, dict) else None
        if not isinstance(node, list):
            return
        names = _fields(spec) if isinstance(spec, type) else list(spec)
        for i, item in enumerate(node):
            if isinstance(item, dict):
                for sub in item:
                    if sub not in names:
                        messages.append(
                            f"Unknown config key '{'.'.join(path)}[{i}].{sub}'.{_suggest(str(sub), names)}")

    for path, spec in _ITEM_KEYS.items():
        check_items(path, spec)
    return messages


# --- JSON Schema ------------------------------------------------------------------------

def _json_type(tp: Any) -> dict:
    origin = typing.get_origin(tp)
    args = typing.get_args(tp)
    if origin in (typing.Union, types.UnionType):
        non_none = [a for a in args if a is not type(None)]
        schema = _json_type(non_none[0]) if len(non_none) == 1 else {}
        if len(non_none) != len(args) and "type" in schema:
            schema = {**schema, "type": [schema["type"], "null"]}
        return schema
    if origin in (list, typing.List):
        return {"type": "array", "items": _json_type(args[0]) if args else {}}
    if origin in (dict, typing.Dict) or tp is dict:
        return {"type": "object"}
    if tp is list:
        return {"type": "array"}
    if tp is bool:
        return {"type": "boolean"}
    if tp is int:
        return {"type": "integer"}
    if tp is float:
        return {"type": "number"}
    if tp in (str, Path):
        return {"type": "string"}
    return {}


def _section_schema(cls: type) -> dict:
    hints = typing.get_type_hints(cls)
    props = {f.name: _json_type(hints[f.name]) for f in dataclasses.fields(cls)}
    return {"type": "object", "properties": props, "additionalProperties": False}


def json_schema() -> dict:
    """JSON Schema (draft 2020-12) for config.yaml."""
    properties: dict[str, Any] = {name: _section_schema(cls) for name, cls in _SECTIONS.items()}

    for section in properties.values():
        section["type"] = ["object", "null"]   # an empty section (all keys commented out) is null in YAML

    output = properties["output"]["properties"]
    output["formats"] = {"type": "array", "items": {"enum": list(SUPPORTED_FORMATS)}}
    properties["scope"]["properties"]["analyse"] = {
        "type": "array", "items": {"enum": list(_cfg._BOUNDARY_CLASSES)}}
    properties["standards"]["properties"]["enabled"] = {
        "type": "array", "items": _section_schema(_cfg.StandardSelection)}
    properties["standards"]["properties"]["imports"] = {
        "type": "array",
        "items": {"type": "object", "properties": {"tool": {"type": "string"}, "path": {"type": "string"}},
                  "additionalProperties": False},
    }

    properties["architecture"]["properties"]["components"] = {
        "type": "array",
        "items": {"type": "object", "properties": {"name": {"type": "string"}, "units": {"type": "array", "items": {"type": "string"}}},
                  "required": ["name", "units"], "additionalProperties": False}}

    component = _section_schema(_cfg.SbomComponent)
    component["required"] = ["name", "path"]
    properties["sbom"]["properties"]["components"] = {"type": "array", "items": component}

    hints = typing.get_type_hints(_cfg.FwLensConfig)
    for key in _TOP_LEVEL_SCALARS:
        properties[key] = _json_type(hints[key]) or {"type": "array"}
    layer = _section_schema(_cfg.LayerRule)
    layer["required"] = ["name"]
    properties["layers"] = {"type": "array", "items": layer}

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://raw.githubusercontent.com/markbac/code-quality/main/fwlens/config.schema.json",
        "title": "FWLens config.yaml",
        "type": "object",
        "properties": properties,
        "additionalProperties": False,
    }
