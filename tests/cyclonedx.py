"""Validation of generated documents against the official CycloneDX 1.6 JSON schema."""

import json
from pathlib import Path

import pytest

SCHEMA_DIR = Path(__file__).parent / "fixtures" / "cyclonedx"


def validate_bom(document: dict) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    referencing = pytest.importorskip("referencing")
    from referencing.jsonschema import DRAFT7

    registry = referencing.Registry()
    for name in ("bom-1.6.schema.json", "spdx.schema.json", "jsf-0.82.schema.json"):
        schema = json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))
        registry = registry.with_resource(schema["$id"], DRAFT7.create_resource(schema))
        registry = registry.with_resource(name, DRAFT7.create_resource(schema))
    main = json.loads((SCHEMA_DIR / "bom-1.6.schema.json").read_text(encoding="utf-8"))
    jsonschema.Draft7Validator(main, registry=registry).validate(document)
