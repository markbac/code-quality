"""
Read a hand-kept components file (for example a product's ``components.yaml``) into CycloneDX
components for the SBOM (#97).

The file records what a source scan cannot see: a bootloader in protected flash, modem firmware
delivered as a binary, a metrology processor, the toolchain. Sections are ``metadata``,
``product``, and any of ``application_firmware`` (with ``first_party`` and ``third_party``
lists), ``application_bootloader``, ``modem_firmware`` and ``metrology_firmware`` and, more
generally, any top-level list of components. An empty value or "unknown" is left out of the SBOM
and listed as a gap, never guessed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

UNKNOWN = {"", "unknown", "tbc", "tbd", "n/a", "none"}

# Component type names used in these files, as CycloneDX types
_TYPES = {
    "device": "device", "firmware": "firmware", "operating-system": "operating-system", "library": "library",
    "framework": "framework", "application": "application", "toolchain": "application", "platform": "platform",
    "container": "container", "data": "data", "file": "file", "device-driver": "device-driver",
}
_SPDX_ID = re.compile(r"^[A-Za-z0-9.\-+]+$")
_SPDX_KNOWN = {
    "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "MPL-2.0", "Zlib", "Unlicense", "GPL-2.0-only",
    "GPL-2.0-or-later", "GPL-3.0-only", "GPL-3.0-or-later", "LGPL-2.1-only", "LGPL-2.1-or-later", "LGPL-3.0-only",
    "LGPL-3.0-or-later", "CC0-1.0", "BSL-1.0", "EPL-2.0", "0BSD",
}


class ComponentsFileError(ValueError):
    pass


def known(value) -> str | None:
    """A scalar as text, or None when it is empty or a placeholder such as "unknown"."""
    if value is None:
        return None
    text = " ".join(str(value).split())
    return None if text.lower() in UNKNOWN else text


@dataclass
class Declared:
    section: str
    name: str
    version: str | None
    type: str
    supplier: str | None = None
    supplier_url: str | None = None
    contact: str | None = None
    license: str | None = None
    spdx: str | None = None
    license_notes: str | None = None
    purl: str | None = None
    cpe: str | None = None
    location: str | None = None
    description: str | None = None
    notes: str | None = None
    copyright: str | None = None
    cve_checked: str | None = None
    compliance_actions: list[str] = field(default_factory=list)

    def gaps(self) -> list[str]:
        out = []
        if self.version is None:
            out.append("version")
        if self.license is None and self.spdx is None:
            out.append("licence")
        if self.cve_checked is None:
            out.append("CVE check")
        return out


@dataclass
class ComponentsFile:
    path: Path
    metadata: dict
    product: Declared | None
    components: list[Declared]

    def gaps(self) -> dict[str, list[str]]:
        found = {c.name: c.gaps() for c in self.components}
        if self.product and self.product.version is None:
            found[self.product.name] = ["version"]
        return {k: v for k, v in found.items() if v}


def _declared(section: str, raw: dict) -> Declared:
    name = known(raw.get("name"))
    if not name:
        raise ComponentsFileError(f"a component in '{section}' has no name")
    kind = str(raw.get("type") or "library").strip().lower()
    if kind not in _TYPES:
        raise ComponentsFileError(f"component '{name}' has type '{kind}', expected one of {sorted(_TYPES)}")
    actions = raw.get("compliance_actions") or []
    if isinstance(actions, str):
        actions = [actions]
    return Declared(
        section=section, name=name, version=known(raw.get("version")), type=_TYPES[kind],
        supplier=known(raw.get("supplier")), supplier_url=known(raw.get("supplier_url")),
        contact=known(raw.get("supplier_contact")), license=known(raw.get("license")),
        spdx=known(raw.get("spdx_expression")), license_notes=known(raw.get("license_notes")),
        purl=known(raw.get("purl")), cpe=known(raw.get("cpe")), location=known(raw.get("location")),
        description=known(raw.get("description")), notes=known(raw.get("notes")), copyright=known(raw.get("copyright")),
        cve_checked=known(raw.get("cve_checked")), compliance_actions=[a for a in map(known, actions) if a])


def _entries(section: str, value) -> list[Declared]:
    """A section is a list of components, or a mapping whose values are lists of components."""
    if isinstance(value, list):
        return [_declared(section, v) for v in value if isinstance(v, dict)]
    if isinstance(value, dict):
        if "name" in value:
            return [_declared(section, value)]
        out: list[Declared] = []
        for sub, items in value.items():
            out += _entries(f"{section}.{sub}", items)
        return out
    return []


def load_components_file(path: Path) -> ComponentsFile:
    path = Path(path)
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ComponentsFileError(f"cannot read components file {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ComponentsFileError(f"{path} is not valid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise ComponentsFileError(f"{path} must be a YAML mapping of sections")
    product = _declared("product", raw["product"]) if isinstance(raw.get("product"), dict) else None
    components: list[Declared] = []
    for section, value in raw.items():
        if section in ("metadata", "product"):
            continue
        components += _entries(section, value)
    return ComponentsFile(path, raw.get("metadata") or {}, product, components)


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-").lower() or "component"


def _license(d: Declared) -> list[dict]:
    if d.spdx:
        return [{"expression": d.spdx}]
    if not d.license:
        return []
    entry: dict
    if d.license in _SPDX_KNOWN:
        entry = {"license": {"id": d.license}}
    else:
        entry = {"license": {"name": d.license}}
    if d.license_notes:
        entry["license"]["text"] = {"contentType": "text/plain", "content": d.license_notes}
    return [entry]


def to_component(d: Declared, ref: str) -> dict:
    """One declared component as a CycloneDX component. Only what the file states is written."""
    out: dict = {"type": d.type, "bom-ref": ref, "name": d.name}
    if d.version:
        out["version"] = d.version
    supplier = {k: v for k, v in (("name", d.supplier), ("url", [d.supplier_url] if d.supplier_url else None),
                                  ("contact", [{"email": d.contact}] if d.contact and "@" in d.contact else None)) if v}
    if supplier:
        out["supplier"] = supplier
    if d.description:
        out["description"] = d.description
    if d.copyright:
        out["copyright"] = d.copyright
    if d.purl:
        out["purl"] = d.purl
    if d.cpe:
        out["cpe"] = d.cpe
    licenses = _license(d)
    if licenses:
        out["licenses"] = licenses
    props = [{"name": "fwlens:evidence", "value": "components file"}, {"name": "fwlens:section", "value": d.section}]
    for name, value in (("fwlens:location", d.location), ("fwlens:notes", d.notes), ("fwlens:cve-checked", d.cve_checked)):
        if value:
            props.append({"name": name, "value": value})
    props += [{"name": "fwlens:compliance-action", "value": a} for a in d.compliance_actions]
    gaps = d.gaps()
    if gaps:
        props.append({"name": "fwlens:gaps", "value": ", ".join(gaps)})
    out["properties"] = props
    return out


def to_product(d: Declared, ref: str, version: str | None) -> dict:
    comp = to_component(d, ref)
    if version and "version" not in comp:
        comp["version"] = version
    return comp


def refs_for(components: list[Declared]) -> list[str]:
    seen: dict[str, int] = {}
    out = []
    for c in components:
        base = f"declared-{_slug(c.name)}"
        seen[base] = seen.get(base, 0) + 1
        out.append(base if seen[base] == 1 else f"{base}-{seen[base]}")
    return out
