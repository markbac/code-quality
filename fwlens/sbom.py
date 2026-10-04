"""
Software Bill of Materials as CycloneDX 1.6 JSON (#92).

The inventory comes from the source tree and the project description, not from a package
manager: first-party sources are the application, and every SDK or third-party directory named
in `scope` (or declared in `sbom.components`) is a component. A version or licence that cannot
be read is left out and marked unknown, never guessed.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from fwlens import __version__
from fwlens.config import FwLensConfig, SbomComponent
from fwlens.identity import project_root, relative_posix
from fwlens.model.project import BoundaryClass

SPEC_VERSION = "1.6"
_SOURCE_SUFFIXES = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".s", ".asm", ".ld", ".icf"}
_IGNORED_DIRS = {".git", "build", "__pycache__", ".cache", "node_modules", ".pytest_cache", "output", ".pio"}
_INCLUDE_RE = re.compile(r'^[ \t]*#[ \t]*include[ \t]*[<"]([^>"\n]+)[>"]', re.MULTILINE)
_SPDX_RE = re.compile(r"SPDX-License-Identifier:\s*([A-Za-z0-9.\-+ ()]+?)\s*(?:\*/|-->|$)")
_MAX_LICENSE_SCAN = 600

# SPDX ids that are written as `license.id`; anything else is written as a name or expression.
_KNOWN_SPDX = {
    "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "BSD-4-Clause", "ISC", "MPL-2.0", "Zlib", "Unlicense",
    "GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0-only", "GPL-3.0-or-later", "LGPL-2.1-only", "LGPL-2.1-or-later",
    "LGPL-3.0-only", "LGPL-3.0-or-later", "CC0-1.0", "BSL-1.0", "EPL-2.0", "0BSD", "Beerware", "Libpng",
}


@dataclass
class _Component:
    name: str
    root: Path
    classification: str                   # sdk | third_party_lib | unknown | manual
    files: list[Path] = field(default_factory=list)
    declared: SbomComponent | None = None
    version: str | None = None
    version_source: str = "unknown"
    licenses: list[str] = field(default_factory=list)
    license_source: str = "unknown"


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-") or "component"


def _sha256(path: Path) -> str | None:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 16), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def _walk_sources(directory: Path) -> list[Path]:
    out = []
    for base, dirs, names in os.walk(directory):
        dirs[:] = sorted(d for d in dirs if d not in _IGNORED_DIRS)
        out += [Path(base) / n for n in sorted(names) if Path(n).suffix.lower() in _SOURCE_SUFFIXES]
    return out


def _aggregate_hash(files: list[Path], root: Path) -> tuple[str, int]:
    """SHA-256 over the sorted lines 'relative/path:sha256-of-content'; unreadable files are skipped."""
    lines = []
    for f in files:
        digest = _sha256(f)
        if digest:
            lines.append(f"{relative_posix(f, root)}:{digest}")
    lines.sort()
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest(), len(lines)


# --- version -----------------------------------------------------------------------------

_PLAIN_VERSION = re.compile(r"^v?(\d+(?:\.\d+){0,3}[\w.+\-]*)$")
_MACRO_VERSION = re.compile(r'#\s*define\s+(\w*VERSION(?:_STR(?:ING)?)?)\s+"v?(\d+\.\d+(?:\.\d+)?[\w.+\-]*)"')
_MACRO_PART = re.compile(r"#\s*define\s+(\w+?)_?VERSION_?(MAJOR|MINOR|PATCH|REVISION)\s+\(?\s*(\d+)")


def detect_version(directory: Path, files: list[Path]) -> tuple[str | None, str]:
    for name in ("VERSION", "VERSION.txt", "version.txt"):
        f = directory / name
        if f.is_file():
            first = (f.read_text(encoding="utf-8", errors="replace").strip().splitlines() or [""])[0].strip()
            m = _PLAIN_VERSION.match(first)
            if m:
                return m.group(1), name
    for name in ("library.json", "package.json"):
        f = directory / name
        if f.is_file():
            try:
                v = json.loads(f.read_text(encoding="utf-8")).get("version")
            except (OSError, ValueError, AttributeError):
                v = None
            if isinstance(v, str) and v:
                return v, name
    parts: dict[str, dict[str, str]] = {}
    for f in [x for x in files if x.suffix.lower() in (".h", ".hpp")][:400]:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        m = _MACRO_VERSION.search(text)
        if m:
            return m.group(2), f"macro {m.group(1)} in {f.name}"
        for p in _MACRO_PART.finditer(text):
            parts.setdefault(p.group(1), {}).setdefault(p.group(2), p.group(3))
    for prefix, found in parts.items():
        if "MAJOR" in found and "MINOR" in found:
            return ".".join(found[k] for k in ("MAJOR", "MINOR", "PATCH") if k in found), f"{prefix} version macros"
    if (directory / ".git").exists():
        out = _git(directory, "describe", "--tags", "--always")
        if out:
            return out, "git describe"
    return None, "unknown"


def _git(directory: Path, *args: str) -> str | None:
    try:
        p = subprocess.run(["git", "-C", str(directory), *args], capture_output=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return None
    out = p.stdout.decode("utf-8", errors="replace").strip()
    return out if p.returncode == 0 and out else None


# --- licence -----------------------------------------------------------------------------

def _identify_license_text(text: str) -> str | None:
    t = " ".join(text.lower().split())
    if "apache license" in t and "version 2.0" in t:
        return "Apache-2.0"
    if "mozilla public license" in t and "2.0" in t:
        return "MPL-2.0"
    if "gnu lesser general public license" in t or "gnu library general public license" in t:
        ver = "3.0" if "version 3" in t else "2.1"
        return f"LGPL-{ver}-or-later" if "any later version" in t else f"LGPL-{ver}-only"
    if "gnu general public license" in t:
        ver = "3.0" if "version 3" in t else "2.0"
        return f"GPL-{ver}-or-later" if "any later version" in t else f"GPL-{ver}-only"
    if "permission is hereby granted, free of charge" in t:
        return "MIT"
    if "redistribution and use in source and binary forms" in t:
        return "BSD-3-Clause" if "neither the name" in t or "may be used to endorse" in t else "BSD-2-Clause"
    if "permission to use, copy, modify, and/or distribute this software for any purpose" in t:
        return "ISC"
    return None


def detect_licenses(directory: Path, files: list[Path]) -> tuple[list[str], str]:
    found: list[str] = []
    for f in files[:_MAX_LICENSE_SCAN]:
        try:
            with open(f, encoding="utf-8", errors="replace") as fh:
                head = "".join(fh.readline() for _ in range(40))
        except OSError:
            continue
        for m in _SPDX_RE.finditer(head):
            expr = " ".join(m.group(1).split())
            if expr not in found:
                found.append(expr)
    if found:
        return sorted(found), "SPDX-License-Identifier headers"
    for entry in sorted(directory.iterdir()) if directory.is_dir() else []:
        if entry.is_file() and re.match(r"(?i)(licen[cs]e|copying)", entry.name):
            ident = _identify_license_text(entry.read_text(encoding="utf-8", errors="replace"))
            if ident:
                return [ident], f"{entry.name} (text matched)"
            return [], f"{entry.name} present but not recognised"
    return [], "unknown"


def _license_entry(expr: str) -> dict:
    if expr in _KNOWN_SPDX:
        return {"license": {"id": expr}}
    if re.search(r"\b(AND|OR|WITH)\b", expr):
        return {"expression": expr}
    return {"license": {"name": expr}}


# --- component discovery ----------------------------------------------------------------

def _component_dir(path: Path, boundary: BoundaryClass, config: FwLensConfig, root: Path) -> tuple[Path, str] | None:
    """The directory a file's component lives in, and its classification; None for first-party."""
    try:
        rel_parts = path.relative_to(root).parts
        base = root
    except ValueError:
        rel_parts, base = path.parts, Path(path.anchor)
    wanted = {BoundaryClass.SDK: config.scope.sdk, BoundaryClass.THIRD_PARTY_LIB: config.scope.third_party_lib}
    if boundary in wanted:
        fragments = [s.lower() for s in wanted[boundary]]
        for i, part in enumerate(rel_parts[:-1]):
            if part.lower() in fragments:
                depth = i + 2 if i + 2 < len(rel_parts) else i + 1       # one level below the fragment
                return base.joinpath(*rel_parts[:depth]), boundary.value
    if boundary == BoundaryClass.UNKNOWN:
        depth = 1 if len(rel_parts) > 1 else 0
        if depth:
            return base.joinpath(*rel_parts[:depth]), "unknown"
    return None


def _application_name(config: FwLensConfig, root: Path) -> str:
    p = config.project
    for candidate in (p.ewp, p.uvprojx, p.cproject):
        if candidate:
            return candidate.stem
    return (p.source_dir or p.proj_dir or root).resolve().name or "firmware"


def _app_version(config: FwLensConfig, root: Path) -> tuple[str | None, str]:
    if config.sbom.application_version:
        return config.sbom.application_version, "sbom.application_version"
    described = _git(root, "describe", "--tags", "--always") if (root / ".git").exists() or _git(root, "rev-parse", "--git-dir") else None
    return (described, "git describe") if described else (None, "unknown")


def _linked_stems(config: FwLensConfig) -> set[str] | None:
    path = config.project.map_file
    if path is None or not path.exists():
        return None
    from fwlens.parser.mapfile import parse_linker_mapfile
    objects = parse_linker_mapfile(path)
    return {name.split(".")[0] for name in objects} if objects else None


def build_sbom(config: FwLensConfig, now: datetime | None = None) -> dict:
    from fwlens.parser.pipeline import read_project
    result = read_project(config)
    root = project_root(config)
    linked = _linked_stems(config)
    declared = list(config.sbom.components)

    components: dict[Path, _Component] = {}
    app_files: list[Path] = []
    file_component: dict[Path, Path | None] = {}

    for d in declared:
        components[d.path] = _Component(d.name, d.path, "manual", declared=d)

    def owner(path: Path, boundary: BoundaryClass) -> Path | None:
        for d in declared:
            try:
                path.relative_to(d.path)
                return d.path
            except ValueError:
                continue
        found = _component_dir(path, boundary, config, root)
        if found:
            directory, classification = found
            components.setdefault(directory, _Component(directory.name, directory, classification))
            return directory
        return None

    for tu in result.source_files:
        key = owner(tu.path, tu.boundary_class)
        file_component[tu.path] = key
        if key is None:
            app_files.append(tu.path)

    for comp in components.values():
        comp.files = _walk_sources(comp.root) if comp.root.is_dir() else []
        if comp.declared is not None:
            d = comp.declared
            comp.version, comp.version_source = (d.version, "sbom.components") if d.version else detect_version(comp.root, comp.files)
            if d.license:
                comp.licenses, comp.license_source = [d.license], "sbom.components"
            else:
                comp.licenses, comp.license_source = detect_licenses(comp.root, comp.files)
        else:
            comp.version, comp.version_source = detect_version(comp.root, comp.files)
            comp.licenses, comp.license_source = detect_licenses(comp.root, comp.files)

    # First-party headers: those in include paths under the project that no component owns.
    include_dirs = {p for tu in result.source_files for p in tu.include_paths}
    for inc in sorted(include_dirs):
        try:
            inc.relative_to(root)
        except ValueError:
            continue
        if inc.is_dir() and not any(_inside(inc, c) for c in components) and inc.name not in _IGNORED_DIRS:
            app_files += [f for f in sorted(inc.glob("*")) if f.suffix.lower() in (".h", ".hpp")]
    app_files = sorted(set(app_files))

    # Dependencies from #include names that resolve to exactly one component.
    name_owner: dict[str, set[Path | None]] = {}
    for comp in components.values():
        for f in comp.files:
            name_owner.setdefault(f.name, set()).add(comp.root)
    for f in app_files:
        name_owner.setdefault(f.name, set()).add(None)

    def includes_of(files: list[Path]) -> set[Path | None]:
        hit: set[Path | None] = set()
        for f in files:
            try:
                text = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for inc in _INCLUDE_RE.findall(text):
                owners = name_owner.get(Path(inc).name, set())
                if len(owners) == 1:
                    hit |= owners
        return hit

    now = now or datetime.now(timezone.utc)
    refs: dict[Path | None, str] = {None: "application"}
    for i, comp in enumerate(sorted(components.values(), key=lambda c: (c.name.lower(), str(c.root)))):
        refs[comp.root] = f"component-{i + 1}-{_slug(comp.name)}"

    app_hash, app_count = _aggregate_hash(app_files, root)
    app_version, app_version_source = _app_version(config, root)
    app_name = _application_name(config, root)
    metadata_component: dict = {
        "type": "firmware", "bom-ref": refs[None], "name": app_name,
        "hashes": [{"alg": "SHA-256", "content": app_hash}],
        "properties": [
            {"name": "fwlens:file-count", "value": str(app_count)},
            {"name": "fwlens:hash-method", "value": "sha256 over sorted 'path:sha256' lines of the first-party sources and headers"},
            {"name": "fwlens:version-source", "value": app_version_source},
        ],
    }
    if app_version:
        metadata_component["version"] = app_version

    tools = [{"type": "application", "name": "fwlens", "version": __version__}]
    if config.project.mode == "ewp":
        tools.append({"type": "application", "name": "IAR Embedded Workbench (project file read, not run)"})
    elif config.project.mode == "keil":
        tools.append({"type": "application", "name": "Keil uVision (project file read, not run)"})

    out_components, dependencies = [], []
    for comp in sorted(components.values(), key=lambda c: refs[c.root]):
        digest, count = _aggregate_hash(comp.files, root)
        decl = comp.declared
        entry: dict = {
            "type": "framework" if comp.classification == "sdk" else "library",
            "bom-ref": refs[comp.root], "name": comp.name,
            "hashes": [{"alg": "SHA-256", "content": digest}],
        }
        if comp.version:
            entry["version"] = comp.version
        if decl is not None:
            if decl.supplier:
                entry["supplier"] = {"name": decl.supplier}
            if decl.purl:
                entry["purl"] = decl.purl
            if decl.description:
                entry["description"] = decl.description
        if comp.licenses:
            entry["licenses"] = [_license_entry(x) for x in comp.licenses]
        stems = {f.stem for f in comp.files if f.suffix.lower() in (".c", ".cc", ".cpp", ".s")}
        state = "unknown" if linked is None else ("true" if stems & linked else "false")
        entry["properties"] = [
            {"name": "fwlens:classification", "value": comp.classification},
            {"name": "fwlens:path", "value": relative_posix(comp.root, root)},
            {"name": "fwlens:file-count", "value": str(count)},
            {"name": "fwlens:hash-method", "value": "sha256 over sorted 'path:sha256' lines of the component's source files"},
            {"name": "fwlens:version-source", "value": comp.version_source},
            {"name": "fwlens:license-source", "value": comp.license_source},
            {"name": "fwlens:linked", "value": state},
        ]
        if config.sbom.include_files:
            entry["components"] = [
                {"type": "file", "bom-ref": f"{refs[comp.root]}:{relative_posix(f, root)}",
                 "name": relative_posix(f, root),
                 "hashes": [{"alg": "SHA-256", "content": h}]}
                for f in comp.files if (h := _sha256(f))]
        out_components.append(entry)
        deps = sorted(refs[o] for o in includes_of(comp.files) if o is not None and o != comp.root)
        dependencies.append({"ref": refs[comp.root], "dependsOn": deps})
    app_deps = sorted(refs[o] for o in includes_of(app_files) if o is not None)
    dependencies.insert(0, {"ref": refs[None], "dependsOn": app_deps})

    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": now.isoformat(timespec="seconds"),
            "lifecycles": [{"phase": "pre-build"}],
            "tools": {"components": tools},
            "component": metadata_component,
            "properties": [
                {"name": "fwlens:method", "value": "source tree and project file scan"},
                {"name": "fwlens:completeness",
                 "value": "components found under the project's scope directories and sbom.components; "
                          "versions and licences only where they can be read from the tree"},
            ],
        },
        "components": out_components,
        "dependencies": dependencies,
    }


def _inside(path: Path, component: Path) -> bool:
    try:
        path.relative_to(component)
        return True
    except ValueError:
        return False


def write_sbom(config: FwLensConfig, path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(build_sbom(config), indent=2) + "\n", encoding="utf-8")
    return path
