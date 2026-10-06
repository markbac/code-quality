"""
Cryptography Bill of Materials as CycloneDX 1.6 JSON (#93).

A static scan of the source for the cryptographic algorithms, protocols and libraries it uses,
matched against the catalogue in fwlens/crypto. It reports what the code names, so it is a
lower bound: runtime configuration, negotiated protocols, keys and calls through function
pointers or wrapper layers are invisible to it. The document says so in its metadata.
"""

from __future__ import annotations

import bisect
import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from fwlens import __version__
from fwlens.config import FwLensConfig
from fwlens.crypto.catalog import Entry, Library, Matcher, bits_and_mode, load_catalog
from fwlens.identity import project_root, relative_posix
from fwlens.model.project import BoundaryClass
from fwlens.sbom import SPEC_VERSION, _app_version, _application_name, _component_dir

MAX_OCCURRENCES = 50
_HEADER_SUFFIXES = {".h", ".hpp"}
_IGNORED_DIRS = {".git", "build", "__pycache__", ".cache", "node_modules", ".pytest_cache", "output", ".pio"}

# Strings, character literals and comments in one pass, so a comment marker inside a string
# (and a quote inside a comment) is not misread.
_LEXICAL = re.compile(
    r'"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'|//[^\n]*|/\*.*?\*/', re.DOTALL)
_IDENT = re.compile(r"[A-Za-z_]\w*")
_INCLUDE = re.compile(r'^[ \t]*#[ \t]*include[ \t]*[<"]([^>"\n]+)[>"]', re.MULTILINE)
_DEFINE = re.compile(r"^[ \t]*#[ \t]*define[ \t]+(\w+)", re.MULTILINE)
_SUITE = re.compile(r"\b(?:MBEDTLS_)?(?:TLS|SSL)_[A-Z0-9_]*?_WITH_[A-Z0-9_]+\b")
_WEAK_SUITE = re.compile(r"_(?:RC4|3DES|DES|DES_CBC|NULL|EXPORT\w*)_|_(?:MD5)$")
_CURVE = re.compile(
    r"\b(?:MBEDTLS_ECP_DP_|NID_X9_62_|NID_)?(secp\d{3}[rk]1|prime256v1|ed25519|curve25519|x25519|"
    r"brainpoolP\d{3}r1|BP\d{3}R1)\b", re.IGNORECASE)
_CURVE_ALIASES = {"prime256v1": "secp256r1", "x25519": "curve25519"}


def _blank(match: re.Match, keep_strings: bool) -> str:
    text = match.group(0)
    if keep_strings and text[0] in "\"'":
        return text
    return "".join(c if c == "\n" else " " for c in text)


def _clean(text: str, keep_strings: bool) -> str:
    """Comments (and optionally strings) replaced by spaces; offsets and line numbers are preserved."""
    return _LEXICAL.sub(lambda m: _blank(m, keep_strings), text)


def _curve(raw: str) -> str:
    c = raw.lower()
    return _CURVE_ALIASES.get(c, c)


@dataclass
class _Asset:
    library: Library | None
    entry: Entry
    mode: str | None
    bits: str | None
    curve: str | None
    occurrences: list[tuple[str, int]] = field(default_factory=list)
    count: int = 0
    kinds: set[str] = field(default_factory=set)
    identifiers: set[str] = field(default_factory=set)


def _scan_files(config: FwLensConfig, result, root: Path) -> list[Path]:
    """Translation units whose boundary class is scanned, plus first-party headers in include paths."""
    scopes = set(config.cbom.scan_scopes)
    files = {tu.path for tu in result.source_files if tu.boundary_class.value in scopes}
    if "first_party" in scopes:
        include_dirs = {p for tu in result.source_files for p in tu.include_paths}
        for inc in sorted(include_dirs):
            try:
                inc.relative_to(root)
            except ValueError:
                continue
            if not inc.is_dir() or inc.name in _IGNORED_DIRS:
                continue
            for f in sorted(inc.iterdir()):
                if f.suffix.lower() not in _HEADER_SUFFIXES:
                    continue
                other = [b for b in (BoundaryClass.SDK, BoundaryClass.THIRD_PARTY_LIB)
                         if _component_dir(f, b, config, root) and b.value not in scopes]
                if not other:
                    files.add(f)
    return sorted(files)


# Words that make a project path look like a cryptographic library even when the catalogue has no
# entry for it. Whole words only, so "shared" and "details" do not match "sha" and "tls".
_CRYPTO_WORDS = {"crypto", "crypt", "cryptlib", "openssl", "ssl", "tls", "dtls", "aes", "rsa", "ecc", "ecdsa",
                 "cipher", "mbedtls", "wolfssl", "wolfcrypt", "hsm", "cmac", "sha", "sha1", "sha2", "sha256", "md5"}
_CRYPTO_PARTS = ("crypt", "cycur", "openssl", "cipher", "mbedtls", "wolfssl")
_LIB_FILES = {".a", ".lib", ".o", ".obj", ".so", ".dll", ".h", ".hpp", ".c"}


def _crypto_named(part: str) -> bool:
    low = part.lower()
    words = [w for w in re.split(r"[^a-z0-9]+", low) if w]
    return any(s in low for s in _CRYPTO_PARTS) or any(w in _CRYPTO_WORDS for w in words)


def _project_evidence(config: FwLensConfig, result, root: Path) -> list[tuple[str, str, Path]]:
    """
    Paths the project file mentions, as (what, description, path): every translation unit, include
    directory and group, and for an IAR project every file of any type (a library delivered as an
    archive is listed there but is no translation unit) and each additional linker library.
    """
    out: list[tuple[str, str, Path]] = []
    for tu in result.source_files:
        out.append(("source file", relative_posix(tu.path, root), tu.path))
        out.extend(("include path", relative_posix(p, root), p) for p in tu.include_paths)
    out.extend(("include path", relative_posix(p, root), p) for p in getattr(result, "global_includes", []))
    out.extend(("group", name, Path(name)) for name in getattr(result, "iar_groups", {}))
    if config.project.mode == "ewp":
        out.extend(_ewp_paths(config, root))
    return out


def _ewp_paths(config: FwLensConfig, root: Path) -> list[tuple[str, str, Path]]:
    import xml.etree.ElementTree as ET

    from fwlens.parser.ewp import _expand_path
    if config.project.ewp is None:
        return []
    try:
        tree = ET.parse(config.project.ewp)
    except (OSError, ET.ParseError):
        return []
    found: list[tuple[str, str, Path]] = []
    for file_el in tree.getroot().iter("file"):
        name = file_el.find("name")
        if name is not None and name.text:
            path = _expand_path(name.text.strip(), config.project.proj_dir, config.project.toolkit_dir)
            if path is not None:
                found.append(("project file", relative_posix(path, root), path))
    for opt in tree.getroot().iter("option"):
        name = opt.find("name")
        if name is not None and name.text in ("IlinkAdditionalLibs", "IlinkOutputFile"):
            if name.text != "IlinkAdditionalLibs":
                continue
            for state in opt.findall("state"):
                if state.text:
                    path = _expand_path(state.text.strip(), config.project.proj_dir, config.project.toolkit_dir)
                    if path is not None:
                        found.append(("linker library", relative_posix(path, root), path))
    return found


def build_cbom(config: FwLensConfig, now: datetime | None = None) -> dict:
    from fwlens.parser.pipeline import read_project
    result = read_project(config)
    root = project_root(config)
    libraries = load_catalog(config.cbom.extra_catalog_dirs)
    matcher = Matcher(libraries)

    assets: dict[tuple, _Asset] = {}
    present: dict[str, str] = {}              # library id -> why it is considered present
    suites: dict[str, list[tuple[str, int]]] = {}

    def record(lib: Library | None, entry: Entry, token: str, where: str, line: int, kind: str,
               file_curves: list[str]) -> None:
        bits, mode = (bits_and_mode(token) if (entry.bits_from_name or entry.mode_from_name) else (None, None))
        bits = bits if entry.bits_from_name else None
        mode = mode if entry.mode_from_name else entry.mode
        curves: list[str | None] = list(file_curves) if entry.curve_aware and file_curves else [entry.curve]
        for curve in curves:
            a = assets.setdefault((lib.id if lib else "", entry.id, mode, bits, curve),
                                  _Asset(lib, entry, mode, bits, curve))
            a.count += 1
            a.kinds.add(kind)
            a.identifiers.add(token)
            if len(a.occurrences) < MAX_OCCURRENCES:
                a.occurrences.append((where, line))

    scanned = _scan_files(config, result, root)
    for path in scanned:
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        with_strings = _clean(raw, keep_strings=True)
        code = _clean(raw, keep_strings=False)
        newlines = [m.start() for m in re.finditer("\n", raw)]

        def line_of(offset: int) -> int:
            return bisect.bisect_left(newlines, offset) + 1

        where = relative_posix(path, root)
        for inc in _INCLUDE.findall(with_strings):
            low = inc.lower()
            for lib in libraries.values():
                if any(frag.lower() in low for frag in lib.include_fragments):
                    present.setdefault(lib.id, f"#include {inc} in {where}")
        for m in _SUITE.finditer(code):
            suites.setdefault(m.group(0), []).append((where, line_of(m.start())))

        file_curves = sorted({_curve(m.group(1)) for m in _CURVE.finditer(code)})
        defined = {m.start(1): m.group(1) for m in _DEFINE.finditer(code)}
        for m in _IDENT.finditer(code):
            token = m.group(0)
            hit = matcher.lookup(token)
            if hit:
                present.setdefault(hit[0].id, f"identifier {token} in {where}")
                record(hit[0], hit[1], token, where, line_of(m.start()), "used", file_curves)
            elif m.start() in defined and token in matcher.config_macros:
                lib, entry = matcher.config_macros[token]
                present.setdefault(lib.id, f"#define {token} in {where}")
                record(lib, entry, token, where, line_of(m.start()), "configured", file_curves)

    # A library named anywhere in the project file counts as present, even when its own sources are
    # outside the scanned scopes or it is only a precompiled archive.
    dir_lookup = {n.lower(): lib for lib in libraries.values() for n in lib.dir_names}
    unknown_libraries: dict[str, str] = {}
    library_dirs = {s.lower() for s in [*config.scope.sdk, *config.scope.third_party_lib]}
    for what, description, path in _project_evidence(config, result, root):
        try:
            parts = list(path.relative_to(root).parts)
        except ValueError:
            parts = list(path.parts)
        if what not in ("include path", "group"):
            stem = path.stem.lower()
            suffix = path.suffix.lower()
            names = parts[:-1] + ([path.stem] if suffix in _LIB_FILES else [])
            file_part = path.stem if suffix in _LIB_FILES else None
        else:
            stem, names, file_part = "", parts, None
        owners = []
        for part in names:
            owner = dir_lookup.get(part.lower())
            if owner is None and stem:
                owner = next((lib for key, lib in dir_lookup.items() if key in stem), None)
            if owner:
                owners.append(owner)
                present.setdefault(owner.id, f"{what} {description} in the project")
        if owners:
            continue                      # the catalogue already accounts for this path
        for part in names:
            if file_part is not None and part == file_part and path.suffix.lower() not in (".a", ".lib") \
                    and part not in parts[:-1]:
                continue                  # a source or header file is not a library by its name
            if _crypto_named(part) and part.lower() not in {"include", "inc", "src"} and (
                    what == "linker library" or path.suffix.lower() in (".a", ".lib")
                    or any(p.lower() in library_dirs for p in parts[:-1])):
                unknown_libraries.setdefault(part, f"{what} {description} in the project")
    # a crypto-looking name that no catalogue library accounts for
    known_names = {n.lower() for lib in libraries.values() for n in lib.dir_names}
    unknown_libraries = {k: v for k, v in unknown_libraries.items()
                         if k.lower() not in known_names and not any(k.lower() in n or n in k.lower() for n in known_names)}

    now = now or datetime.now(timezone.utc)
    components: list[dict] = []
    refs: dict[tuple, str] = {}
    for key in sorted(assets, key=lambda k: tuple("" if x is None else str(x) for x in k)):
        a = assets[key]
        e = a.entry
        name = e.name
        if a.bits:
            name = f"{name}-{a.bits}"
        if a.mode and e.mode_from_name:
            name = f"{name}-{a.mode.upper()}"
        if a.curve and e.curve_aware:
            name = f"{name} ({a.curve})"
        ref = "crypto-" + re.sub(r"[^A-Za-z0-9._-]+", "-", "-".join(str(x) for x in key if x)).strip("-")
        refs[key] = ref
        if e.kind == "protocol":
            props: dict = {"type": e.protocol}
            if e.version:
                props["version"] = e.version
            crypto = {"assetType": "protocol", "protocolProperties": props}
        else:
            algo: dict = {"primitive": e.primitive}
            if a.bits or e.parameter_set:
                algo["parameterSetIdentifier"] = a.bits or e.parameter_set
            if a.mode:
                algo["mode"] = a.mode
            if a.curve:
                algo["curve"] = a.curve
            if e.hardware:
                algo["executionEnvironment"] = "hardware"
            if e.functions:
                algo["cryptoFunctions"] = list(e.functions)
            crypto = {"assetType": "algorithm", "algorithmProperties": algo}
        weak = e.weak or ("ECB mode leaks plaintext patterns" if a.mode == "ecb" else None)
        properties = [
            {"name": "fwlens:evidence-kind", "value": ",".join(sorted(a.kinds))},
            {"name": "fwlens:identifiers", "value": ", ".join(sorted(a.identifiers)[:10])},
            {"name": "fwlens:occurrence-count", "value": str(a.count)},
        ]
        if a.library:
            properties.append({"name": "fwlens:library", "value": a.library.name})
        if a.count > len(a.occurrences):
            properties.append({"name": "fwlens:occurrences-truncated", "value": f"{len(a.occurrences)} of {a.count} listed"})
        if weak:
            properties.append({"name": "fwlens:weak", "value": weak})
        components.append({
            "type": "cryptographic-asset", "bom-ref": ref, "name": name, "cryptoProperties": crypto,
            "evidence": {"occurrences": [{"location": w, "line": ln} for w, ln in a.occurrences]},
            "properties": properties,
        })

    if suites:
        names = sorted(suites)
        occ = sorted({o for n in names for o in suites[n]})[:MAX_OCCURRENCES]
        properties = [{"name": "fwlens:evidence-kind", "value": "used"},
                      {"name": "fwlens:occurrence-count", "value": str(sum(len(v) for v in suites.values()))}]
        weak_names = [n for n in names if _WEAK_SUITE.search(n)]
        if weak_names:
            properties.append({"name": "fwlens:weak", "value": "weak cipher suite(s): " + ", ".join(weak_names)})
        components.append({
            "type": "cryptographic-asset", "bom-ref": "crypto-cipher-suites", "name": "TLS cipher suites named in source",
            "cryptoProperties": {"assetType": "protocol", "protocolProperties": {
                "type": "tls", "cipherSuites": [{"name": n, "identifiers": [n]} for n in names]}},
            "evidence": {"occurrences": [{"location": w, "line": ln} for w, ln in occ]},
            "properties": properties,
        })
        refs[("cipher-suites",)] = "crypto-cipher-suites"

    lib_components, provides = [], []
    for lib_id in sorted(present):
        lib = libraries[lib_id]
        ref = f"library-{lib_id}"
        lib_components.append({
            "type": "library", "bom-ref": ref, "name": lib.name,
            "properties": [{"name": "fwlens:evidence-kind", "value": "library-present"},
                           {"name": "fwlens:evidence", "value": present[lib_id]}]})
        mine = sorted(refs[k] for k in assets if k[0] == lib_id)
        if mine:
            provides.append({"ref": ref, "provides": mine})

    for name, evidence in sorted(unknown_libraries.items()):
        lib_components.append({
            "type": "library", "bom-ref": "library-unlisted-" + re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-"),
            "name": name,
            "properties": [{"name": "fwlens:evidence-kind", "value": "library-name-match"},
                           {"name": "fwlens:evidence", "value": evidence},
                           {"name": "fwlens:note", "value": "the name suggests cryptography but the library is not in "
                                                            "the crypto catalogue, so no algorithms are listed: add "
                                                            "an entry under cbom.extra_catalog_dirs"}]})

    app_version, app_source = _app_version(config, root)
    app: dict = {"type": "firmware", "bom-ref": "application", "name": _application_name(config, root),
                 "properties": [{"name": "fwlens:version-source", "value": app_source}]}
    if app_version:
        app["version"] = app_version
    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": now.isoformat(timespec="seconds"),
            "lifecycles": [{"phase": "pre-build"}],
            "tools": {"components": [{"type": "application", "name": "fwlens", "version": __version__}]},
            "component": app,
            "properties": [
                {"name": "fwlens:method", "value": "static scan of source for names in the crypto catalogue"},
                {"name": "fwlens:completeness",
                 "value": "detected usage only, not a complete inventory: runtime configuration, negotiated "
                          "protocols, keys, and calls through function pointers or wrapper layers are not visible"},
                {"name": "fwlens:scanned-scopes", "value": ",".join(config.cbom.scan_scopes)},
                {"name": "fwlens:files-scanned", "value": str(len(scanned))},
            ],
        },
        "components": lib_components + components,
        "dependencies": [{"ref": "application", "dependsOn": sorted(c["bom-ref"] for c in components)}, *provides],
    }


def write_cbom(config: FwLensConfig, path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(build_cbom(config), indent=2) + "\n", encoding="utf-8")
    return path
