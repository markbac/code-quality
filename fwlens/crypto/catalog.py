"""
The cryptographic catalogue behind the CBOM: which identifiers in C source mean which asset.

Catalogue files are YAML (see fwlens/crypto/catalog/). Each declares one `library` and its
`entries`. `cbom.extra_catalog_dirs` adds more files; an entry whose `id` matches a bundled
entry of the same library replaces it, so a project can correct or extend the bundled data.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from fwlens.config import ConfigError

PRIMITIVES = ("drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash", "pke", "xof", "kdf",
              "key-agree", "kem", "ae", "combiner", "other", "unknown")
MODES = ("cbc", "ecb", "ccm", "gcm", "cfb", "ofb", "ctr", "other", "unknown")
FUNCTIONS = ("generate", "keygen", "encrypt", "decrypt", "digest", "tag", "keyderive", "sign", "verify",
             "encapsulate", "decapsulate", "other", "unknown")
PROTOCOLS = ("tls", "ssh", "ipsec", "ike", "sstp", "wpa", "other", "unknown")
KINDS = ("algorithm", "protocol", "certificate")
USAGES = ("trust-anchor", "own-certificate", "parse", "verify", "hostname", "verify-disabled", "verify-relaxed",
          "private-key", "other")

_BUNDLED = Path(__file__).parent / "catalog"


@dataclass
class Entry:
    id: str
    name: str
    kind: str = "algorithm"
    primitive: str = "unknown"
    mode: str | None = None
    parameter_set: str | None = None
    curve: str | None = None
    identifiers: list[str] = field(default_factory=list)
    config_macros: list[str] = field(default_factory=list)
    functions: list[str] = field(default_factory=list)
    weak: str | None = None
    hardware: bool = False
    curve_aware: bool = False
    mode_from_name: bool = False
    bits_from_name: bool = False
    protocol: str = "other"
    version: str | None = None
    usage: str = "other"          # for kind certificate: what the code does with certificates


@dataclass
class Library:
    id: str
    name: str
    include_fragments: list[str] = field(default_factory=list)
    dir_names: list[str] = field(default_factory=list)
    entries: dict[str, Entry] = field(default_factory=dict)


_ENTRY_KEYS = {f for f in Entry.__dataclass_fields__}
_LIBRARY_KEYS = {"id", "name", "include_fragments", "dir_names"}


def _strings(value, where: str, key: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(x, str) and x for x in value):
        raise ConfigError(f"{where}: '{key}' must be a list of non-empty strings")
    return list(value)


def _entry(raw, where: str, needs_names: bool = True) -> Entry:
    if not isinstance(raw, dict) or not raw.get("id") or not raw.get("name"):
        raise ConfigError(f"{where}: every entry needs 'id' and 'name'")
    unknown = set(raw) - _ENTRY_KEYS
    if unknown:
        raise ConfigError(f"{where}: entry '{raw['id']}' has unknown key(s) {sorted(unknown)}")
    e = Entry(id=str(raw["id"]), name=str(raw["name"]))
    for key in ("kind", "primitive", "mode", "parameter_set", "curve", "weak", "protocol", "version", "usage"):
        if raw.get(key) is not None:
            setattr(e, key, str(raw[key]))
    for key in ("hardware", "curve_aware", "mode_from_name", "bits_from_name"):
        setattr(e, key, bool(raw.get(key, False)))
    e.identifiers = _strings(raw.get("identifiers"), where, "identifiers")
    e.config_macros = _strings(raw.get("config_macros"), where, "config_macros")
    e.functions = _strings(raw.get("functions"), where, "functions")
    for value, allowed, key in ((e.kind, KINDS, "kind"), (e.primitive, PRIMITIVES, "primitive"),
                                (e.protocol, PROTOCOLS, "protocol"), (e.usage, USAGES, "usage")):
        if value not in allowed:
            raise ConfigError(f"{where}: entry '{e.id}' has {key} '{value}'; use one of {list(allowed)}")
    if e.mode is not None and e.mode not in MODES:
        raise ConfigError(f"{where}: entry '{e.id}' has mode '{e.mode}'; use one of {list(MODES)}")
    bad = [f for f in e.functions if f not in FUNCTIONS]
    if bad:
        raise ConfigError(f"{where}: entry '{e.id}' has unsupported function(s) {bad}; use {list(FUNCTIONS)}")
    if needs_names and not e.identifiers and not e.config_macros:
        raise ConfigError(f"{where}: entry '{e.id}' needs identifiers or config_macros")
    return e


def _read(path: Path, libraries: dict[str, Library]) -> None:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"crypto catalogue {path}: {exc}") from exc
    where = f"crypto catalogue {path.name}"
    if not isinstance(raw, dict) or not isinstance(raw.get("library"), dict) or "entries" not in raw:
        raise ConfigError(f"{where}: needs a 'library' mapping and an 'entries' list")
    lib_raw = raw["library"]
    unknown = set(lib_raw) - _LIBRARY_KEYS
    if unknown or not lib_raw.get("id") or not lib_raw.get("name"):
        raise ConfigError(f"{where}: 'library' needs id and name, and only allows {sorted(_LIBRARY_KEYS)}")
    lib = libraries.setdefault(str(lib_raw["id"]), Library(str(lib_raw["id"]), str(lib_raw["name"])))
    lib.name = str(lib_raw["name"])
    for key in ("include_fragments", "dir_names"):
        if key in lib_raw:
            setattr(lib, key, _strings(lib_raw[key], where, key))
    if not isinstance(raw["entries"], list):
        raise ConfigError(f"{where}: 'entries' must be a list")
    for item in raw["entries"]:
        e = _entry(item, where)
        lib.entries[e.id] = e


def load_catalog(extra_dirs: list[Path] | None = None) -> dict[str, Library]:
    """The bundled catalogue plus any extra directories, later files overriding earlier entries by id."""
    libraries: dict[str, Library] = {}
    for directory in [_BUNDLED, *(extra_dirs or [])]:
        if not directory.is_dir():
            raise ConfigError(f"cbom.extra_catalog_dirs: {directory} is not a directory")
        for path in sorted(directory.glob("*.yaml")) + sorted(directory.glob("*.yml")):
            _read(path, libraries)
    return libraries


class Matcher:
    """Looks an identifier up: exact names first, then the longest `prefix*` pattern."""

    def __init__(self, libraries: dict[str, Library]):
        self._exact: dict[str, tuple[Library, Entry]] = {}
        self._prefix: list[tuple[str, Library, Entry]] = []
        self.config_macros: dict[str, tuple[Library, Entry]] = {}
        for lib in libraries.values():
            for e in lib.entries.values():
                for pattern in e.identifiers:
                    if pattern.endswith("*"):
                        self._prefix.append((pattern[:-1], lib, e))
                    else:
                        self._exact[pattern] = (lib, e)
                for macro in e.config_macros:
                    self.config_macros[macro] = (lib, e)
        self._prefix.sort(key=lambda t: -len(t[0]))
        self._cache: dict[str, tuple[Library, Entry] | None] = {}

    def lookup(self, token: str) -> tuple[Library, Entry] | None:
        if token in self._cache:
            return self._cache[token]
        found = self._exact.get(token)
        if found is None:
            for prefix, lib, e in self._prefix:
                if token.startswith(prefix):
                    found = (lib, e)
                    break
        self._cache[token] = found
        return found


_BITS = re.compile(r"_(128|192|256)(?:_|$)")
_MODE = re.compile(r"_(ecb|cbc|ctr|gcm|ccm|cfb|ofb|xts)\w*$", re.IGNORECASE)


def bits_and_mode(token: str) -> tuple[str | None, str | None]:
    """'EVP_aes_128_gcm' -> ('128', 'gcm'); modes outside the CycloneDX list become 'other'."""
    bits = _BITS.search(token)
    mode = _MODE.search(token)
    found = mode.group(1).lower() if mode else None
    if found and found not in MODES:
        found = "other"
    return (bits.group(1) if bits else None), found
