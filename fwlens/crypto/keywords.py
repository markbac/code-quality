"""
Keyword autodetection for the CBOM: an identifier the catalogue does not list is split into words
and matched against phrases such as "aes" or "sha 256" (fwlens/crypto/keywords.yaml). It finds
wrapper functions and vendor libraries by what they are called, so it is a weaker kind of evidence
than a catalogue hit and the CBOM marks it as such.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path

import yaml

from fwlens.config import ConfigError
from fwlens.crypto.catalog import Entry, Library, _entry

_BUNDLED = Path(__file__).parent / "keywords.yaml"
_WORDS = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")
_BITS = {"128", "192", "256"}
_MODES = {"ecb", "cbc", "ctr", "gcm", "ccm", "cfb", "ofb", "xts"}
_MODE_VALUES = {"ecb", "cbc", "ccm", "gcm", "cfb", "ofb", "ctr"}


@dataclass
class Keyword:
    phrases: list[tuple[str, ...]]
    context: bool
    entry: Entry


@dataclass
class Hit:
    entry: Entry
    bits: str | None
    mode: str | None


def words_of(token: str) -> list[str]:
    return [w.lower() for w in _WORDS.findall(token)]


def _slug(name: str) -> str:
    return "kw-" + re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def _parse(items, where: str) -> list[Keyword]:
    if not isinstance(items, list):
        raise ConfigError(f"{where}: keywords must be a list")
    out = []
    for raw in items:
        if not isinstance(raw, dict) or not raw.get("name"):
            raise ConfigError(f"{where}: every keyword needs 'name' and 'match'")
        raw = dict(raw)
        match = raw.pop("match", None)
        context = bool(raw.pop("context", False))
        if not isinstance(match, list) or not match or not all(isinstance(m, str) and m.strip() for m in match):
            raise ConfigError(f"{where}: keyword '{raw['name']}' needs 'match' as a list of phrases")
        raw.setdefault("id", _slug(str(raw["name"])))
        phrases = [tuple(w.lower() for w in re.split(r"[\s_]+", m.strip()) if w) for m in match]
        out.append(Keyword(phrases, context, _entry(raw, where, needs_names=False)))
    return out


class Keywords:
    def __init__(self, keywords: list[Keyword], context_words: set[str]):
        self._ordered = sorted(((p, k) for k in keywords for p in k.phrases), key=lambda t: -len(t[0]))
        self._context = context_words
        self._cache: dict[str, list[Hit]] = {}

    def match(self, token: str) -> list[Hit]:
        if token in self._cache:
            return self._cache[token]
        words = words_of(token)
        used: set[int] = set()
        found: list[tuple[Keyword, int]] = []
        for phrase, kw in self._ordered:
            n = len(phrase)
            for i in range(len(words) - n + 1):
                if tuple(words[i:i + n]) == phrase and not used.intersection(range(i, i + n)):
                    used.update(range(i, i + n))
                    found.append((kw, i))
                    break
        bits = next((w for w in words if w in _BITS), None)
        mode = next((w for w in words if w in _MODES), None)
        has_context = bool(self._context.intersection(words))
        hits: list[Hit] = []
        seen: set[str] = set()
        for kw, _ in found:
            if kw.context and not has_context or kw.entry.id in seen:
                continue
            seen.add(kw.entry.id)
            e = kw.entry
            hits.append(Hit(e, bits if e.bits_from_name else None,
                            (mode if mode in _MODE_VALUES else "other" if mode else None) if e.mode_from_name else e.mode))
        self._cache[token] = hits
        return hits

    def first_primitive(self, text: str) -> Entry | None:
        """The first keyword entry for a name, used to fill the gaps in an entry the user wrote."""
        hits = self.match(text)
        return hits[0].entry if hits else None


def load_keywords(extra: list[dict] | None = None) -> Keywords:
    try:
        raw = yaml.safe_load(_BUNDLED.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"keywords {_BUNDLED}: {exc}") from exc
    keywords = _parse(raw["keywords"], "bundled keywords")
    if extra:
        added = _parse(extra, "cbom.keywords")
        by_id = {k.entry.id: k for k in keywords}
        for k in added:
            by_id[k.entry.id] = k                  # the same name replaces the bundled keyword
        keywords = list(by_id.values())
    return Keywords(keywords, {str(w) for w in raw.get("context_words", [])})


def ignored(token: str, patterns: list[str]) -> bool:
    return any(fnmatchcase(token, p) for p in patterns)


def add_apis(libraries: dict[str, Library], apis: list[dict], keywords: Keywords) -> None:
    """
    Function and macro names from `cbom.apis`, added as catalogue entries. `library` names the
    library they belong to (an existing one such as cycurlib, or a new one). An entry that leaves
    out `primitive` and the like takes them from the keywords in its name.
    """
    for i, item in enumerate(apis, 1):
        raw = dict(item)
        where = f"cbom.apis[{i}]"
        lib_id = str(raw.pop("library", "project-apis"))
        if not raw.get("name"):
            raise ConfigError(f"{where}: every entry needs 'name' and 'identifiers'")
        raw.setdefault("id", f"api-{i}-" + re.sub(r"[^a-z0-9]+", "-", str(raw["name"]).lower()).strip("-"))
        entry = _entry(raw, where)
        hint = keywords.first_primitive(entry.name)
        if hint is None:
            for ident in entry.identifiers:
                hint = keywords.first_primitive(ident.rstrip("*"))
                if hint:
                    break
        if hint is not None and "kind" not in raw and hint.kind == entry.kind:
            for key in ("primitive", "protocol", "parameter_set", "weak", "mode", "version"):
                if key not in raw and getattr(hint, key) not in (None, "unknown", "other"):
                    setattr(entry, key, getattr(hint, key))
            if "functions" not in raw:
                entry.functions = list(hint.functions)
            if "hardware" not in raw:
                entry.hardware = hint.hardware
        lib = libraries.setdefault(lib_id, Library(lib_id, lib_id if lib_id != "project-apis" else "Project crypto APIs"))
        lib.entries[entry.id] = entry
