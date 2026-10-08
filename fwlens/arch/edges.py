"""
Typed, weighted dependencies between units (translation units).

    call      a function in one unit calls a function defined in another
    callback  a unit stores the address of another unit's function (a dispatch table, `&handler`)
    state     a unit reads or writes another unit's global, or a struct in its header embeds
              a struct declared by another unit
    type      a unit uses a type another unit declares
    include   a header of one unit includes a header of another

The existing call and include graphs are left as they are. These edges are built beside them from
the same parse, plus a lexical read of the source for the type, struct and address-of facts.
"""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path

from fwlens.arch.model import DEFAULT_WEIGHTS, EDGE_KINDS, Edge
from fwlens.model.project import ProjectModel

EVIDENCE_KEPT = 3
HEADER_SUFFIXES = {".h", ".hh", ".hpp", ".hxx", ".inc"}
_IDENT = re.compile(r"[A-Za-z_]\w*")
_COMMENT = re.compile(r"/\*.*?\*/|//[^\n]*", re.DOTALL)
_STRING = re.compile(r'"(?:\\.|[^"\\\n])*"')
_TYPEDEF_NAME = re.compile(r"\}\s*([A-Za-z_]\w*)\s*(?:,[^;]*)?;")
_TYPEDEF_SIMPLE = re.compile(r"\btypedef\b[^;{}]*?\b([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*;")
_TYPEDEF_FUNC_PTR = re.compile(r"\btypedef\b[^;{}]*\(\s*\*\s*([A-Za-z_]\w*)\s*\)")
_TAG = re.compile(r"\b(?:struct|union|enum)\s+([A-Za-z_]\w*)\s*\{")
_MEMBER = re.compile(r"^\s*(?:const\s+|volatile\s+)*(?:struct\s+|union\s+|enum\s+)?([A-Za-z_]\w*)\s+([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*;", re.M)
_ADDRESS_OF = re.compile(r"&\s*([A-Za-z_]\w*)\b(?!\s*[\[.\-(])")


def norm(path) -> str:
    return str(path).replace("\\", "/")


def blank(text: str) -> str:
    """Comments and strings replaced by spaces, so line numbers still match."""
    def keep_newlines(m: re.Match) -> str:
        return re.sub(r"[^\n]", " ", m.group(0))
    return _STRING.sub(keep_newlines, _COMMENT.sub(keep_newlines, text))


def read_text(path) -> str:
    try:
        return blank(Path(path).read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return ""


def line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def type_names(text: str) -> set[str]:
    """Names a header declares as types: typedefs, and struct, union and enum tags with a body."""
    names = set(_TYPEDEF_NAME.findall(text)) | set(_TYPEDEF_FUNC_PTR.findall(text)) | set(_TAG.findall(text))
    for m in _TYPEDEF_SIMPLE.finditer(text):
        names.add(m.group(1))
    return names


def struct_bodies(text: str):
    """(start_offset, body) of every brace block that follows struct or union."""
    for m in re.finditer(r"\b(?:struct|union)\s*(?:[A-Za-z_]\w*)?\s*\{", text):
        depth, i = 1, m.end()
        while i < len(text) and depth:
            depth += {"{": 1, "}": -1}.get(text[i], 0)
            i += 1
        yield m.end(), text[m.end():i - 1]


class Units:
    """Which unit a file belongs to: a unit's own file, or a header with the same stem."""

    def __init__(self, model: ProjectModel):
        self.paths: dict[str, Path] = {}
        for m in model.modules:
            self.paths[norm(m.path)] = Path(m.path)
        sources = [p for p in self.paths if Path(p).suffix.lower() not in HEADER_SUFFIXES]
        self.names = sorted(sources + [p for p in self.paths if p not in sources
                                       and not self._twin(p, sources)])
        self._by_stem: dict[str, list[str]] = defaultdict(list)
        for u in sorted(sources):
            self._by_stem[Path(u).stem.lower()].append(u)
        self._cache: dict[str, str | None] = {}

    def _twin(self, header: str, sources: list[str]) -> bool:
        return any(Path(s).stem.lower() == Path(header).stem.lower() for s in sources)

    def owner(self, file) -> str | None:
        key = norm(file)
        if key in self._cache:
            return self._cache[key]
        found: str | None = None
        if key in self.names:
            found = key
        else:
            candidates = self._by_stem.get(Path(key).stem.lower(), [])
            if len(candidates) == 1:
                found = candidates[0]
            elif candidates:
                found = max(candidates, key=lambda c: (len(_common(c, key)), c))
        self._cache[key] = found
        return found


def _common(a: str, b: str) -> list[str]:
    out = []
    for x, y in zip(a.split("/")[:-1], b.split("/")[:-1]):
        if x != y:
            break
        out.append(x)
    return out


class _Collector:
    def __init__(self) -> None:
        self.counts: dict[tuple[str, str, str], int] = defaultdict(int)
        self.evidence: dict[tuple[str, str, str], list] = defaultdict(list)

    def add(self, source: str, target: str, kind: str, where: str = "", line: int = 0) -> None:
        if source == target:
            return
        key = (source, target, kind)
        self.counts[key] += 1
        if where and len(self.evidence[key]) < EVIDENCE_KEPT:
            self.evidence[key].append([where, line])


def build_edges(model: ProjectModel, weights: dict | None = None, units: Units | None = None) -> tuple[list[str], list[Edge]]:
    """Returns (units, edges). `weights` overrides the default weight of any kind."""
    w = {**DEFAULT_WEIGHTS, **{k: float(v) for k, v in (weights or {}).items() if k in EDGE_KINDS}}
    units = units or Units(model)
    out = _Collector()

    func_units: dict[str, set[str]] = defaultdict(set)
    for m in model.modules:
        u = units.owner(m.path)
        for f in m.functions:
            if u:
                func_units[f.name].add(u)

    def defined_in(name: str, caller: str) -> str | None:
        found = func_units.get(name)
        if not found or caller in found or len(found) != 1:
            return None
        return next(iter(found))

    texts: dict[str, str] = {}
    for m in model.modules:
        u = units.owner(m.path)
        if not u:
            continue
        for f in m.functions:
            for callee in dict.fromkeys(f.callees):
                target = defined_in(callee, u)
                if target:
                    out.add(u, target, "call", norm(f.file), f.line)
        for name in m.file_scope_fn_refs:
            target = defined_in(name, u)
            if target:
                out.add(u, target, "callback", norm(m.path), 0)
        for table, fns in m.dispatch_tables.items():
            for name in dict.fromkeys(fns):
                target = defined_in(name, u)
                if target:
                    out.add(u, target, "callback", norm(m.path), m.dispatch_table_lines.get(table, 0))
        text = texts.setdefault(norm(m.path), read_text(m.path))
        for hit in _ADDRESS_OF.finditer(text):
            target = defined_in(hit.group(1), u)
            if target:
                out.add(u, target, "callback", norm(m.path), line_of(text, hit.start()))

    for g in model.globals:
        owner = units.owner(g.file)
        if not owner or g.is_static:
            continue
        for fn in dict.fromkeys([*g.readers, *g.writers]):
            for user in func_units.get(fn, ()):
                if user != owner:
                    out.add(user, owner, "state", norm(g.file), 0)

    headers = sorted({norm(d) for m in model.modules for _s, d in m.all_include_edges}
                     | {p for p in units.paths if Path(p).suffix.lower() in HEADER_SUFFIXES})
    declares: dict[str, str] = {}
    header_text: dict[str, str] = {}
    for h in headers:
        owner = units.owner(h)
        if not owner:
            continue
        header_text[h] = read_text(h)
        for name in type_names(header_text[h]):
            declares.setdefault(name, owner)

    for h, text in header_text.items():
        owner = units.owner(h)
        for start, body in struct_bodies(text):
            for member in _MEMBER.finditer(body):
                target = declares.get(member.group(1))
                if target and owner:
                    out.add(owner, target, "state", h, line_of(text, start) + body.count("\n", 0, member.start()))

    for m in model.modules:
        u = units.owner(m.path)
        if not u:
            continue
        text = texts.setdefault(norm(m.path), read_text(m.path))
        idents = set(_IDENT.findall(text))
        for p in (h for h in header_text if units.owner(h) == u):
            idents |= set(_IDENT.findall(header_text[p]))
        for name in sorted(idents):
            target = declares.get(name)
            if target and target != u:
                out.add(u, target, "type", norm(m.path), 0)

    seen: set[tuple[str, str]] = set()
    for m in model.modules:
        for s, d in m.all_include_edges:
            a, b = units.owner(s), units.owner(d)
            if a and b and a != b and (a, b) not in seen:
                seen.add((a, b))
                out.add(a, b, "include", norm(s), 0)

    edges = [Edge(s, t, k, n, round(n * w[k], 3), out.evidence[(s, t, k)])
             for (s, t, k), n in sorted(out.counts.items())]
    return units.names, edges
