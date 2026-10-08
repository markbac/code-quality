"""
Public and internal symbols, and encapsulation leaks.

A function is public when a header declares it, internal when it is `static`, declared in no header, or
declared only in a private header (`architecture.private_headers`). A dispatch table counts as an
interface, and so does a header with a struct of function pointers. An edge from one unit to an
internal symbol of another is a leak: usually an `extern` written in the caller to dodge the header.
"""

from __future__ import annotations

import posixpath
import re
from collections import defaultdict
from fnmatch import fnmatchcase

from fwlens.arch.edges import HEADER_SUFFIXES, Units, line_of, norm, read_text, struct_bodies
from fwlens.arch.model import Interface, Leak
from fwlens.model.project import ProjectModel

PRIVATE_HEADERS = ["*_priv.h", "*_private.h", "*_internal.h", "*/internal/*", "*/private/*"]
_PROTOTYPE = re.compile(r"\b([A-Za-z_]\w*)\s*\([^;{}]*\)\s*(?:__attribute__\s*\(\([^;]*\)\)\s*)?;")
_EXTERN_VAR = re.compile(r"\bextern\b[^;(]*?\b([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*;")
_FUNC_PTR_MEMBER = re.compile(r"\(\s*\*\s*[A-Za-z_]\w*\s*\)\s*\(")
_NOT_NAMES = {"if", "while", "for", "switch", "return", "sizeof", "defined", "typedef"}


def is_private(path: str, patterns: list[str]) -> bool:
    return any(fnmatchcase(path, p) or fnmatchcase(path.rsplit("/", 1)[-1], p) for p in patterns)


def _is_static(lines: list[str], line: int, name: str) -> bool:
    """`static` before the function name, on its line or on the line above when the type is split from it."""
    if not 0 < line <= len(lines):
        return False
    here = lines[line - 1]
    at = re.search(rf"\b{re.escape(name)}\s*\(", here)
    prefix = here[:at.start()] if at else here
    if not prefix.strip() and line > 1 and not lines[line - 2].rstrip().endswith((";", "}", "{")):
        prefix = lines[line - 2] + " " + prefix
    return bool(re.search(r"\bstatic\b", prefix))


def analyse(model: ProjectModel, units: Units, private_headers: list[str] | None = None):
    """Returns (interfaces, leaks, ops_headers): headers with a struct of function pointers, owned or not."""
    patterns = PRIVATE_HEADERS if private_headers is None else private_headers
    headers = sorted({norm(d) for m in model.modules for _s, d in m.all_include_edges}
                     | {norm(m.path) for m in model.modules if m.path.suffix.lower() in HEADER_SUFFIXES})
    declared: dict[str, set[str]] = defaultdict(set)         # symbol -> headers declaring it
    header_text = {h: read_text(h) for h in headers}
    for h, text in header_text.items():
        for name in _PROTOTYPE.findall(text):
            if name not in _NOT_NAMES:
                declared[name].add(h)
        for name in _EXTERN_VAR.findall(text):
            declared[name].add(h)

    # patterns are matched against the path below the common directory, so a project that lives under a
    # directory called `private` (as macOS temporary directories do) is not all private
    root = posixpath.commonpath([posixpath.dirname(h) for h in headers]) if headers else ""
    private = {h: is_private("/" + h[len(root):].lstrip("/"), patterns) for h in headers}

    def visible(name: str) -> set[str]:
        return {h for h in declared.get(name, ()) if not private[h]}

    interfaces: dict[str, Interface] = {u: Interface(u) for u in units.names}
    function_unit: dict[str, tuple[str, int]] = {}
    for m in model.modules:
        u = units.owner(m.path)
        if not u:
            continue
        lines = read_text(m.path).splitlines()
        for f in m.functions:
            if _is_static(lines, f.line, f.name):
                interfaces[u].internal.append(f.name)
                continue
            function_unit.setdefault(f.name, (u, f.line))
            (interfaces[u].public if visible(f.name) else interfaces[u].internal).append(f.name)
    for table in model.dispatch_tables:
        u = units.owner(table.file)
        if u:
            interfaces[u].tables.append(table.var_name)
    ops_headers: list[str] = []
    for h, text in header_text.items():
        if any(_FUNC_PTR_MEMBER.search(body) for _s, body in struct_bodies(text)):
            ops_headers.append(h)
            u = units.owner(h)
            if u:
                interfaces[u].abstract_headers.append(h)

    includes: dict[str, set[str]] = defaultdict(set)         # unit -> headers its files include
    for m in model.modules:
        u = units.owner(m.path)
        if u:
            includes[u].update(norm(d) for _s, d in m.all_include_edges)

    leaks: list[Leak] = []

    def check(user: str, owner: str, name: str, where: str, line: int) -> None:
        if user == owner:
            return
        if not declared.get(name):
            leaks.append(Leak(user, owner, name, "undeclared", where, line))
        elif not visible(name) and declared[name] & includes[user]:
            leaks.append(Leak(user, owner, name, "private-header", where, line))

    for m in model.modules:
        user = units.owner(m.path)
        if not user:
            continue
        for f in m.functions:
            for callee in dict.fromkeys(f.callees):
                target = function_unit.get(callee)
                if target and callee not in interfaces[user].internal:
                    check(user, target[0], callee, norm(f.file), f.line)
    function_file = {f.name: f.file for m in model.modules for f in m.functions}
    for g in model.globals:
        owner = units.owner(g.file)
        if not owner or g.is_static:
            continue
        for fn in dict.fromkeys([*g.readers, *g.writers]):
            definition = function_unit.get(fn)
            if definition and definition[0] != owner:
                text = read_text(function_file[fn])
                at = re.search(rf"\b{re.escape(g.name)}\b", text)
                check(definition[0], owner, g.name, norm(function_file[fn]), line_of(text, at.start()) if at else 0)
    leaks.sort(key=lambda lk: (lk.source, lk.target, lk.symbol))
    unique = list({(lk.source, lk.target, lk.symbol, lk.kind): lk for lk in leaks}.values())
    return [interfaces[u] for u in units.names], unique, sorted(ops_headers)

