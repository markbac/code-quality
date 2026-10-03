"""
Check engines for native rules (issue #49). A rule's YAML picks an engine and its parameters.

    ast            walk the AST of each first-party translation unit
                   match: cursor (a libclang CursorKind name), callee_in (call names)
    compound_body  selection and iteration statements whose body is not a compound statement
    callgraph      cycles in the first-party call graph (recursion)

An engine returns raw hits (file, line, function, text). Turning hits into findings is
done once, in fwlens.standards.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from fwlens.identity import body_fingerprint, function_source
from fwlens.standards.rules import Rule


@dataclass
class Hit:
    rule: Rule
    file: Path
    line: int
    function: Optional[str]
    text: str
    fingerprint: Optional[dict] = None   # overrides the statement fingerprint when set


def _source_text(file_cache: dict, path: str, start: int, end: int) -> str:
    lines = file_cache.get(path)
    if lines is None:
        try:
            lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            lines = []
        file_cache[path] = lines
    return "\n".join(lines[max(0, start - 1):min(len(lines), end, start + 5)])


def _body_is_compound(ci, cursor) -> list[bool]:
    """For IF/WHILE/FOR/DO/SWITCH return whether each controlled body is a compound statement."""
    K = ci.CursorKind
    kids = list(cursor.get_children())
    if cursor.kind == K.IF_STMT:
        res = [len(kids) > 1 and kids[1].kind == K.COMPOUND_STMT]
        if len(kids) > 2:
            res.append(kids[2].kind in (K.COMPOUND_STMT, K.IF_STMT))   # else-if is allowed
        return res
    if cursor.kind == K.DO_STMT:
        return [bool(kids) and kids[0].kind == K.COMPOUND_STMT]
    if cursor.kind in (K.WHILE_STMT, K.FOR_STMT, K.SWITCH_STMT):
        return [bool(kids) and kids[-1].kind == K.COMPOUND_STMT]
    return []


def run_ast_engines(ci, tu_path: Path, tu, rules: list[Rule], file_cache: dict) -> list[Hit]:
    """One walk of a parsed translation unit evaluating every ast and compound_body rule."""
    K = ci.CursorKind
    by_cursor: dict = {}
    compound_rules = [r for r in rules if r.engine == "compound_body"]
    for r in rules:
        if r.engine == "ast":
            kind = getattr(K, r.match["cursor"], None)
            if kind is None:
                raise ValueError(f"{r.key}: unknown cursor kind {r.match['cursor']!r}")
            by_cursor.setdefault(kind, []).append(r)
    compound_kinds = {K.IF_STMT, K.WHILE_STMT, K.FOR_STMT, K.DO_STMT, K.SWITCH_STMT}
    hits: list[Hit] = []
    main = str(tu_path)

    def visit(cursor, function):
        try:
            kind = cursor.kind
        except ValueError:
            kind = None   # a cursor kind the Python bindings do not know
        loc = cursor.location
        in_main = loc.file is not None and loc.file.name == main
        if kind is not None and in_main:
            fn = function
            if kind == K.FUNCTION_DECL and cursor.is_definition():
                fn = cursor.spelling
            for r in by_cursor.get(kind, ()):
                names = r.match.get("callee_in")
                if names is not None and cursor.spelling not in names:
                    continue
                hits.append(Hit(r, tu_path, loc.line, fn,
                                _source_text(file_cache, main, cursor.extent.start.line, cursor.extent.end.line)))
            if kind in compound_kinds:
                for r in compound_rules:
                    if not all(_body_is_compound(ci, cursor)):
                        hits.append(Hit(r, tu_path, loc.line, fn,
                                        _source_text(file_cache, main, cursor.extent.start.line,
                                                     cursor.extent.start.line)))
            function = fn
        for child in cursor.get_children():
            visit(child, function)

    visit(tu.cursor, None)
    return hits


def run_callgraph_engine(model, rules: list[Rule], file_cache: dict) -> list[Hit]:
    """Report every first-party function that is part of a call cycle."""
    import networkx as nx

    funcs = {f.name: f for f in model.first_party_functions()}
    graph = nx.DiGraph()
    graph.add_nodes_from(funcs)
    for name, f in funcs.items():
        for callee in f.callees:
            if callee in funcs:
                graph.add_edge(name, callee)
    in_cycle: set[str] = set()
    for comp in nx.strongly_connected_components(graph):
        if len(comp) > 1:
            in_cycle |= comp
    in_cycle |= {n for n in graph.nodes if graph.has_edge(n, n)}
    hits = []
    for r in rules:
        if r.engine != "callgraph":
            continue
        for name in sorted(in_cycle):
            f = funcs[name]
            fp = {"body_hash": body_fingerprint(function_source(f, file_cache.setdefault("_funcs", {})))["body_hash"]}
            hits.append(Hit(r, Path(f.file), f.line, name, _source_text(file_cache, str(f.file), f.line, f.line), fp))
    return hits
