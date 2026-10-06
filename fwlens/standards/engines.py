"""
Check engines for native rules (issues #49 and #95). A rule's YAML picks an engine and its
parameters. A rule may list several checks, each with its own engine.

    ast            walk the AST of each first-party translation unit
                   match: cursor (a libclang CursorKind name), callee_in (call names),
                          callee_prefix (call name prefix), unused_result (only calls whose
                          result is discarded)
    compound_body  selection and iteration statements whose body is not a compound statement
    callgraph      cycles in the first-party call graph (recursion)
    detector       a named check written in Python, run during the same AST walk
                   match: name (see DETECTORS), plus any parameters that detector reads
    source         a regular expression over the comment-stripped source text of first-party
                   files, headers included
                   match: pattern, target (code | strings | raw | comments), multiline
    diagnostic     a regular expression over the diagnostics libclang reports while parsing
                   match: pattern, severity (warning | error, default warning)
    system         a named check over declarations collected from every translation unit
                   (identifier clashes, linkage), see SYSTEM_CHECKS

An engine returns raw hits (file, line, function, text). Turning hits into findings is
done once, in fwlens.standards.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from fwlens.identity import body_fingerprint, function_source
from fwlens.standards.astutil import callee_name, resolve_kind
from fwlens.standards.rules import Rule


@dataclass
class Hit:
    rule: Rule
    file: Path
    line: int
    function: str | None
    text: str
    fingerprint: dict | None = None   # overrides the statement fingerprint when set


# --- registries -----------------------------------------------------------------------------

@dataclass
class Detector:
    name: str
    kinds: tuple[str, ...]
    visit: Callable | None = None       # visit(ctx, cursor, params) -> iterable of (line, text)
    finish: Callable | None = None      # finish(ctx, params) -> iterable of (line, text), after the walk


DETECTORS: dict[str, Detector] = {}
SYSTEM_CHECKS: dict[str, Callable] = {}
SOURCE_CHECKS: dict[str, Callable] = {}


def detector(name: str, *kinds: str):
    """Register an AST detector. It is called for every cursor of the given kinds in the main file."""
    def wrap(fn):
        DETECTORS[name] = Detector(name, tuple(kinds), visit=fn, finish=DETECTORS.get(name, Detector(name, ())).finish)
        return fn
    return wrap


def finisher(name: str):
    """Register the after-the-walk half of a detector (for checks that need the whole file first)."""
    def wrap(fn):
        existing = DETECTORS.get(name)
        if existing is None:
            DETECTORS[name] = Detector(name, (), finish=fn)
        else:
            existing.finish = fn
        return fn
    return wrap


def source_check(name: str):
    """Register a check over the text of one file: fn(source, params) -> iterable of (line, text)."""
    def wrap(fn):
        SOURCE_CHECKS[name] = fn
        return fn
    return wrap


def system_check(name: str):
    """Register a check over the declarations of all translation units: fn(records, params) -> hits."""
    def wrap(fn):
        SYSTEM_CHECKS[name] = fn
        return fn
    return wrap


class Records(list):
    """What the system checks read: declaration records (the list itself) plus the references seen."""

    def __init__(self):
        super().__init__()
        self.refs: dict[tuple, set] = {}          # entity key -> translation units that refer to it
        self.macro_files: set[str] = set()        # files whose #define lines are already recorded

    def add_ref(self, key: tuple, tu: str) -> None:
        self.refs.setdefault(key, set()).add(tu)


# --- walk context -----------------------------------------------------------------------------

class Ctx:
    """State shared by the detectors during the walk of one translation unit."""

    def __init__(self, ci, tu_path: Path, tu, file_cache: dict, records: Records, first_party: set | None = None):
        self.ci = ci
        self.K = ci.CursorKind
        self.T = ci.TypeKind
        self.tu = tu
        self.tu_path = tu_path
        self.main = str(tu_path)
        self.file_cache = file_cache
        self.parents: list = []            # ancestors of the cursor being visited, outermost first
        self.function: str | None = None
        self.state: dict = {}              # per-detector scratch space for this translation unit
        self.records = records             # declaration records for system checks (all TUs)
        self.first_party = first_party if first_party is not None else {self.main}
        self._top: list | None = None

    def line_text(self, start: int, end: int | None = None) -> str:
        return _source_text(self.file_cache, self.main, start, end if end is not None else start)

    def in_main(self, cursor) -> bool:
        f = cursor.location.file
        return f is not None and f.name == self.main

    @property
    def top_level(self) -> list:
        """Every top-level declaration of the translation unit, headers included, in order."""
        if self._top is None:
            self._top = list(self.tu.cursor.get_children())
        return self._top

    def enclosing(self, *kinds):
        """The nearest ancestor of one of the given CursorKind names, or None."""
        wanted = {resolve_kind(self.K, k) for k in kinds}
        for p in reversed(self.parents):
            try:
                if p.kind in wanted:
                    return p
            except ValueError:
                continue
        return None


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


def _call_result_discarded(ctx: Ctx, cursor) -> bool:
    """True when a call expression is a whole statement, so its value is thrown away."""
    K = ctx.K
    if not ctx.parents:
        return False
    parent = ctx.parents[-1]
    if parent.kind == K.COMPOUND_STMT:
        return True
    if parent.kind in (K.IF_STMT, K.WHILE_STMT, K.FOR_STMT, K.DO_STMT, K.SWITCH_STMT):
        kids = list(parent.get_children())
        # a brace-less body is the last child (the second for if/else bodies); a condition is not discarded
        return bool(kids) and (kids[-1] == cursor or (parent.kind == K.IF_STMT and cursor in kids[1:]))
    return False


def run_ast_engines(ci, tu_path: Path, tu, rules: list[Rule], file_cache: dict,
                    records: Records | None = None, collect: bool = False,
                    first_party: set | None = None) -> list[Hit]:
    """
    One walk of a parsed translation unit evaluating every ast, compound_body and detector rule.
    With ``collect`` the walk also records declarations and references into ``records`` for the
    system checks.
    """
    K = ci.CursorKind
    ctx = Ctx(ci, tu_path, tu, file_cache, records if records is not None else Records(), first_party)
    by_cursor: dict = {}
    compound_rules: list[Rule] = []
    finishers: list = []
    for r in rules:
        for check in r.native_checks:
            if check.engine == "compound_body":
                compound_rules.append(r)
            elif check.engine == "ast":
                kind = resolve_kind(K, check.match["cursor"])
                if kind is None:
                    raise ValueError(f"{r.key}: unknown cursor kind {check.match['cursor']!r}")
                by_cursor.setdefault(kind, []).append((r, None, check.match))
            elif check.engine == "detector":
                det = DETECTORS[check.match["name"]]
                for kname in det.kinds:
                    kind = resolve_kind(K, kname)
                    if kind is None:
                        raise ValueError(f"detector {det.name}: unknown cursor kind {kname!r}")
                    by_cursor.setdefault(kind, []).append((r, det, check.match))
                if det.finish is not None:
                    finishers.append((r, det, check.match))
    compound_kinds = {K.IF_STMT, K.WHILE_STMT, K.FOR_STMT, K.DO_STMT, K.SWITCH_STMT}
    hits: list[Hit] = []
    main = str(tu_path)

    def emit(rule, line, function, text):
        hits.append(Hit(rule, tu_path, line, function, text))

    def visit(cursor):
        try:
            kind = cursor.kind
        except ValueError:
            kind = None   # a cursor kind the Python bindings do not know
        loc = cursor.location
        in_main = loc.file is not None and loc.file.name == main
        outer_function = ctx.function
        if kind is not None and in_main and not _macro_statement(cursor, kind, compound_kinds):
            if kind == K.FUNCTION_DECL and cursor.is_definition():
                ctx.function = cursor.spelling
            if collect:
                system.collect_visit(ctx, cursor, kind)
            for r, det, params in by_cursor.get(kind, ()):
                if det is None:
                    names = params.get("callee_in")
                    prefix = params.get("callee_prefix")
                    called = callee_name(cursor) if kind == K.CALL_EXPR else cursor.spelling
                    if names is not None and called not in names:
                        continue
                    if prefix is not None and not called.startswith(tuple(prefix)):
                        continue
                    if params.get("unused_result") and not _call_result_discarded(ctx, cursor):
                        continue
                    emit(r, loc.line, ctx.function,
                         _source_text(file_cache, main, cursor.extent.start.line, cursor.extent.end.line))
                else:
                    for item in det.visit(ctx, cursor, params) or ():
                        line, text = item[0], item[1]
                        emit(r, line, ctx.function, text)
            if kind in compound_kinds:
                for r in compound_rules:
                    if not all(_body_is_compound(ci, cursor)):
                        emit(r, loc.line, ctx.function,
                             _source_text(file_cache, main, cursor.extent.start.line, cursor.extent.start.line))
        ctx.parents.append(cursor)
        try:
            for child in cursor.get_children():
                if len(ctx.parents) == 1 and not _in_file(child, main):
                    continue          # top-level declarations from headers are not analysed
                visit(child)
        finally:
            ctx.parents.pop()
            ctx.function = outer_function

    visit(tu.cursor)
    if collect:
        system.collect_unit(ctx)
    for r, det, params in finishers:
        for item in det.finish(ctx, params) or ():
            emit(r, item[0], item[2] if len(item) > 2 else None, item[1])
    return hits


_KEYWORD = {"IF_STMT": "if", "WHILE_STMT": "while", "FOR_STMT": "for", "DO_STMT": "do", "SWITCH_STMT": "switch"}


def _macro_statement(cursor, kind, compound_kinds) -> bool:
    """A control statement written by a macro (glibc's assert is ``if (e) ; else ...``), not in the source."""
    if kind not in compound_kinds:
        return False
    first = next(cursor.get_tokens(), None)
    return first is None or first.spelling != _KEYWORD[kind.name]


def _in_file(cursor, main: str) -> bool:
    f = cursor.location.file
    return f is not None and f.name == main


def run_callgraph_engine(model, rules: list[Rule], file_cache: dict) -> list[Hit]:
    """Report every first-party function that is part of a call cycle."""
    import networkx as nx

    wanted = [r for r in rules if any(c.engine == "callgraph" for c in r.native_checks)]
    if not wanted:
        return []
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
    for r in wanted:
        for name in sorted(in_cycle):
            f = funcs[name]
            fp = {"body_hash": body_fingerprint(function_source(f, file_cache.setdefault("_funcs", {})))["body_hash"]}
            hits.append(Hit(r, Path(f.file), f.line, name, _source_text(file_cache, str(f.file), f.line, f.line), fp))
    return hits


def run_system_engines(records: Records, rules: list[Rule]) -> list[Hit]:
    """Checks over declarations collected from all translation units."""
    hits: list[Hit] = []
    for r in rules:
        for check in r.native_checks:
            if check.engine != "system":
                continue
            for file, line, text, function in SYSTEM_CHECKS[check.match["name"]](records, check.match):
                hits.append(Hit(r, Path(file), line, function, text))
    return hits


# Importing the check modules registers their detectors and system checks.
from fwlens.standards import (  # noqa: E402,F401
    barrc,
    cflow,
    declarations,
    expressions,
    functions,
    library,
    pointers,
    sourcechecks,
    system,
)

__all__ = ["Records", "DETECTORS", "SYSTEM_CHECKS", "SOURCE_CHECKS", "Ctx", "Hit", "detector", "finisher",
           "system_check", "source_check", "run_ast_engines", "run_callgraph_engine", "run_system_engines"]
