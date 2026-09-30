"""
Header include hygiene checks.

Reuses the file-level #include graph already built by
fwlens.graph.engines.build_include_graph() (nodes = resolved file paths,
edge src -> dst means src #includes dst) rather than re-parsing anything.
Guard-checking and unused-include detection read header/source text directly
off disk -- they're regex heuristics, not semantic analysis, and are
labelled as such wherever they're reported (see html_report.py's "About
these metrics" cards for this section).
"""

from __future__ import annotations

import re
from pathlib import Path

import networkx as nx

from fwlens.config import FwLensConfig
from fwlens.model.project import (
    DeepIncludeChain,
    IncludeCycle,
    MissingIncludeGuard,
    ModuleMetrics,
    ProjectModel,
    SelfInclude,
    UnusedInclude,
)

_PRAGMA_ONCE_RE = re.compile(r'^\s*#\s*pragma\s+once\b', re.MULTILINE)
_IFNDEF_RE = re.compile(r'^\s*#\s*ifndef\s+(\w+)', re.MULTILINE)
_DEFINE_RE = re.compile(r'^\s*#\s*define\s+(\w+)', re.MULTILINE)

# Declaration-name extraction for the unused-includes heuristic. Each is a
# rough, single-line-oriented pattern -- multi-line struct typedefs and
# function-pointer parameters are known gaps (see check_unused_includes
# docstring). False negatives (missing a declared name) are the safe
# failure direction here, since they only make the header look "used" when
# it might not be -- never the reverse.
_MACRO_NAME_RE   = re.compile(r'^\s*#\s*define\s+(\w+)', re.MULTILINE)
_FUNC_PROTO_RE   = re.compile(
    r'^\s*(?:extern\s+|static\s+|inline\s+)*[\w\*\s]+?\b(\w+)\s*\([^;{}]*\)\s*;', re.MULTILINE)
_TYPEDEF_RE      = re.compile(r'^\s*typedef\b.*?\b(\w+)\s*;\s*$', re.MULTILINE)
_EXTERN_VAR_RE   = re.compile(
    r'^\s*extern\s+(?:const\s+)?[\w\*\s]+?\b(\w+)\s*(?:\[[^\]]*\])?\s*;', re.MULTILINE)

_COMMENT_RE = re.compile(r'//[^\n]*|/\*.*?\*/', re.DOTALL)
_STRING_RE  = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')
_TOKEN_RE   = re.compile(r'\b[A-Za-z_]\w*\b')

_MIN_NAME_LEN = 3  # skip 1-2 char macro/typedef names -- too likely to collide by chance


def _strip_comments_and_strings(text: str) -> str:
    text = _COMMENT_RE.sub(' ', text)
    text = _STRING_RE.sub(' ', text)
    return text


def _is_first_party(path: Path, config: FwLensConfig) -> bool:
    """Path-only first-party classifier -- works for headers, which don't get
    their own ModuleMetrics entry (only .c translation units do). Checks every
    path segment against config.scope.first_party, same approach as
    fwlens.parser.dirscan._classify_boundary."""
    try:
        rel_parts = [p.lower() for p in path.relative_to(config.project.proj_dir).parts]
    except ValueError:
        rel_parts = [p.lower() for p in path.parts]
    fp = {s.lower() for s in config.scope.first_party}
    return any(part in fp for part in rel_parts)


def detect_include_cycles(include_graph: nx.DiGraph) -> list[IncludeCycle]:
    """Strongly-connected components of size > 1 in the include graph -- A
    includes B includes ... includes A. Reported longest-first."""
    cycles = []
    for scc in nx.strongly_connected_components(include_graph):
        if len(scc) <= 1:
            continue
        sub = include_graph.subgraph(scc)
        try:
            cycle_nodes = next(nx.simple_cycles(sub))
        except StopIteration:
            cycle_nodes = list(scc)
        cycles.append(IncludeCycle(files=[Path(p) for p in cycle_nodes], length=len(cycle_nodes)))
    cycles.sort(key=lambda c: c.length, reverse=True)
    return cycles


def detect_self_includes(include_graph: nx.DiGraph) -> list[SelfInclude]:
    """Direct self-loops (a file #includes itself, resolved). A degenerate
    1-node cycle that detect_include_cycles' SCC-size>1 filter can't see."""
    return [SelfInclude(file=Path(n)) for n in include_graph.nodes if include_graph.has_edge(n, n)]


def check_include_guards(include_graph: nx.DiGraph, config: FwLensConfig) -> list[MissingIncludeGuard]:
    """First-party headers with neither #pragma once nor a matching
    #ifndef/#define guard pair. Only checks files reachable in the include
    graph and classified first-party; out-of-scope/SDK headers are skipped
    since fwlens has no standing to ask you to change vendor code."""
    results = []
    for node in sorted(include_graph.nodes):
        path = Path(node)
        if path.suffix.lower() not in ('.h', '.hpp'):
            continue
        if not _is_first_party(path, config):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if _PRAGMA_ONCE_RE.search(text):
            continue
        ifndef_m = _IFNDEF_RE.search(text)
        if not ifndef_m:
            results.append(MissingIncludeGuard(file=path, reason="no #ifndef or #pragma once found"))
            continue
        guard_name = ifndef_m.group(1)
        define_m = _DEFINE_RE.search(text)
        if not define_m or define_m.group(1) != guard_name:
            results.append(MissingIncludeGuard(
                file=path, reason=f"#ifndef {guard_name} not followed by a matching #define"))
    results.sort(key=lambda g: str(g.file))
    return results


def top_deep_include_chains(model: ProjectModel, top_n: int = 20) -> list[DeepIncludeChain]:
    """Surfaces ModuleMetrics.include_depth (already computed by
    compute_include_depth(), previously exported to CSV but never shown in
    the report) -- no new graph work, just a ranked view."""
    fp = [m for m in model.first_party_modules() if m.include_depth > 0]
    fp.sort(key=lambda m: m.include_depth, reverse=True)
    return [DeepIncludeChain(file=m.path, depth=m.include_depth, chain=list(m.include_chain))
            for m in fp[:top_n]]


def _declared_names(header_text: str) -> set[str]:
    text = _strip_comments_and_strings(header_text)
    names = set()
    for rx in (_MACRO_NAME_RE, _FUNC_PROTO_RE, _TYPEDEF_RE, _EXTERN_VAR_RE):
        names.update(m.group(1) for m in rx.finditer(text))
    return {n for n in names if len(n) >= _MIN_NAME_LEN}


def detect_unused_includes(
    model: ProjectModel, config: FwLensConfig, top_n: int = 100
) -> list[UnusedInclude]:
    """
    Heuristic: for each first-party .c file's first-party #include, extract
    the header's declared names (macros, function prototypes, typedefs,
    extern globals -- single-line-oriented regexes, so multi-line struct
    typedefs and function-pointer-typed parameters are known gaps) and check
    whether the including file's own token set contains any of them. Flags
    the include as possibly unused only if NONE of the header's declared
    names appear anywhere in the including file.

    First-party-to-first-party only: SDK/third-party headers are skipped,
    both because their declared-name extraction is noisier (less consistent
    header style) and because "remove this SDK include" isn't always
    actionable the way a first-party one is.

    False negatives (a genuinely unused include not flagged) are the
    expected failure mode -- e.g. a macro used only for its side effect on
    another macro, or a declaration form the regexes don't recognise. This
    check is a worklist to check by eye, not a rm -f... list.
    """
    header_names_cache: dict[Path, set[str]] = {}

    def declared_names_for(header_path: Path) -> set[str]:
        if header_path not in header_names_cache:
            try:
                text = header_path.read_text(encoding="utf-8", errors="replace")
                header_names_cache[header_path] = _declared_names(text)
            except OSError:
                header_names_cache[header_path] = set()
        return header_names_cache[header_path]

    results: list[UnusedInclude] = []
    for m in model.first_party_modules():
        if not m.includes:
            continue
        try:
            src_text = m.path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        stripped = _strip_comments_and_strings(src_text)
        # Drop the #include lines themselves so a header's own filename stem
        # (rare, but possible) can't count as "using" it.
        stripped = re.sub(r'^\s*#\s*include\b[^\n]*$', ' ', stripped, flags=re.MULTILINE)
        file_tokens = set(_TOKEN_RE.findall(stripped))

        for inc in m.includes:
            if inc.suffix.lower() not in ('.h', '.hpp'):
                continue
            if not _is_first_party(inc, config):
                continue
            declared = declared_names_for(inc)
            if not declared:
                continue  # nothing extractable -- not enough signal either way
            if declared.isdisjoint(file_tokens):
                results.append(UnusedInclude(
                    file=m.path, included=inc, declared_name_count=len(declared)))

    results.sort(key=lambda u: (str(u.file), str(u.included)))
    return results[:top_n]


def run_header_checks(model: ProjectModel, config: FwLensConfig) -> None:
    """Entry point called from fwlens.graph.engines.run_graph_engine(), after
    the include graph is built. Mutates model in place."""
    include_graph = getattr(model, "_include_graph", None)
    if include_graph is None:
        return
    model.include_cycles = detect_include_cycles(include_graph)
    model.self_includes = detect_self_includes(include_graph)
    model.missing_include_guards = check_include_guards(include_graph, config)
    model.deep_include_chains = top_deep_include_chains(model)
    model.unused_includes = detect_unused_includes(model, config)
