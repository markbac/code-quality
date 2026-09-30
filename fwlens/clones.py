"""
Clone / duplicate function detection for fwlens.

Detects type-2 clones (same structure, renamed identifiers/literals) via
normalised-token k-shingling and Jaccard similarity. Runs on raw source text
(regex tokeniser, no libclang re-parse needed -- FunctionMetrics already has
each function's file/line/loc from the AST walk) so it works in EWP or
directory mode identically.

Naive all-pairs comparison is O(n^2) and doesn't scale past a few hundred
functions. Instead, functions are bucketed by an inverted index of shingle
hashes: only functions that already share at least one shingle become
candidate pairs, and full Jaccard similarity is only computed for those --
this scales roughly with the amount of actual duplication, not codebase size.
"""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path

from fwlens.model.project import ClonePair, FunctionMetrics, ProjectModel

_TOKEN_RE = re.compile(
    r'"[^"]*"|\'[^\']*\'|\d+\.?\d*[uUlLfF]*|[A-Za-z_]\w*|[^\sA-Za-z0-9_]'
)
_COMMENT_RE = re.compile(r'/\*.*?\*/|//[^\n]*', re.DOTALL)

_KEYWORDS = frozenset([
    "if", "else", "for", "while", "do", "switch", "case", "default", "break",
    "continue", "return", "goto", "sizeof", "struct", "union", "enum", "typedef",
    "static", "const", "volatile", "extern", "void", "int", "char", "short",
    "long", "unsigned", "signed", "float", "double", "auto", "register",
])

_SHINGLE_K = 8
_MIN_TOKENS = 30            # ignore trivially small functions -- too noisy to be meaningful
_MIN_SIMILARITY = 0.75
_MAX_PAIRS_PER_BUCKET = 50  # cap pathological buckets (e.g. boilerplate headers) cheaply


def _normalise_tokens(text: str) -> list[str]:
    """Identifiers -> ID, numeric/string/char literals -> LIT, keywords/operators kept as-is.
    Comments are stripped first -- comment wording has no bearing on structural similarity
    and, worse, differing comments between two otherwise-identical functions would dilute
    their similarity below the threshold."""
    text = _COMMENT_RE.sub(" ", text)
    tokens = []
    for raw in _TOKEN_RE.findall(text):
        if raw and (raw[0].isalpha() or raw[0] == "_"):
            tokens.append(raw if raw in _KEYWORDS else "ID")
        elif raw and (raw[0].isdigit() or raw[0] in "\"'"):
            tokens.append("LIT")
        else:
            tokens.append(raw)
    return tokens


def _shingles(tokens: list[str], k: int) -> set[tuple]:
    if len(tokens) < k:
        return {tuple(tokens)} if tokens else set()
    return {tuple(tokens[i:i + k]) for i in range(len(tokens) - k + 1)}


def _function_source(func: FunctionMetrics, file_cache: dict[Path, list[str]]) -> str:
    lines = file_cache.get(func.file)
    if lines is None:
        try:
            lines = func.file.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            lines = []
        file_cache[func.file] = lines
    start = max(0, func.line - 1)
    end = min(len(lines), start + max(func.loc, 1))
    return "\n".join(lines[start:end])


def detect_clones(model: ProjectModel) -> None:
    """Populate model.clone_pairs with near-duplicate first-party function pairs."""
    funcs = model.first_party_functions()
    file_cache: dict[Path, list[str]] = {}

    signatures: dict[str, tuple[FunctionMetrics, set[tuple], int]] = {}
    shingle_index: dict[tuple, list[str]] = defaultdict(list)

    for func in funcs:
        source = _function_source(func, file_cache)
        tokens = _normalise_tokens(source)
        if len(tokens) < _MIN_TOKENS:
            continue
        shingle_set = _shingles(tokens, _SHINGLE_K)
        key = f"{func.file}:{func.line}:{func.name}"
        signatures[key] = (func, shingle_set, len(tokens))
        for sh in shingle_set:
            shingle_index[sh].append(key)

    seen_pairs: set[tuple[str, str]] = set()
    pairs: list[ClonePair] = []

    for sh, keys in shingle_index.items():
        if len(keys) < 2 or len(keys) > _MAX_PAIRS_PER_BUCKET:
            continue  # a shingle shared by too many functions is boilerplate, not a clone signal
        for i in range(len(keys)):
            for j in range(i + 1, len(keys)):
                a, b = sorted((keys[i], keys[j]))
                if (a, b) in seen_pairs:
                    continue
                seen_pairs.add((a, b))

                func_a, set_a, n_a = signatures[a]
                func_b, set_b, n_b = signatures[b]
                if func_a.file == func_b.file and func_a.name == func_b.name:
                    continue
                union = set_a | set_b
                if not union:
                    continue
                similarity = len(set_a & set_b) / len(union)
                if similarity >= _MIN_SIMILARITY:
                    pairs.append(ClonePair(
                        function_a=func_a.name, file_a=func_a.file, line_a=func_a.line,
                        function_b=func_b.name, file_b=func_b.file, line_b=func_b.line,
                        similarity=round(similarity, 3),
                        token_count_a=n_a, token_count_b=n_b,
                        is_dead_a=func_a.is_dead_candidate, is_dead_b=func_b.is_dead_candidate,
                    ))

    # Surface the pairs where duplication overlaps with dead code first -- one or both
    # sides being both a near-duplicate AND unreachable is a stronger, safer removal
    # signal than either metric alone (right-hand tie-break keeps the existing
    # similarity-descending order within each group).
    pairs.sort(key=lambda p: (p.is_dead_a or p.is_dead_b, p.similarity), reverse=True)
    model.clone_pairs = pairs
