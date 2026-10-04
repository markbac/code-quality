"""
Stable finding identity (issues #29 and #53).

A finding must keep its identity when code is moved, renamed, reformatted or when
unrelated lines are inserted above it. Identity therefore never contains a line
number and is matched in tiers, cheapest and most certain first:

1. key        same file, function and metric/rule (``Breach.id``)
2. content    same normalised body hash (the code moved with the finding)
3. shape      same body with identifiers abstracted (function and parameter renames)
4. similar    MinHash Jaccard similarity of the body above a threshold   -> uncertain
5. contained  most of the current body already existed in a base function  -> uncertain
              (a function that was split)

Anything left over is ``new`` (current side) or ``resolved`` (base side).
Hashes are blake2b, so they are identical across machines and Python hash seeds.
"""

from __future__ import annotations

import functools
import hashlib
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from fwlens.clones import _COMMENT_RE, _KEYWORDS, _TOKEN_RE

SCHEME = "fwlens-finding/1"
_SHINGLE_K = 5
_MINHASH_SIZE = 64
_MIN_SHAPE_TOKENS = 40
_MASK = (1 << 61) - 1

# Status values
NEW, UNCHANGED, MOVED, UNCERTAIN = "new", "unchanged", "moved", "uncertain"


def _h64(text: str) -> int:
    return int.from_bytes(hashlib.blake2b(text.encode("utf-8"), digest_size=8).digest(), "big")


def _hex(text: str) -> str:
    return hashlib.blake2b(text.encode("utf-8"), digest_size=8).hexdigest()


@functools.lru_cache(maxsize=1)
def _perms() -> tuple[tuple[int, int], ...]:
    return tuple((_h64(f"a{i}") | 1, _h64(f"b{i}")) for i in range(_MINHASH_SIZE))


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

def to_posix(path) -> str:
    return str(path).replace("\\", "/")


@functools.lru_cache(maxsize=32)
def _git_toplevel(directory: str) -> Optional[str]:
    try:
        out = subprocess.run(["git", "-C", directory, "rev-parse", "--show-toplevel"],
                             capture_output=True, text=True, timeout=10)
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def project_root(config) -> Path:
    """Repository root so ids match between a laptop and CI: CI_PROJECT_DIR on GitLab, else the
    git top level, else the config dir."""
    import os
    ci_root = os.environ.get("CI_PROJECT_DIR")
    if ci_root and Path(ci_root).is_dir():
        return Path(ci_root)
    start = config.project.source_dir or config.project.proj_dir or config.config_path.parent
    top = _git_toplevel(str(start))
    return Path(top) if top else Path(config.config_path).parent


def relative_posix(path, root: Optional[Path]) -> str:
    """Repo-relative, forward-slash path. Paths outside the root keep their full posix form."""
    p = Path(path)
    if root is not None:
        try:
            return to_posix(p.resolve().relative_to(Path(root).resolve()))
        except (ValueError, OSError):
            pass
    return to_posix(path)


# ---------------------------------------------------------------------------
# Fingerprints
# ---------------------------------------------------------------------------

def tokenise(text: str) -> list[str]:
    """Comment-free tokens with identifiers and literals kept."""
    return _TOKEN_RE.findall(_COMMENT_RE.sub(" ", text))


def _abstract(tokens: list[str]) -> list[str]:
    out = []
    for t in tokens:
        if t[0].isalpha() or t[0] == "_":
            out.append(t if t in _KEYWORDS else "ID")
        elif t[0].isdigit() or t[0] in "\"'":
            out.append("LIT")
        else:
            out.append(t)
    return out


def statement_fingerprint(text: str) -> dict:
    """Fingerprint of one statement (for rule findings). Exact content only: changing
    the callee or an operand makes it a different finding."""
    return {"body_hash": _hex(" ".join(tokenise(text)))}


def body_fingerprint(source: str) -> dict:
    """Fingerprint of a function. The signature is excluded, so renaming the function
    keeps the content hash. Includes an abstracted hash and a MinHash for similarity."""
    brace = source.find("{")
    body = source[brace:] if brace >= 0 else source
    tokens = tokenise(body)
    abstract = _abstract(tokens)
    # Shingles keep identifiers: abstracting them makes unrelated functions with the same
    # control-flow shape look alike. Pure renames are handled by the shape hash instead.
    shingles = {tuple(tokens[i:i + _SHINGLE_K]) for i in range(max(1, len(tokens) - _SHINGLE_K + 1))}
    hashes = [_h64(" ".join(s)) for s in shingles]
    minhash = [min(((a * x + b) & _MASK) for x in hashes) if hashes else 0 for a, b in _perms()]
    return {
        "body_hash": _hex(" ".join(tokens)),
        "shape_hash": _hex(" ".join(abstract)),
        "ntokens": len(tokens),
        "minhash": minhash,
        "nshingles": len(shingles),
    }


def function_source(func, file_cache: dict) -> str:
    lines = file_cache.get(func.file)
    if lines is None:
        try:
            lines = Path(func.file).read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            lines = []
        file_cache[func.file] = lines
    start = max(0, func.line - 1)
    return "\n".join(lines[start:start + max(func.loc, 1)])


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------

def make_key(file: str, function: Optional[str], metric: str, ordinal: int = 1) -> str:
    if function is None:
        return f"{file}:{metric}"
    name = function if ordinal == 1 else f"{function}#{ordinal}"
    return f"{file}:{name}:{metric}"


def migrate_legacy_id(entry: dict) -> dict:
    """Turn a v1 entry (id ``file:line:function:metric``) into a v2 entry without a line in its id."""
    if entry.get("function") is not None or entry.get("kind") == "module":
        new = dict(entry)
        new.setdefault("function", None)
        if entry.get("kind") == "module":
            new["id"] = make_key(entry["file"], None, entry["metric"])
        return new
    parts = str(entry["id"]).split(":")
    new = dict(entry)
    if entry.get("kind") == "function" and len(parts) >= 4 and parts[-3].isdigit():
        new["function"] = parts[-2]
        new["line"] = int(parts[-3])
        new["id"] = make_key(entry["file"], parts[-2], entry["metric"])
    return new


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------

@dataclass
class Match:
    current: object                      # a Breach
    base: Optional[dict]                 # matched base entry, None for new
    status: str                          # new | unchanged | moved | uncertain
    tier: str = ""                       # key | content | shape | similar | contained
    note: str = ""

    @property
    def worsened(self) -> bool:
        # After a split the old value says nothing about the new, smaller function.
        if self.base is None or self.tier == "contained":
            return False
        return self.current.value > self.base.get("value", self.current.value)

    @property
    def improved(self) -> bool:
        return self.base is not None and self.current.value < self.base.get("value", self.current.value)


@dataclass
class MatchResult:
    matches: list[Match] = field(default_factory=list)
    resolved: list[dict] = field(default_factory=list)

    def by_status(self, status: str) -> list[Match]:
        return [m for m in self.matches if m.status == status]

    def gating(self, uncertain_gates: bool = False) -> list[Match]:
        out = []
        for m in self.matches:
            if m.status == NEW or m.worsened:
                out.append(m)
            elif m.status == UNCERTAIN and uncertain_gates:
                out.append(m)
        return out


def _jaccard(a: list[int], b: list[int]) -> float:
    if not a or len(a) != len(b):
        return 0.0
    return sum(1 for x, y in zip(a, b) if x == y) / len(a)


def _containment(cur_fp: dict, base_fp: dict) -> float:
    """Estimated share of the current body's shingles that also exist in the base body."""
    j = _jaccard(cur_fp.get("minhash", []), base_fp.get("minhash", []))
    na, nb = cur_fp.get("nshingles", 0), base_fp.get("nshingles", 0)
    if not na or j == 0:
        return 0.0
    return min(1.0, j * (na + nb) / ((1 + j) * na))


def _order(item_file: str, item_line: Optional[int]) -> tuple:
    return (item_file, item_line or 0)


def match_findings(current: Iterable, base_entries: Iterable[dict], *,
                   similarity: float = 0.85, containment: float = 0.6,
                   edit_containment: float = 0.8) -> MatchResult:
    current = list(current)
    base = [migrate_legacy_id(e) for e in base_entries]
    result = MatchResult()
    matched: dict[int, Match] = {}
    used: set[int] = set()

    def record(idx: int, base_idx: int, status: str, tier: str, note: str = "") -> None:
        matched[idx] = Match(current[idx], base[base_idx], status, tier, note)
        used.add(base_idx)

    # 1. key
    by_id = {e["id"]: i for i, e in enumerate(base)}
    for ci, b in enumerate(current):
        bi = by_id.get(b.id)
        if bi is not None and bi not in used:
            record(ci, bi, UNCHANGED, "key")

    def pending() -> list[int]:
        return sorted((i for i in range(len(current)) if i not in matched),
                      key=lambda i: _order(current[i].file, current[i].line))

    def free_base(metric: str) -> list[int]:
        return sorted((i for i, e in enumerate(base) if i not in used and e.get("metric") == metric),
                      key=lambda i: _order(base[i].get("file", ""), base[i].get("line")))

    # 2 and 3: exact content, then identifier-abstracted shape. Pair in source order.
    for fp_field, status, tier in (("body_hash", MOVED, "content"), ("shape_hash", MOVED, "shape")):
        for ci in pending():
            fp = current[ci].fingerprint
            h = fp.get(fp_field)
            if not h:
                continue
            if fp_field == "shape_hash" and fp.get("ntokens", 0) < _MIN_SHAPE_TOKENS:
                continue  # tiny bodies share a shape by chance
            for bi in free_base(current[ci].metric):
                if base[bi].get("fingerprint", {}).get(fp_field) == h:
                    record(ci, bi, status, tier)
                    break

    # 4. similar (loose): the same function, edited. Either the bodies are close overall, or
    #    nearly all of the base body is still present in a longer current body.
    for ci in pending():
        fp = current[ci].fingerprint
        if not fp.get("minhash"):
            continue
        best, best_score, best_j = None, 0.0, 0.0
        for bi in free_base(current[ci].metric):
            bfp = base[bi].get("fingerprint", {})
            j = _jaccard(fp["minhash"], bfp.get("minhash", []))
            kept = _containment(bfp, fp)          # share of the old body still present
            score = max(j, kept if kept >= edit_containment else 0.0)
            if score > best_score and (j >= similarity or kept >= edit_containment):
                best, best_score, best_j = bi, score, j
        if best is not None:
            record(ci, best, UNCERTAIN, "similar", f"{best_score:.0%} of the previous body is still here")

    # 5. contained: most of this (smaller) body already existed in a base function -- a split
    for ci in pending():
        fp = current[ci].fingerprint
        if not fp.get("minhash"):
            continue
        best, best_c = None, 0.0
        for bi, e in enumerate(base):
            if e.get("metric") != current[ci].metric:
                continue
            c = _containment(fp, e.get("fingerprint", {}))
            if c > best_c:
                best, best_c = bi, c
        if best is not None and best_c >= containment:
            # a split can feed several helpers, so the base entry is not marked as used
            matched[ci] = Match(current[ci], base[best], UNCERTAIN, "contained",
                                f"{best_c:.0%} of this body existed in {base[best].get('function')}")

    for ci, b in enumerate(current):
        result.matches.append(matched.get(ci) or Match(b, None, NEW))
    result.resolved = [e for i, e in enumerate(base) if i not in used
                       and not any(m.base is e for m in matched.values())]
    return result
