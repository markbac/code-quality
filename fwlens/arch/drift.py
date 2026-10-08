"""
Architecture drift: compare the model of this run with a saved one, or with the code at an earlier git revision.

A snapshot is the model with repo-relative paths, so two checkouts compare. Components are matched by the
files they hold (overlap of 0.5 or more), not by name, because an inferred name can change between runs.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

from fwlens.arch.layers import component_graph
from fwlens.arch.model import ArchModel
from fwlens.identity import relative_posix

VERSION = 1
MATCH = 0.5


def snapshot(arch: ArchModel, root) -> dict:
    rel = {u: relative_posix(u, root) for u in arch.units}
    domain = {s.name: s.domain for s in arch.subsystems}
    graph = component_graph(arch.components, arch.edges)
    return {
        "version": VERSION,
        "components": [{"name": c.name, "units": sorted(rel[u] for u in c.units), "domain": domain.get(c.name, ""),
                        "level": arch.layering.level_of.get(c.name, 0)} for c in arch.components],
        "edges": [{"source": a, "target": b, "kinds": sorted(d["kinds"]), "weight": round(d["weight"], 2)}
                  for a, b, d in sorted(graph.edges(data=True))],
        "cycles": [list(c) for c in arch.layering.cycles],
        "violations": [{"rule": v.rule, "source": v.source_component, "target": v.target_component or v.target,
                        "file": relative_posix(v.file, root)} for v in arch.violations],
        "leaks": [{"source": rel.get(lk.source, lk.source), "target": rel.get(lk.target, lk.target), "symbol": lk.symbol}
                  for lk in arch.leaks],
        "patterns": [{"id": p.id, "scope": p.scope, "component": p.component, "confidence": p.confidence}
                     for p in arch.patterns],
    }


def save(arch: ArchModel, root, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(snapshot(arch, root), indent=2) + "\n", encoding="utf-8")
    return path


def load(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"architecture baseline {path}: {exc}") from exc
    if not isinstance(data, dict) or data.get("version") != VERSION:
        raise ValueError(f"architecture baseline {path}: not an architecture snapshot of version {VERSION}")
    return data


def _match(old: list, new: list) -> dict:
    """new component name -> old component name, best overlap first."""
    pairs = []
    for n in new:
        for o in old:
            union = len(set(n["units"]) | set(o["units"]))
            overlap = len(set(n["units"]) & set(o["units"])) / union if union else 0
            if overlap >= MATCH:
                pairs.append((-overlap, n["name"], o["name"]))
    mapping: dict = {}
    taken: set = set()
    for _o, n, o in sorted(pairs):
        if n not in mapping and o not in taken:
            mapping[n] = o
            taken.add(o)
    return mapping


def diff(old: dict, new: dict) -> dict:
    to_old = _match(old["components"], new["components"])          # new name -> old name
    to_new = {o: n for n, o in to_old.items()}

    def name(n: str) -> str:
        return to_old.get(n, n)

    old_names = {c["name"] for c in old["components"]}
    result: dict = {
        "components_added": sorted(c["name"] for c in new["components"] if c["name"] not in to_old),
        "components_removed": sorted(c["name"] for c in old["components"] if c["name"] not in to_new),
        "renamed": sorted([o, n] for n, o in to_old.items() if o != n),
    }
    where_old = {u: c["name"] for c in old["components"] for u in c["units"]}
    where_new = {u: c["name"] for c in new["components"] for u in c["units"]}
    result["units_moved"] = [{"unit": u, "from": where_old[u], "to": where_new[u]} for u in sorted(where_old)
                             if u in where_new and where_old[u] in to_new and where_new[u] in to_old
                             and to_new[where_old[u]] != where_new[u]]
    result["units_added"] = sorted(set(where_new) - set(where_old))
    result["units_removed"] = sorted(set(where_old) - set(where_new))

    def edge_map(snap: dict, rename) -> dict:
        return {(rename(e["source"]), rename(e["target"])): e for e in snap["edges"]}
    e_old, e_new = edge_map(old, lambda n: n), edge_map(new, name)
    result["edges_added"] = [{"source": a, "target": b, "kinds": e_new[(a, b)]["kinds"], "weight": e_new[(a, b)]["weight"]}
                             for a, b in sorted(set(e_new) - set(e_old))]
    result["edges_removed"] = [{"source": a, "target": b, "kinds": e_old[(a, b)]["kinds"], "weight": e_old[(a, b)]["weight"]}
                               for a, b in sorted(set(e_old) - set(e_new))]

    cycles_old = {frozenset(c) for c in old["cycles"]}
    cycles_new = {frozenset(name(n) for n in c) for c in new["cycles"]}
    result["cycles_new"] = sorted(sorted(c) for c in cycles_new - cycles_old)
    result["cycles_resolved"] = sorted(sorted(c) for c in cycles_old - cycles_new)

    def vkey(v: dict, rename) -> tuple:
        return (v["rule"], rename(v["source"]), rename(v["target"]))
    v_old = {vkey(v, lambda n: n) for v in old["violations"]}
    v_new = {vkey(v, name) for v in new["violations"]}
    result["violations_new"] = [list(v) for v in sorted(v_new - v_old)]
    result["violations_resolved"] = [list(v) for v in sorted(v_old - v_new)]
    l_old = {(lk["source"], lk["target"], lk["symbol"]) for lk in old["leaks"]}
    l_new = {(lk["source"], lk["target"], lk["symbol"]) for lk in new["leaks"]}
    result["leaks_new"] = [list(x) for x in sorted(l_new - l_old)]
    result["leaks_resolved"] = [list(x) for x in sorted(l_old - l_new)]

    def touching(snap: dict, rename) -> dict:
        total: dict = defaultdict(float)
        for e in snap["edges"]:
            total[rename(e["source"])] += e["weight"]
            total[rename(e["target"])] += e["weight"]
        return total
    t_old, t_new = touching(old, lambda n: n), touching(new, name)
    domain = {c["name"]: c["domain"] for c in new["components"]}
    result["coupling_trend"] = sorted(
        ({"component": to_new.get(o, o), "domain": domain.get(to_new.get(o, o), ""), "before": round(t_old[o], 2),
          "after": round(t_new[o], 2), "change": round(t_new[o] - t_old[o], 2)}
         for o in sorted(old_names & set(to_new)) if abs(t_new[o] - t_old[o]) > 1e-9),
        key=lambda r: (-abs(r["change"]), r["component"]))
    levels_old = {c["name"]: c["level"] for c in old["components"]}
    result["level_changes"] = [{"component": n, "before": levels_old[o], "after": lv}
                               for n, o in sorted(to_old.items())
                               for lv in [next(c["level"] for c in new["components"] if c["name"] == n)]
                               if lv != levels_old[o]]

    def pkey(p: dict, rename) -> tuple:
        return (p["id"], rename(p["component"]) if p["component"] else "")
    p_old = {pkey(p, lambda n: n): p["confidence"] for p in old["patterns"]}
    p_new = {pkey(p, name): p["confidence"] for p in new["patterns"]}
    result["patterns_changed"] = (
        [{"pattern": k[0], "component": k[1], "change": "appeared", "confidence": p_new[k]} for k in sorted(set(p_new) - set(p_old))]
        + [{"pattern": k[0], "component": k[1], "change": "gone", "confidence": p_old[k]} for k in sorted(set(p_old) - set(p_new))]
        + [{"pattern": k[0], "component": k[1], "change": f"{p_old[k]} to {p_new[k]}", "confidence": p_new[k]}
           for k in sorted(set(p_old) & set(p_new)) if p_old[k] != p_new[k]])
    result["worse"] = bool(result["cycles_new"] or result["violations_new"] or result["leaks_new"])
    return result


def lines(report: dict) -> list:
    """The report as plain text lines, worst first."""
    out = []

    def add(title: str, items: list) -> None:
        if items:
            out.append(f"{title} ({len(items)})")
            out.extend("  " + i for i in items[:15])
            if len(items) > 15:
                out.append(f"  ... and {len(items) - 15} more")
    add("New cycles", [" <-> ".join(c) for c in report["cycles_new"]])
    add("New rule and layer violations", [f"{r}: {s} -> {t}" for r, s, t in report["violations_new"]])
    add("New encapsulation leaks", [f"{s} -> {t}: {sym}" for s, t, sym in report["leaks_new"]])
    add("New dependencies between components", [f"{e['source']} -> {e['target']} ({', '.join(e['kinds'])})" for e in report["edges_added"]])
    add("Dependencies removed", [f"{e['source']} -> {e['target']}" for e in report["edges_removed"]])
    add("Components added", report["components_added"])
    add("Components removed", report["components_removed"])
    add("Components renamed", [f"{a} -> {b}" for a, b in report["renamed"]])
    add("Files moved to another component", [f"{m['unit']}: {m['from']} -> {m['to']}" for m in report["units_moved"]])
    add("Level changes", [f"{c['component']}: {c['before']} -> {c['after']}" for c in report["level_changes"]])
    add("Coupling trend", [f"{t['component']}: {t['before']} -> {t['after']} ({t['change']:+})" for t in report["coupling_trend"]])
    add("Patterns", [f"{p['pattern']}{' in ' + p['component'] if p['component'] else ''}: {p['change']}" for p in report["patterns_changed"]])
    add("Cycles resolved", [" <-> ".join(c) for c in report["cycles_resolved"]])
    add("Violations resolved", [f"{r}: {s} -> {t}" for r, s, t in report["violations_resolved"]])
    return out or ["No architectural change."]


def snapshot_at_ref(config_path: Path, ref: str, repo_root: Path) -> dict:
    """Run FWLens on the code at `ref` in a temporary worktree and return its snapshot."""
    def git(*args: str) -> str:
        out = subprocess.run(["git", "-C", str(repo_root), *args], capture_output=True, text=True)
        if out.returncode != 0:
            raise RuntimeError(f"git {' '.join(args)} failed: {out.stderr.strip()}")
        return out.stdout.strip()

    sha = git("rev-parse", "--verify", ref + "^{commit}")
    tmp = Path(tempfile.mkdtemp(prefix="fwlens-arch-"))
    worktree = tmp / "wt"
    git("worktree", "add", "--detach", str(worktree), sha)
    try:
        rel = Path(config_path).resolve().relative_to(Path(repo_root).resolve())
        target = tmp / "snapshot.json"
        proc = subprocess.run([sys.executable, "-I", "-m", "fwlens", "architecture", "save", "--config", str(worktree / rel),
                               "--output", str(target)], cwd=worktree, capture_output=True, text=True)
        if not target.exists():
            raise RuntimeError(f"analysis of {sha[:10]} produced no snapshot:\n{proc.stdout[-800:]}\n{proc.stderr[-800:]}")
        return load(target)
    finally:
        subprocess.run(["git", "-C", str(repo_root), "worktree", "remove", "--force", str(worktree)], capture_output=True)
        shutil.rmtree(tmp, ignore_errors=True)
