"""
Components inferred from the dependencies, and directory drift.

1. Components you pin (`architecture.components`) are taken first.
2. Units in the same IDE group (IAR, Keil, Eclipse) form a component; a group larger than
   `architecture.max_component_units` is split by community detection.
3. The rest are clustered by community detection (Louvain, seeded, so a run is repeatable) on the
   weighted dependency graph. Units with no dependencies are grouped by directory.

Configured layers and groups are kept as they are. `differences` lists where the inferred components
disagree with them.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from fnmatch import fnmatchcase
from pathlib import PurePosixPath

import networkx as nx

from fwlens.arch.edges import norm
from fwlens.arch.model import Component, Drift, Edge
from fwlens.model.project import ProjectModel

SEED = 0


def matches(path: str, pattern: str) -> bool:
    pattern = norm(pattern)
    return fnmatchcase(path, pattern) or fnmatchcase(path, "*/" + pattern.lstrip("/"))


def coupling_graph(units: list[str], edges: list[Edge]) -> nx.Graph:
    g = nx.Graph()
    g.add_nodes_from(sorted(units))
    for e in edges:
        w = g.get_edge_data(e.source, e.target, {}).get("weight", 0.0)
        g.add_edge(e.source, e.target, weight=w + e.weight)
    return g


def _communities(g: nx.Graph, nodes: list[str], resolution: float) -> list[list[str]]:
    sub = g.subgraph(sorted(nodes))
    if sub.number_of_edges() == 0:
        return [[n] for n in sorted(nodes)]
    found = nx.community.louvain_communities(sub, weight="weight", resolution=resolution, seed=SEED)
    return sorted((sorted(c) for c in found), key=lambda c: c[0])


def _name_for(units: list[str], taken: set[str]) -> str:
    dirs = Counter(PurePosixPath(u).parent.name or "root" for u in units)
    base = sorted(dirs.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
    name, n = base, 2
    while name in taken:
        name, n = f"{base}-{n}", n + 1
    return name


def infer(model: ProjectModel, units: list[str], edges: list[Edge], pinned: list[dict] | None = None,
          resolution: float = 1.0, max_units: int = 40, drift_threshold: float = 0.6):
    """Returns (components, drift, differences)."""
    g = coupling_graph(units, edges)
    group_of: dict[str, str] = {}
    layer_of: dict[str, str] = {}
    for m in model.modules:
        u = norm(m.path)
        if u in g:
            if m.iar_groups:
                group_of[u] = m.iar_groups[-1]
            if m.layer:
                layer_of[u] = m.layer

    components: list[Component] = []
    taken: set[str] = set()
    placed: set[str] = set()

    def add(name: str, members: list[str], source: str) -> None:
        if not members:
            return
        name = name if name not in taken else _name_for(members, taken)
        taken.add(name)
        components.append(Component(f"c{len(components) + 1}", name, sorted(members), source))
        placed.update(members)

    for spec in pinned or []:
        add(str(spec["name"]), [u for u in sorted(g) if u not in placed and any(matches(u, p) for p in spec["units"])], "pinned")

    by_group: dict[str, list[str]] = defaultdict(list)
    for u in sorted(g):
        if u not in placed and u in group_of:
            by_group[group_of[u]].append(u)
    for name, members in sorted(by_group.items()):
        if len(members) <= max_units:
            add(name, members, "group")
        else:
            for part in _communities(g, members, resolution):
                add(f"{name}/{_name_for(part, set())}", part, "group+community")

    rest = [u for u in sorted(g) if u not in placed]
    for part in _communities(g, rest, resolution):
        if len(part) == 1 and g.degree(part[0]) == 0:
            continue
        add(_name_for(part, taken), part, "community")
    loners: dict[str, list[str]] = defaultdict(list)
    for u in rest:
        if u not in placed:
            loners[str(PurePosixPath(u).parent)].append(u)
    for directory, members in sorted(loners.items()):
        add(PurePosixPath(directory).name or "root", members, "directory")

    component_of = {u: c.id for c in components for u in c.units}
    for c in components:
        inside = total = 0.0
        for u in c.units:
            for v, data in g[u].items():
                total += data["weight"]
                inside += data["weight"] if component_of[v] == c.id else 0.0
        c.cohesion = round(inside / total, 3) if total else 1.0
        c.configured = sorted({x for u in c.units for x in (layer_of.get(u), group_of.get(u)) if x})
        counted = Counter(layer_of[u] for u in c.units if u in layer_of)
        c.layer = sorted(counted.items(), key=lambda kv: (-kv[1], kv[0]))[0][0] if counted else ""

    by_dir: dict[str, Counter] = defaultdict(Counter)
    for u in g:
        by_dir[str(PurePosixPath(u).parent)][component_of[u]] += 1
    dir_component = {d: sorted(cnt.items(), key=lambda kv: (-kv[1], kv[0]))[0][0] for d, cnt in by_dir.items()}
    names = {c.id: c.name for c in components}
    drift: list[Drift] = []
    for u in sorted(g):
        weights: Counter = Counter()
        for v, data in g[u].items():
            weights[component_of[v]] += data["weight"]
        total = sum(weights.values())
        if not total:
            continue
        home = dir_component[str(PurePosixPath(u).parent)]
        outside = 1 - weights.get(home, 0.0) / total
        if outside >= drift_threshold:
            best = sorted(weights.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
            drift.append(Drift(u, str(PurePosixPath(u).parent), names[home], names[best], round(outside, 3), round(total, 2)))
    drift.sort(key=lambda d: (-d.outside, -d.weight, d.unit))

    differences = []
    for c in components:
        layers = sorted({layer_of[u] for u in c.units if u in layer_of})
        if len(layers) > 1:
            differences.append({"kind": "spans-layers", "component": c.name, "detail": layers})
    spread: dict[str, set[str]] = defaultdict(set)
    for u, grp in group_of.items():
        spread[grp].add(component_of[u])
    for grp, ids in sorted(spread.items()):
        if len(ids) > 1:
            differences.append({"kind": "group-split", "component": grp, "detail": sorted(names[i] for i in ids)})
    return components, drift, differences

