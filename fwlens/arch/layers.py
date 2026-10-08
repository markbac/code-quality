"""
Layers inferred from the dependencies.

Components are collapsed from the unit edges, strongly connected components are condensed, and every
component gets a level: 0 for one that depends on nothing else, otherwise one more than the highest
level of what it depends on. Components in a cycle share a level and are reported as a cycle, with the
dependencies that point upward inside it (the weakest way to break it). The inferred stack is shown
beside the configured `layers:` and the differences are listed, never applied.
"""

from __future__ import annotations

from collections import defaultdict

import networkx as nx

from fwlens.arch.model import Component, Edge, LayerModel


def component_graph(components: list[Component], edges: list[Edge]) -> nx.DiGraph:
    comp_of = {u: c.name for c in components for u in c.units}
    g = nx.DiGraph()
    g.add_nodes_from(sorted(c.name for c in components))
    for e in edges:
        a, b = comp_of.get(e.source), comp_of.get(e.target)
        if not a or not b or a == b:
            continue
        if g.has_edge(a, b):
            g[a][b]["weight"] += e.weight
            g[a][b]["kinds"].add(e.kind)
        else:
            g.add_edge(a, b, weight=e.weight, kinds={e.kind})
    return g


def infer_layers(components: list[Component], edges: list[Edge], configured_order: list[str] | None = None) -> LayerModel:
    """`configured_order` lists the configured layer names, lowest first (the order of `layers:`)."""
    g = component_graph(components, edges)
    model = LayerModel()
    sccs = [sorted(s) for s in nx.strongly_connected_components(g)]
    sccs.sort(key=lambda s: s[0])
    scc_of = {n: i for i, s in enumerate(sccs) for n in s}
    dag = nx.condensation(g, scc=[set(s) for s in sccs])
    mapping = dag.graph["mapping"]
    level_of_scc: dict[int, int] = {}
    for node in reversed(list(nx.topological_sort(dag))):
        successors = [level_of_scc[s] for s in dag.successors(node)]
        level_of_scc[node] = 1 + max(successors) if successors else 0
    model.level_of = {n: level_of_scc[mapping[n]] for n in g}

    for members in sccs:
        if len(members) > 1:
            model.cycles.append(members)
            sub = g.subgraph(members)
            height = {n: sum(d["weight"] for _a, _b, d in sub.out_edges(n, data=True))
                      - sum(d["weight"] for _a, _b, d in sub.in_edges(n, data=True)) for n in members}
            order = {n: i for i, n in enumerate(sorted(members, key=lambda n: (-height[n], n)))}
            for a, b, d in sub.edges(data=True):
                if order[a] > order[b]:
                    model.back_edges.append({"source": a, "target": b, "weight": round(d["weight"], 2),
                                             "kinds": sorted(d["kinds"])})
    model.back_edges.sort(key=lambda e: (-e["weight"], e["source"], e["target"]))

    by_level: dict[int, list[str]] = defaultdict(list)
    for n, lvl in model.level_of.items():
        by_level[lvl].append(n)
    in_cycle = {n for c in model.cycles for n in c}
    model.layers = [{"level": lvl, "components": sorted(by_level[lvl]),
                     "cycle": sorted(n for n in by_level[lvl] if n in in_cycle)}
                    for lvl in sorted(by_level, reverse=True)]

    down = nxt = 0.0
    for a, b, d in g.edges(data=True):
        if scc_of[a] == scc_of[b]:
            continue
        gap = model.level_of[a] - model.level_of[b]
        down += d["weight"]
        if gap == 1:
            nxt += d["weight"]
        else:
            model.skip_edges.append({"source": a, "target": b, "skips": gap - 1, "weight": round(d["weight"], 2),
                                     "kinds": sorted(d["kinds"])})
    model.next_layer_share = round(nxt / down, 3) if down else 1.0
    model.skip_edges.sort(key=lambda e: (-e["weight"], e["source"], e["target"]))

    rank = {name: i for i, name in enumerate(configured_order or [])}
    layer_of = {c.name: c.layer for c in components if c.layer in rank}
    for a, b, d in g.edges(data=True):
        if a in layer_of and b in layer_of and rank[layer_of[a]] < rank[layer_of[b]]:
            agrees = model.level_of[a] <= model.level_of[b]
            model.disagreements.append({
                "source": a, "target": b, "source_layer": layer_of[a], "target_layer": layer_of[b],
                "weight": round(d["weight"], 2),
                "note": "both orders put this dependency upward" if agrees
                else "configured order says upward, the dependencies put the source above the target"})
    model.disagreements.sort(key=lambda e: (-e["weight"], e["source"], e["target"]))
    return model
