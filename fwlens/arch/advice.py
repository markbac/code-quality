"""
Advice from the recovered architecture. Nothing here changes the code or the findings.

    cycle suggestions   for each cycle of components, the dependencies whose removal makes it acyclic and costs the
                        fewest call sites. Exact for up to MAX_EXACT components in a cycle; larger cycles use a
                        greedy cut, which is not guaranteed to be the smallest.
    interface catalogue each component's public functions with the components that use them (fan-in), and the
                        exports nobody outside the component uses.

A function that is an interrupt handler, an entry point, `main`, an event callback, or stored in a dispatch table is
reached in ways the call graph does not show, so it is never listed as unused.
"""

from __future__ import annotations

import networkx as nx

from fwlens.arch.edges import norm
from fwlens.arch.layers import component_graph
from fwlens.arch.model import ArchModel
from fwlens.model.project import ProjectModel

MAX_EXACT = 12
ROWS = 30


def _sites(arch: ArchModel) -> dict:
    comp_of = {u: c.name for c in arch.components for u in c.units}
    sites: dict = {}
    for e in arch.edges:
        a, b = comp_of.get(e.source), comp_of.get(e.target)
        if a and b and a != b:
            row = sites.setdefault((a, b), {"call_sites": 0, "kinds": set(), "evidence": []})
            row["call_sites"] += e.count
            row["kinds"].add(e.kind)
            row["evidence"].extend(e.evidence[:1])
    return sites


def _cheapest_order(nodes: list[str], cost: dict) -> list[tuple[str, str]]:
    """The edges that point backwards in the ordering of `nodes` with the least total cost (dynamic programming over subsets)."""
    n = len(nodes)
    index = {v: i for i, v in enumerate(nodes)}
    back = [[0] * n for _ in range(n)]            # back[i][j]: cost of the edge i -> j when i is placed after j
    for (a, b), c in cost.items():
        back[index[a]][index[b]] = c
    best = {0: (0, -1)}
    for mask in range(1 << n):
        if mask not in best:
            continue
        base = best[mask][0]
        for v in range(n):
            if mask & (1 << v):
                continue
            # v is placed after everything already in mask: its edges into mask point backwards
            add = sum(back[v][u] for u in range(n) if mask & (1 << u))
            nxt = mask | (1 << v)
            if nxt not in best or base + add < best[nxt][0]:
                best[nxt] = (base + add, v)
    order, mask = [], (1 << n) - 1
    while mask:
        v = best[mask][1]
        order.append(nodes[v])
        mask &= ~(1 << v)
    order.reverse()
    position = {v: i for i, v in enumerate(order)}
    return sorted(e for e in cost if position[e[0]] > position[e[1]])


def _greedy(sub: nx.DiGraph, cost: dict) -> list[tuple[str, str]]:
    g = sub.copy()
    cut = []
    while True:
        try:
            cycle = nx.find_cycle(g)
        except nx.NetworkXNoCycle:
            break
        a, b = min(((u, v) for u, v, *_ in cycle), key=lambda e: (cost[e], e))
        g.remove_edge(a, b)
        cut.append((a, b))
    for e in sorted(cut, key=lambda e: -cost[e]):         # put back any edge the later cuts made unnecessary
        g.add_edge(*e)
        if not nx.is_directed_acyclic_graph(g):
            g.remove_edge(*e)
        else:
            cut.remove(e)
    return sorted(cut)


def cycle_suggestions(arch: ArchModel) -> list[dict]:
    sites = _sites(arch)
    graph = component_graph(arch.components, arch.edges)
    out = []
    for scc in sorted(sorted(s) for s in nx.strongly_connected_components(graph) if len(s) > 1):
        sub = graph.subgraph(scc).copy()
        # a call site costs 1000 and each edge 1, so fewer call sites win and then fewer edges
        cost = {(a, b): sites[(a, b)]["call_sites"] * 1000 + 1 for a, b in sub.edges}
        cut = _cheapest_order(scc, cost) if len(scc) <= MAX_EXACT else _greedy(sub, cost)
        remove = [{"from": a, "to": b, "call_sites": sites[(a, b)]["call_sites"], "kinds": sorted(sites[(a, b)]["kinds"]),
                   "examples": sites[(a, b)]["evidence"][:3]} for a, b in cut]
        remove.sort(key=lambda r: (r["call_sites"], r["from"], r["to"]))
        out.append({"cycle": scc, "exact": len(scc) <= MAX_EXACT, "remove": remove,
                    "call_sites": sum(r["call_sites"] for r in remove)})
    return out


def interface_catalogue(model: ProjectModel, arch: ArchModel) -> list[dict]:
    comp_of = {u: c.name for c in arch.components for u in c.units}
    functions = {f.name: f for m in model.modules for f in m.functions}
    unit_of = {f.name: norm(m.path) for m in model.modules for f in m.functions}
    callers: dict = {}
    for f in functions.values():
        for callee in f.callees:
            callers.setdefault(callee, set()).add(f.name)
    indirect = {s["callback"] for e in arch.events for s in e.subscribers}
    indirect |= {fn for t in model.dispatch_tables for fn in t.stored_fns}
    interfaces = {i.unit: i for i in arch.interfaces}
    rows = []
    for c in arch.components:
        public = sorted({name for u in c.units if u in interfaces for name in interfaces[u].public})
        exports, unused = [], []
        for name in public:
            fn = functions.get(name)
            users = sorted({comp_of[caller_unit] for caller in callers.get(name, ())
                            if (caller_unit := unit_of.get(caller, "")) in comp_of} - {c.name})
            exports.append({"function": name, "fan_in": len(users), "used_by": users})
            reached_otherwise = bool(fn and (fn.is_isr or fn.is_entry_point)) or name == "main" or name in indirect
            if not users and not reached_otherwise:
                unused.append(name)
        if exports:
            exports.sort(key=lambda r: (-r["fan_in"], r["function"]))
            rows.append({"component": c.name, "public": len(exports), "unused": unused,
                         "exports": exports[:ROWS]})
    rows.sort(key=lambda r: (-len(r["unused"]), -r["public"], r["component"]))
    return rows[:ROWS]

