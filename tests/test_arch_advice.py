"""Cycle-breaking suggestions and the interface catalogue (#132)."""

from arch_helpers import project

from fwlens.arch.advice import MAX_EXACT, _greedy
import networkx as nx

# A -> B once, B -> C once, C -> A three times, and B -> A twice: the cheapest way to break both cycles is
# to remove A -> B (1 call site), not C -> A (3) or B -> A (2) and B -> C.
FILES = {
    "a/a.h": "void a_fn(void);\n",
    "a/a.c": '#include "a.h"\n#include "../b/b.h"\nvoid a_fn(void){ b_fn(); }\nvoid a_unused(void){}\n',
    "b/b.h": "void b_fn(void);\n",
    "b/b.c": '#include "b.h"\n#include "../a/a.h"\n#include "../c/c.h"\nvoid b_fn(void){ c_fn(); a_fn(); a_fn(); }\n',
    "c/c.h": "void c_fn(void);\n",
    "c/c.c": '#include "c.h"\n#include "../a/a.h"\nvoid c_fn(void){ a_fn(); a_fn(); a_fn(); }\n',
}
COMPONENTS = [{"name": n.upper(), "units": [f"{n}/*"]} for n in ("a", "b", "c")]


def _arch(tmp_path, files=FILES):
    return project(tmp_path, files, components=COMPONENTS)[2]


def test_the_cheapest_edge_cut_is_suggested(tmp_path):
    arch = _arch(tmp_path)
    (s,) = arch.cycle_suggestions
    assert s["cycle"] == ["A", "B", "C"] and s["exact"]
    assert [(r["from"], r["to"]) for r in s["remove"]] == [("A", "B")]
    assert s["call_sites"] == s["remove"][0]["call_sites"]


def test_nothing_is_suggested_without_a_cycle(tmp_path):
    files = {k: v for k, v in FILES.items() if not k.startswith("c/")}
    files["b/b.c"] = '#include "b.h"\nvoid b_fn(void){}\n'
    assert _arch(tmp_path, files).cycle_suggestions == []


def test_the_greedy_cut_breaks_every_cycle():
    g = nx.DiGraph([("a", "b"), ("b", "c"), ("c", "a"), ("b", "a")])
    cost = {e: 1000 * w + 1 for e, w in {("a", "b"): 1, ("b", "c"): 1, ("c", "a"): 3, ("b", "a"): 2}.items()}
    cut = _greedy(g, cost)
    g.remove_edges_from(cut)
    assert nx.is_directed_acyclic_graph(g) and MAX_EXACT >= 3


def test_the_catalogue_lists_fan_in_and_unused_exports(tmp_path):
    arch = _arch(tmp_path)
    rows = {r["component"]: r for r in arch.interface_catalogue}
    a = {e["function"]: e for e in rows["A"]["exports"]}
    assert a["a_fn"]["used_by"] == ["B", "C"] and a["a_fn"]["fan_in"] == 2
    assert rows["B"]["unused"] == []
    assert "a_unused" not in a and "a_unused" not in rows["A"]["unused"]       # not in a header, so not public
