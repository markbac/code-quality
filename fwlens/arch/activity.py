"""
Git history, ownership and shared state grouped by component.

    hotspots      commits, fix commits and the worst function hotspot score per component
    ownership     the main authors of a component's files, how fragmented the rest is, and the teams
                  (`architecture.teams` maps author names to teams)
    hidden        component pairs whose files change together with no dependency between them
    structural    component pairs with a strong dependency whose files never change together
    shared state  globals touched from more than one component, flagged when an interrupt is involved
                  or the components belong to different domains

Every row is a place to look, not a verdict. Ownership uses each file's main author, which is all the
git analysis keeps; without git history the first three are empty.
"""

from __future__ import annotations

from collections import defaultdict
from fnmatch import fnmatchcase

from fwlens.arch.edges import Units, norm
from fwlens.arch.layers import component_graph
from fwlens.arch.model import ArchModel
from fwlens.model.project import ProjectModel

ROWS = 30
STRUCTURAL_MIN_WEIGHT = 5.0
STRUCTURAL_MIN_COMMITS = 5


def team_of(author: str, teams: dict) -> str:
    for team, patterns in sorted(teams.items()):
        if any(fnmatchcase(author.lower(), str(p).lower()) for p in patterns):
            return team
    return ""


def compute(model: ProjectModel, arch: ArchModel, units: Units, teams: dict | None = None) -> dict:
    teams = teams or {}
    comp_of = {u: c.name for c in arch.components for u in c.units}
    domain = {s.name: s.domain for s in arch.subsystems}
    modules = {norm(m.path): m for m in model.modules}
    out: dict = {"hotspots": [], "ownership": [], "hidden_coupling": [], "structural_only": [], "shared_state": []}

    for c in arch.components:
        commits = fixes = 0
        worst, worst_fn = 0.0, ""
        authors: dict = defaultdict(int)
        fragmentation = []
        for u in c.units:
            m = modules.get(u)
            if not m:
                continue
            commits += m.commit_count
            fixes += m.bugfix_commit_count
            for f in m.functions:
                if f.hotspot_score > worst:
                    worst, worst_fn = f.hotspot_score, f.name
            if m.main_author:
                authors[m.main_author] += 1
                fragmentation.append(m.ownership_fragmentation)
        if commits:
            out["hotspots"].append({"component": c.name, "commits": commits, "fix_commits": fixes,
                                    "worst_hotspot": round(worst, 2), "worst_function": worst_fn})
        if authors:
            names = sorted(authors, key=lambda a: (-authors[a], a))
            team_set = sorted({t for a in names if (t := team_of(a, teams))})
            out["ownership"].append({"component": c.name, "main_authors": names[:5], "author_count": len(names),
                                     "fragmentation": round(sum(fragmentation) / len(fragmentation), 2),
                                     "teams": team_set, "several_teams": len(team_set) > 1})
    out["hotspots"].sort(key=lambda r: (-r["worst_hotspot"], -r["commits"], r["component"]))
    out["ownership"].sort(key=lambda r: (-r["several_teams"], -r["author_count"], r["component"]))

    graph = component_graph(arch.components, arch.edges)
    linked = {frozenset((a, b)) for a, b in graph.edges()}
    pairs: dict = defaultdict(lambda: {"co_changes": 0, "files": 0, "coupling": 0.0})
    for p in model.change_coupling:
        a, b = comp_of.get(units.owner(p.file_a) or ""), comp_of.get(units.owner(p.file_b) or "")
        if a and b and a != b:
            row = pairs[tuple(sorted((a, b)))]
            row["co_changes"] += p.co_changes
            row["files"] += 1
            row["coupling"] += p.coupling
    for (a, b), row in pairs.items():
        entry = {"a": a, "b": b, "co_changes": row["co_changes"], "file_pairs": row["files"],
                 "avg_coupling": round(row["coupling"] / row["files"], 2)}
        if frozenset((a, b)) not in linked:
            out["hidden_coupling"].append(entry)
    out["hidden_coupling"].sort(key=lambda r: (-r["co_changes"], r["a"], r["b"]))

    commits_by = {r["component"]: r["commits"] for r in out["hotspots"]}
    seen = set()
    for a, b, d in graph.edges(data=True):
        key = tuple(sorted((a, b)))
        if key in seen:
            continue
        seen.add(key)
        weight = d["weight"] + (graph[b][a]["weight"] if graph.has_edge(b, a) else 0.0)
        if (weight >= STRUCTURAL_MIN_WEIGHT and key not in pairs
                and min(commits_by.get(a, 0), commits_by.get(b, 0)) >= STRUCTURAL_MIN_COMMITS):
            out["structural_only"].append({"a": key[0], "b": key[1], "weight": round(weight, 2)})
    out["structural_only"].sort(key=lambda r: (-r["weight"], r["a"], r["b"]))

    function_unit = {f.name: norm(m.path) for m in model.modules for f in m.functions}
    for g in model.globals:
        owner = comp_of.get(units.owner(g.file) or "")
        users = {comp_of[function_unit[fn]] for fn in [*g.readers, *g.writers] if fn in function_unit
                 and function_unit[fn] in comp_of}
        touched = users | ({owner} if owner else set())
        if len(touched) < 2:
            continue
        domains = {domain.get(c, "") for c in touched} - {""}
        out["shared_state"].append({
            "name": g.name, "owner": owner or "", "components": sorted(touched),
            "isr": bool(g.isr_readers or g.isr_writers), "volatile_risk": bool(g.volatile_risk),
            "crosses_domain": len(domains) > 1})
    out["shared_state"].sort(key=lambda r: (-r["volatile_risk"], -r["isr"], -r["crosses_domain"], -len(r["components"]), r["name"]))
    for key in out:
        out[key] = out[key][:ROWS]
    return out
