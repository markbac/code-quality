"""
Graph engine for fwlens.

Builds and analyses:
- Function call graph
- Module dependency graph
- Include graph
- SCC detection (Tarjan via networkx)
- Fan-in / fan-out computation
- Dead code candidate detection
- Instability / stable abstractions metrics
- ISR latency risk
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import networkx as nx

from fwlens.config import FwLensConfig
from fwlens.model.project import (
    ArchitectureViolation, DispatchTable, FunctionMetrics, GlobalVarInfo,
    GroupDirMismatch, ISRRisk, ModuleMetrics, ProjectModel, StackRisk,
)


def build_call_graph(model: ProjectModel) -> nx.DiGraph:
    """
    Build directed function call graph: FunctionName -> FunctionName.
    Node attributes: file, is_isr, is_entry_point.
    """
    G = nx.DiGraph()
    name_to_func: dict[str, FunctionMetrics] = {}

    for func in model.all_functions():
        G.add_node(func.name, file=str(func.file), is_isr=func.is_isr,
                   is_entry_point=func.is_entry_point, cc=func.cyclomatic_complexity)
        name_to_func[func.name] = func

    for func in model.all_functions():
        for callee in func.callees:
            G.add_edge(func.name, callee)

    return G


def build_module_dep_graph(model: ProjectModel, call_graph: nx.DiGraph) -> nx.DiGraph:
    """
    Build directed module dependency graph: Path -> Path.

    An edge A -> B means module A calls at least one function defined in module B.
    This gives meaningful fan-in/fan-out and instability metrics.
    Include-based edges are also added for modules with no resolvable call edges.
    """
    G = nx.DiGraph()

    # Index: function name -> module path
    func_to_module: dict[str, Path] = {}
    for m in model.modules:
        G.add_node(str(m.path), boundary=m.boundary_class.value, layer=m.layer)
        for f in m.functions:
            func_to_module[f.name] = m.path

    # Add call-based edges
    for m in model.modules:
        for f in m.functions:
            for callee in f.callees:
                callee_module = func_to_module.get(callee)
                if callee_module and callee_module != m.path:
                    G.add_edge(str(m.path), str(callee_module))

    return G


def build_include_graph(model: ProjectModel) -> nx.DiGraph:
    """
    Build directed include graph: file -> file, covering the FULL transitive include
    chain (any depth), not just each .c file's own direct #includes.

    Built from ModuleMetrics.all_include_edges rather than .includes: the latter is
    deliberately scoped to depth==1 (direct includes only) for callers like the
    unused-includes heuristic that need that narrower view. Using .includes here
    instead silently produced a graph with ONLY .c-file -> header edges and zero
    header -> header edges -- every file's computed include depth capped at 1 no
    matter how deep its real chain went, and circular/self includes routed through
    an intermediate header could never be detected, since no edge existed for the
    detector to walk. Building from the full per-depth edge list fixes both.
    """
    G = nx.DiGraph()
    for m in model.modules:
        src = str(m.path)
        G.add_node(src)
        for edge_src, edge_dst in m.all_include_edges:
            G.add_node(str(edge_src))
            G.add_node(str(edge_dst))
            G.add_edge(str(edge_src), str(edge_dst))
    return G


def compute_fan_in_out(model: ProjectModel, call_graph: nx.DiGraph) -> None:
    """Annotate FunctionMetrics with fan_in from the call graph."""
    in_degrees = dict(call_graph.in_degree())
    func_map: dict[str, FunctionMetrics] = {}
    for func in model.all_functions():
        func_map[func.name] = func

    for func in model.all_functions():
        func.fan_in = in_degrees.get(func.name, 0)
        # fan_out already set from callees list during AST walk


def compute_information_flow_complexity(model: ProjectModel) -> None:
    """
    Henry & Kafura's information flow complexity: IF4 = length x (fan_in x fan_out)^2.
    Uses LOC as the length proxy (the original metric used a program-specific length
    measure; LOC is the common substitute). Penalises functions that are both
    internally long AND heavily coupled through the call graph -- a different signal
    from cyclomatic complexity, which only measures internal branching and says
    nothing about how coupled the function is to the rest of the codebase.
    Must run after compute_fan_in_out (fan_in) -- fan_out is set during the AST walk.
    """
    for func in model.all_functions():
        func.information_flow_complexity = func.loc * (func.fan_in * func.fan_out) ** 2


def compute_module_coupling(model: ProjectModel, module_dep_graph: nx.DiGraph) -> None:
    """
    Compute per-module instability and stable abstractions metrics.
    I = Ce / (Ca + Ce)
    D = |A + I - 1|
    """
    nodes = list(module_dep_graph.nodes())
    in_deg = dict(module_dep_graph.in_degree())   # Ca (afferent)
    out_deg = dict(module_dep_graph.out_degree())  # Ce (efferent)

    path_to_module = {m.path: m for m in model.modules}

    for m in model.modules:
        key = str(m.path)
        Ca = in_deg.get(key, 0)
        Ce = out_deg.get(key, 0)
        m.fan_in = Ca
        m.fan_out = Ce
        total = Ca + Ce
        m.instability = Ce / total if total > 0 else 0.0

        # Abstractness: ratio of type declarations to total declarable entities.
        # A = type_decls / (type_decls + function_count)
        # This gives a meaningful 0-1 score even for .c files:
        # - A file with only functions and no types: A=0 (fully concrete)
        # - A file with types and functions: A somewhere between 0 and 1
        # - A file with only type declarations: A=1 (fully abstract)
        total_decls = m.function_count + m.type_decl_count
        if total_decls > 0:
            m.abstractness = m.type_decl_count / total_decls
        else:
            m.abstractness = 0.0

        m.main_sequence_distance = abs(m.abstractness + m.instability - 1.0)


def detect_scc(module_dep_graph: nx.DiGraph, model: ProjectModel) -> list[list[str]]:
    """
    Detect strongly connected components in the module dependency graph.
    Annotates modules with scc_id and in_cycle flag.
    Returns list of SCCs with more than one node (cycles).
    """
    sccs = list(nx.strongly_connected_components(module_dep_graph))
    cycles = [list(scc) for scc in sccs if len(scc) > 1]

    path_to_module = {str(m.path): m for m in model.modules}

    for i, scc in enumerate(sccs):
        for node in scc:
            if node in path_to_module:
                path_to_module[node].scc_id = i
                path_to_module[node].in_cycle = len(scc) > 1

    return cycles


def compute_include_depth(model: ProjectModel, include_graph: nx.DiGraph) -> None:
    """Compute max transitive include depth per .c module, and the actual longest
    chain that achieves it (not just the number) -- see ModuleMetrics.include_chain."""
    for m in model.modules:
        src = str(m.path)
        if src not in include_graph:
            m.include_depth = 0
            m.include_chain = []
            continue
        try:
            # BFS shortest paths from this node to everything reachable -- the
            # include graph has no weights, so shortest-path length == hop count,
            # which is exactly what "include depth" means here.
            paths = nx.single_source_shortest_path(include_graph, src)
            if paths:
                longest = max(paths.values(), key=len)
                m.include_depth = len(longest) - 1  # hops, not node count
                m.include_chain = [Path(p) for p in longest]
            else:
                m.include_depth = 0
                m.include_chain = []
        except Exception:
            m.include_depth = 0
            m.include_chain = []


def detect_dead_code(model: ProjectModel, call_graph: nx.DiGraph, config: FwLensConfig) -> None:
    """
    Flag functions with zero in-project callers as dead code candidates.
    Excludes: entry points, ISRs, functions not in first-party scope,
    and functions referenced in global variable initialisers (dispatch
    tables, command tables, callback structs, etc.).
    """
    entry_points = set(config.entry_points)
    in_degrees = dict(call_graph.in_degree())

    # Build a set of all functions referenced at file scope across all modules
    # (i.e. stored as function pointers in global arrays/structs).
    # These have no CALL_EXPR callers but are clearly live.
    file_scope_refs: set[str] = set()
    for module in model.modules:
        file_scope_refs.update(module.file_scope_fn_refs)

    for func in model.first_party_functions():
        if func.is_entry_point or func.is_isr:
            continue
        if func.name in entry_points:
            func.is_entry_point = True
            continue
        if func.name in file_scope_refs:
            continue
        if in_degrees.get(func.name, 0) == 0:
            func.is_dead_candidate = True
            model.dead_candidates.append(func)


def compute_stack_depth(model: ProjectModel, call_graph: nx.DiGraph) -> None:
    """
    Estimate worst-case stack depth per function from known entry points.
    Uses LOC as a proxy for frame size (not linker-accurate).
    Marks non-estimable for recursive functions and indirect calls.
    """
    func_map: dict[str, FunctionMetrics] = {f.name: f for f in model.all_functions()}

    # Detect recursion (cycles in call graph) via strongly-connected components --
    # any SCC with more than one node means every member can reach every other
    # member, i.e. is (mutually/indirectly) recursive. This is the right tool for
    # "which nodes are on some cycle": O(V+E), unlike nx.simple_cycles, which
    # enumerates every individual cycle and can be combinatorially expensive on a
    # large strongly-connected component (exactly the case in a codebase with
    # heavy callback/registration-chain recovery feeding the call graph).
    try:
        recursive_funcs: set[str] = set()
        for scc in nx.strongly_connected_components(call_graph):
            if len(scc) > 1:
                recursive_funcs |= scc
        # Also catch direct self-recursion (a 1-node SCC with a self-loop edge),
        # which strongly_connected_components alone doesn't flag as size > 1.
        recursive_funcs |= {n for n in call_graph.nodes() if call_graph.has_edge(n, n)}
    except Exception:
        recursive_funcs = set()

    # Mark recursive as non-estimable
    for func in model.all_functions():
        if func.name in recursive_funcs:
            func.stack_estimable = False

    # Topological sort over the acyclic subgraph only (recursive/cyclic nodes
    # removed) -- guaranteed to succeed by construction, unlike sorting the full
    # graph, which fails (NetworkXUnfeasible) as soon as ANY cycle exists anywhere
    # and previously fell back to an arbitrary order for the WHOLE graph, silently
    # producing wrong depths even for the (usually large) non-cyclic majority.
    acyclic_graph = call_graph.subgraph(
        [n for n in call_graph.nodes() if n not in recursive_funcs]
    )
    try:
        topo = list(nx.topological_sort(acyclic_graph))
    except nx.NetworkXUnfeasible:
        # Shouldn't happen given the SCC-based filtering above, but fall back to
        # an arbitrary order over just the (small, already-flagged) remainder
        # rather than failing outright.
        topo = list(acyclic_graph.nodes())

    depth_map: dict[str, int] = {}

    for name in reversed(topo):
        func = func_map.get(name)
        if func is None:
            depth_map[name] = 0
            continue
        if not func.stack_estimable:
            depth_map[name] = -1  # sentinel
            continue

        frame_estimate = max(4, func.loc // 4)  # rough: ~1 local per 4 LOC
        callee_depths = [
            depth_map.get(c, 0)
            for c in func.callees
            if depth_map.get(c, 0) >= 0
        ]
        max_callee = max(callee_depths) if callee_depths else 0
        depth_map[name] = frame_estimate + max_callee

    for func in model.all_functions():
        d = depth_map.get(func.name)
        if d is None or d < 0:
            func.stack_depth_estimate = None
            func.stack_estimable = False
        else:
            func.stack_depth_estimate = d


def compute_isr_latency_risk(model: ProjectModel, call_graph: nx.DiGraph) -> None:
    """
    Score ISR latency risk per ISR function.
    risk = own_cc + sum(transitive callee CC) + call_depth * penalty
    """
    depth_penalty = 2
    func_map: dict[str, FunctionMetrics] = {f.name: f for f in model.all_functions()}

    isr_funcs = [f for f in model.first_party_functions() if f.is_isr]

    for isr in isr_funcs:
        try:
            # BFS from ISR node
            reachable = nx.descendants(call_graph, isr.name)
            transitive_cc = sum(
                func_map[n].cyclomatic_complexity
                for n in reachable
                if n in func_map
            )
            # Max depth
            lengths = nx.single_source_shortest_path_length(call_graph, isr.name)
            call_depth = max(lengths.values()) if lengths else 0
        except Exception:
            transitive_cc = 0
            call_depth = 0
            non_estimable = True
        else:
            non_estimable = False

        risk_score = (
            isr.cyclomatic_complexity
            + transitive_cc
            + call_depth * depth_penalty
        )

        model.isr_risks.append(ISRRisk(
            isr_name=isr.name,
            file=isr.file,
            line=isr.line,
            own_cc=isr.cyclomatic_complexity,
            transitive_cc_sum=transitive_cc,
            call_depth=call_depth,
            risk_score=risk_score,
            non_estimable=non_estimable,
        ))

    model.isr_risks.sort(key=lambda r: r.risk_score, reverse=True)


def compute_entry_point_stack_risk(model: ProjectModel) -> None:
    """
    Surface worst-case stack depth for every entry point -- ISRs and configured
    task/main entry points -- not just ISRs.

    compute_stack_depth already gives every function its own worst-case depth
    (frame estimate + deepest callee chain); this just collects that figure for
    the functions actually invoked from outside the call graph (entry points)
    instead of leaving it buried in the full function list. Sorted deepest-first;
    non-estimable entries (recursion in the reachable call tree) sort last.
    """
    entries = [f for f in model.first_party_functions() if f.is_entry_point or f.is_isr]

    risks = [
        StackRisk(
            function_name=f.name,
            file=f.file,
            line=f.line,
            is_isr=f.is_isr,
            stack_depth_estimate=f.stack_depth_estimate,
            stack_estimable=f.stack_estimable,
        )
        for f in entries
    ]
    risks.sort(key=lambda r: (r.stack_depth_estimate is None, -(r.stack_depth_estimate or 0)))
    model.entry_point_stack_risks = risks


def compute_global_access_risk(model: ProjectModel) -> None:
    """
    Cross-reference every global variable against each function's global_reads/
    global_writes (already collected during the AST walk) to find its readers
    and writers, split by ISR vs non-ISR context.

    Flags `volatile_risk = True` for a variable touched from both an ISR and
    normal (main-loop) code without a volatile qualifier -- a classic
    non-atomic shared-state hazard on this class of MCU: the main loop can
    observe a torn read, or a write can be lost to instruction reordering /
    caching the compiler would otherwise avoid for a volatile-qualified access.
    """
    by_name: dict[str, list[GlobalVarInfo]] = {}
    for gv in model.globals:
        by_name.setdefault(gv.name, []).append(gv)

    for func in model.all_functions():
        for var_name in func.global_reads:
            for gv in by_name.get(var_name, []):
                if func.name not in gv.readers:
                    gv.readers.append(func.name)
                if func.is_isr and func.name not in gv.isr_readers:
                    gv.isr_readers.append(func.name)
        for var_name in func.global_writes:
            for gv in by_name.get(var_name, []):
                if func.name not in gv.writers:
                    gv.writers.append(func.name)
                if func.is_isr and func.name not in gv.isr_writers:
                    gv.isr_writers.append(func.name)

    for gv in model.globals:
        isr_touch = bool(gv.isr_readers or gv.isr_writers)
        main_touch = bool(
            set(gv.readers) - set(gv.isr_readers)
            or set(gv.writers) - set(gv.isr_writers)
        )
        gv.volatile_risk = isr_touch and main_touch and not gv.is_volatile


def detect_arch_violations(
    model: ProjectModel,
    module_dep_graph: nx.DiGraph,
    config: FwLensConfig,
) -> None:
    """
    Detect layer violations in the module dependency graph.

    Layer order is defined by position in config.layers (index 0 = lowest).
    A violation occurs when a module in a lower layer calls into a higher layer
    (upward), or skips one or more layers (skipped).
    Unknown-layer modules are excluded from violation detection.
    """
    from fwlens.model.project import ArchitectureViolation

    # Build layer rank map: layer name -> integer rank (0 = lowest)
    layer_rank: dict[str, int] = {
        rule.name: i for i, rule in enumerate(config.layers)
    }

    path_to_module = {str(m.path): m for m in model.modules}

    for src_str, dst_str in module_dep_graph.edges():
        src_mod = path_to_module.get(src_str)
        dst_mod = path_to_module.get(dst_str)
        if not src_mod or not dst_mod:
            continue

        src_layer = src_mod.layer
        dst_layer = dst_mod.layer
        if not src_layer or not dst_layer:
            continue
        if src_layer not in layer_rank or dst_layer not in layer_rank:
            continue

        src_rank = layer_rank[src_layer]
        dst_rank = layer_rank[dst_layer]

        # Downward dependency (higher layer -> lower layer) is expected -- no violation.
        # Upward dependency (lower layer -> higher layer) is a violation.
        if dst_rank > src_rank:
            gap = dst_rank - src_rank
            vtype = "skipped" if gap > 1 else "upward"
            model.arch_violations.append(ArchitectureViolation(
                source_module=src_mod.path,
                target_module=dst_mod.path,
                source_layer=src_layer,
                target_layer=dst_layer,
                violation_type=vtype,
                dependency_kind="call",
            ))


def compute_zone_metrics(model: ProjectModel, config: FwLensConfig) -> None:
    """
    Classify modules by actual defect-risk and change-pain.

    Pain score (0-1) is a weighted percentile composite of five signals:

      fan_in              33%  -- blast radius: how many modules break if this changes
      avg_cc              23%  -- structural complexity of making the change correctly
      avg_halstead_effort 18%  -- cognitive load while working in the code
      in_cycle            14%  -- whether the module can be tested in isolation
      indirect_call_sites  7%  -- hidden coupling via function pointers (understated fan-out)
      avg_magic_density    5%  -- unexplained literals that make value-changes risky

    All continuous components are percentile ranks within the first-party population,
    so the score is self-calibrating regardless of codebase size or absolute values.

    Zone of Pain threshold: pain_score >= 0.6.
    """
    fp = model.first_party_modules()
    if not fp:
        return

    fan_ins    = [m.fan_in               for m in fp]
    avg_ccs    = [m.avg_cc               for m in fp]
    efforts    = [m.avg_halstead_effort  for m in fp]
    magics     = [m.avg_magic_density    for m in fp]
    indirects  = [m.indirect_call_sites  for m in fp]

    def _pr(val: float, population: list[float]) -> float:
        """Percentile rank: fraction of population values strictly less than val."""
        if not population:
            return 0.0
        return sum(1 for v in population if v < val) / len(population)

    for m in fp:
        cycle_score = 1.0 if m.in_cycle else 0.0

        pain = (
            0.33 * _pr(m.fan_in,              fan_ins)    +
            0.23 * _pr(m.avg_cc,              avg_ccs)    +
            0.18 * _pr(m.avg_halstead_effort, efforts)    +
            0.14 * cycle_score                            +
            0.07 * _pr(m.indirect_call_sites, indirects)  +
            0.05 * _pr(m.avg_magic_density,   magics)
        )
        m.pain_score = round(pain, 3)

        if m.pain_score >= 0.6:
            m.zone = "pain"
        elif m.in_cycle:
            m.zone = "warning"
        else:
            m.zone = "main_sequence"


def analyse_group_dir_alignment(model: ProjectModel) -> None:
    """
    Compare each first-party file's IAR group name against its parent directory name.

    A mismatch means the IAR project tree and the filesystem directory structure have
    diverged -- common when files are reorganised in the IDE without moving them on disk,
    or when the IDE tree was never designed to mirror the filesystem.

    For each mismatch, records:
    - The file's actual parent directory name
    - The IAR group it belongs to
    - A suggested path showing where the file would live if directories mirrored groups

    The suggested path replaces only the immediate parent directory component with the
    IAR group name, leaving the rest of the path unchanged.
    """
    for module in model.first_party_modules():
        group = module.iar_groups[0] if module.iar_groups else None
        if not group:
            continue
        actual_dir = module.path.parent.name
        if actual_dir.lower() == group.lower():
            continue
        # Suggested path: same parent tree but immediate dir renamed to group name
        suggested_dir = module.path.parent.parent / group
        model.group_dir_mismatches.append(GroupDirMismatch(
            file=module.path,
            iar_group=group,
            actual_dir=actual_dir,
            layer=module.layer or "Unknown",
            suggested_dir=suggested_dir,
        ))

    model.group_dir_mismatches.sort(key=lambda m: (m.layer, m.iar_group, m.file.name))


def build_dispatch_table_index(model: ProjectModel, call_graph: nx.DiGraph) -> None:
    """
    Build the project-level dispatch table index and synthesise indirect call edges.

    For each dispatch table T defined in module M:
      - Find every function F (across all modules) whose global_reads contains T
      - Those functions are the "dispatchers" -- they execute items from the table
      - Add synthetic call edges F -> fn for every fn stored in T, tagged indirect=True
      - Record the full DispatchTable on model.dispatch_tables
      - Annotate F.dispatch_table_reads with T so the report can show the link

    This means:
      - Table-stored functions get correct fan_in (they have callers now)
      - ISR latency can follow through dispatch tables
      - The Function Pointers report tab shows the full dispatch chain
    """
    # Build a map: var_name -> (module, [fn_names], line)
    table_index: dict[str, tuple] = {}
    for module in model.modules:
        for var_name, fn_names in module.dispatch_tables.items():
            if fn_names:  # only tables that actually store functions
                line = module.dispatch_table_lines.get(var_name, 0)
                table_index[var_name] = (module, fn_names, line)

    if not table_index:
        return

    # Build a map: fn_name -> FunctionMetrics for fast lookup
    fn_map: dict[str, FunctionMetrics] = {}
    for module in model.modules:
        for fn in module.functions:
            fn_map[fn.name] = fn

    # For each function that reads a table variable, add synthetic edges
    for module in model.modules:
        for fn in module.functions:
            for var_name in fn.global_reads:
                if var_name not in table_index:
                    continue
                _def_module, fn_names, _line = table_index[var_name]
                if var_name not in fn.dispatch_table_reads:
                    fn.dispatch_table_reads.append(var_name)
                for target_fn in fn_names:
                    if target_fn and target_fn != fn.name:
                        if not call_graph.has_edge(fn.name, target_fn):
                            call_graph.add_edge(fn.name, target_fn, indirect=True)

    # Build a project-wide var→var registration map by merging all modules
    # e.g. DailyLogVft -> [DailyLog],  UIBatteryChange -> [emBatteryChange]
    var_reg_index: dict[str, list[str]] = {}
    for module in model.modules:
        for embedded_var, containers in module.var_registrations.items():
            var_reg_index.setdefault(embedded_var, [])
            for c in containers:
                if c not in var_reg_index[embedded_var]:
                    var_reg_index[embedded_var].append(c)

    # Build DispatchTable records with dispatcher lists and registration chains
    for var_name, (def_module, fn_names, line) in table_index.items():
        dispatchers = [
            fn.name
            for module in model.modules
            for fn in module.functions
            if var_name in fn.dispatch_table_reads
        ]
        model.dispatch_tables.append(DispatchTable(
            var_name=var_name,
            file=def_module.path,
            line=line,
            stored_fns=fn_names,
            dispatchers=dispatchers,
            registered_into=var_reg_index.get(var_name, []),
        ))

    model.dispatch_tables.sort(key=lambda t: t.var_name)


def run_graph_engine(model: ProjectModel, config: FwLensConfig) -> None:
    """Run the full graph engine pipeline, mutating model in place."""
    call_graph = build_call_graph(model)
    build_dispatch_table_index(model, call_graph)  # must be before fan-in/out
    module_dep_graph = build_module_dep_graph(model, call_graph)
    include_graph = build_include_graph(model)

    compute_fan_in_out(model, call_graph)
    compute_information_flow_complexity(model)
    compute_module_coupling(model, module_dep_graph)
    detect_scc(module_dep_graph, model)
    compute_include_depth(model, include_graph)
    detect_dead_code(model, call_graph, config)
    compute_stack_depth(model, call_graph)
    compute_entry_point_stack_risk(model)
    compute_isr_latency_risk(model, call_graph)
    compute_global_access_risk(model)
    detect_arch_violations(model, module_dep_graph, config)
    compute_zone_metrics(model, config)
    analyse_group_dir_alignment(model)

    # Store graphs on model for use by stats/reporting
    model._call_graph = call_graph
    model._module_dep_graph = module_dep_graph
    model._include_graph = include_graph

    from fwlens.header_checks import run_header_checks
    run_header_checks(model, config)