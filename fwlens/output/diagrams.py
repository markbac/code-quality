"""
Architecture and call-graph visualisation for fwlens.

- generate_architecture_diagram: whole-codebase Mermaid flowchart, modules
  grouped into subgraphs by architecture layer, coloured by zone (pain /
  uselessness / warning / OK). Derived directly from the module dependency
  graph fwlens already builds, so it can't drift out of sync with the model
  the way a hand-maintained C4/Structurizr diagram can.
- generate_dependency_svg: the same module dependency graph as a
  networkx/matplotlib SVG, node size proportional to LOC.
- generate_call_graph_diagram: an on-demand Mermaid diagram scoped to one
  function -- callers (blast radius: what breaks if this changes), callees
  (dispatch chain: what this reaches), or both -- out to a configurable depth.

Mermaid labels use <br/> for line breaks, not \\n (Mermaid doesn't render
literal newlines inside node labels).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import networkx as nx

from fwlens.config import FwLensConfig
from fwlens.model.project import ProjectModel, StateMachine

_ZONE_CLASS = {
    "pain": "pain",
    "uselessness": "useless",
    "warning": "warning",
    "main_sequence": "ok",
}
_ZONE_COLOUR = {
    "pain": "#dc2626",
    "uselessness": "#ca8a04",
    "warning": "#d97706",
    "main_sequence": "#16a34a",
    "unknown": "#6b7280",
}

_MERMAID_CLASSDEFS = (
    "    classDef pain fill:#fee2e2,stroke:#dc2626,color:#7f1d1d\n"
    "    classDef useless fill:#fef9c3,stroke:#ca8a04,color:#713f12\n"
    "    classDef warning fill:#fef3c7,stroke:#d97706,color:#78350f\n"
    "    classDef ok fill:#dcfce7,stroke:#16a34a,color:#14532d\n"
    "    classDef unknown fill:#f3f4f6,stroke:#6b7280,color:#1f2937\n"
    "    classDef root fill:#dbeafe,stroke:#2563eb,color:#1e3a8a,stroke-width:3px\n"
)


def _safe_label(text: str) -> str:
    return re.sub(r'["\[\]{}|]', "", text)


def _safe_id(text: str) -> str:
    return re.sub(r'\W', "_", text)


def _xml_escape(text: str) -> str:
    return (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace('"', "&quot;"))


def generate_architecture_svg_inline(model: ProjectModel, config: FwLensConfig,
                                      source_index: Optional[dict] = None) -> str:
    """
    Return raw <svg>...</svg> markup for embedding directly inline in the HTML report
    (not written to a file) -- modules grouped into horizontal bands by architecture
    layer, coloured by zone, with dependency edges drawn between them. A hand-rolled
    look-alike of generate_architecture_diagram's Mermaid output, not literally the
    same renderer: no JS graph library or Mermaid bundle needed, and boxes are
    clickable via the report's existing showFile() source-view modal, since the SVG
    is inlined into the page DOM rather than referenced as an external image.
    """
    source_index = source_index or {}
    dep_graph: Optional[nx.DiGraph] = getattr(model, "_module_dep_graph", None)
    fp_modules = model.first_party_modules()
    fp_paths = {str(m.path) for m in fp_modules}
    module_by_path = {str(m.path): m for m in fp_modules}

    if not fp_modules:
        return '<svg width="400" height="80"><text x="10" y="40" fill="#6b7280" font-size="13">No first-party modules.</text></svg>'

    layers: dict[str, list[str]] = {}
    for p, m in module_by_path.items():
        layers.setdefault(m.layer or "Unknown", []).append(p)

    layer_order = [rule.name for rule in config.layers] + ["Unknown"]
    ordered_layers = [l for l in layer_order if l in layers] + \
                      [l for l in layers if l not in layer_order]

    # --- Layout constants ---
    BOX_W, BOX_H = 160, 46
    H_GAP, V_GAP = 24, 14
    LABEL_H = 26
    BAND_PAD = 12
    MARGIN = 16
    MAX_ROW_W = 920
    per_row = max(1, (MAX_ROW_W + H_GAP) // (BOX_W + H_GAP))

    # --- Pass 1: compute box positions per layer band ---
    positions: dict[str, dict] = {}   # path -> {x, y, w, h, cx, cy}
    band_rects: list[dict] = []       # {y, h, label}
    y = MARGIN

    for layer_name in ordered_layers:
        paths_in_layer = sorted(layers[layer_name])
        n = len(paths_in_layer)
        rows = -(-n // per_row)  # ceil
        band_top = y
        grid_top = y + LABEL_H + BAND_PAD
        for i, p in enumerate(paths_in_layer):
            row, col = divmod(i, per_row)
            bx = MARGIN + col * (BOX_W + H_GAP)
            by = grid_top + row * (BOX_H + V_GAP)
            positions[p] = {
                "x": bx, "y": by, "w": BOX_W, "h": BOX_H,
                "cx": bx + BOX_W / 2, "cy": by + BOX_H / 2,
            }
        band_h = LABEL_H + BAND_PAD + rows * BOX_H + max(0, rows - 1) * V_GAP + BAND_PAD
        band_rects.append({"y": band_top, "h": band_h, "label": layer_name})
        y = band_top + band_h + V_GAP

    total_w = MARGIN * 2 + per_row * BOX_W + max(0, per_row - 1) * H_GAP
    total_h = y + MARGIN
    ARC_HEADROOM = 44
    total_h += ARC_HEADROOM
    for pos in positions.values():
        pos["y"] += ARC_HEADROOM
        pos["cy"] += ARC_HEADROOM
    for band in band_rects:
        band["y"] += ARC_HEADROOM

    # --- Pass 2: edges ---
    edges = []
    if dep_graph is not None:
        for src, dst in dep_graph.edges():
            if src in fp_paths and dst in fp_paths and src != dst and src in positions and dst in positions:
                edges.append((src, dst))

    def _edge_path(a: dict, b: dict, seed: int) -> tuple:
        """
        Path 'd' plus start/end points. Same-row edges between non-adjacent boxes
        arc above the row instead of drawing straight through intervening boxes --
        a strict nearest-side anchor makes every edge from a fan-out source overlap
        into what looks like a single chain when all targets share a row. The lift
        varies by seed so multiple long same-row edges don't stack exactly on top
        of each other either.
        """
        dx = b["cx"] - a["cx"]
        dy = b["cy"] - a["cy"]
        same_row = abs(dy) < 5
        adjacent = abs(dx) <= (BOX_W + H_GAP) * 1.3

        if same_row and not adjacent:
            x1, y1 = a["cx"], a["y"]
            x2, y2 = b["cx"], b["y"]
            lift = 16 + 9 * (seed % 4)
            mx, my = (x1 + x2) / 2, min(y1, y2) - lift
            return f'M{x1:.0f},{y1:.0f} Q{mx:.0f},{my:.0f} {x2:.0f},{y2:.0f}'

        if abs(dy) >= abs(dx):
            if dy >= 0:
                x1, y1 = a["cx"], a["y"] + a["h"]
                x2, y2 = b["cx"], b["y"]
            else:
                x1, y1 = a["cx"], a["y"]
                x2, y2 = b["cx"], b["y"] + b["h"]
        elif dx >= 0:
            x1, y1 = a["x"] + a["w"], a["cy"]
            x2, y2 = b["x"], b["cy"]
        else:
            x1, y1 = a["x"], a["cy"]
            x2, y2 = b["x"] + b["w"], b["cy"]
        mx, my = (x1 + x2) / 2, (y1 + y2) / 2
        return f'M{x1:.0f},{y1:.0f} Q{mx:.0f},{my:.0f} {x2:.0f},{y2:.0f}'

    svg_parts = []
    svg_parts.append(
        f'<svg viewBox="0 0 {total_w} {total_h}" width="100%" '
        f'style="max-width:{total_w}px;background:#111827;border-radius:8px" '
        f'xmlns="http://www.w3.org/2000/svg">'
    )
    svg_parts.append(
        '<defs><marker id="fwlens-arrow" viewBox="0 0 10 10" refX="9" refY="5" '
        'markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
        '<path d="M0,0 L10,5 L0,10 z" fill="#64748b"/></marker></defs>'
    )

    for band in band_rects:
        svg_parts.append(
            f'<rect x="4" y="{band["y"]}" width="{total_w - 8}" height="{band["h"]}" '
            f'rx="6" fill="#1f2937" stroke="#374151" stroke-width="1"/>'
        )
        svg_parts.append(
            f'<text x="{MARGIN}" y="{band["y"] + 18}" fill="#9ca3af" '
            f'font-size="12" font-weight="600" font-family="sans-serif">'
            f'{_xml_escape(band["label"])}</text>'
        )

    for i, (src, dst) in enumerate(edges):
        path_d = _edge_path(positions[src], positions[dst], seed=i)
        svg_parts.append(
            f'<path d="{path_d}" fill="none" stroke="#64748b" stroke-width="1.2" '
            f'stroke-opacity="0.55" marker-end="url(#fwlens-arrow)"/>'
        )

    for p, pos in positions.items():
        m = module_by_path[p]
        colour = _ZONE_COLOUR.get(getattr(m, "zone", ""), _ZONE_COLOUR["unknown"])
        has_source = p.replace("\\", "/") in source_index
        label = _xml_escape(m.path.name)
        if len(label) > 20:
            label = label[:18] + "…"
        onclick = f" onclick=\"showFile('{p.replace(chr(92), '/')}')\"" \
                  f" style=\"cursor:pointer\"" if has_source else ""
        svg_parts.append(f'<g{onclick}>')
        svg_parts.append(
            f'<rect x="{pos["x"]}" y="{pos["y"]}" width="{pos["w"]}" height="{pos["h"]}" '
            f'rx="5" fill="{colour}" fill-opacity="0.18" stroke="{colour}" stroke-width="1.5"/>'
        )
        svg_parts.append(
            f'<text x="{pos["cx"]:.0f}" y="{pos["cy"] - 2:.0f}" fill="#e5e7eb" '
            f'font-size="12" text-anchor="middle" font-family="sans-serif">{label}</text>'
        )
        svg_parts.append(
            f'<text x="{pos["cx"]:.0f}" y="{pos["cy"] + 14:.0f}" fill="#9ca3af" '
            f'font-size="10" text-anchor="middle" font-family="sans-serif">{m.loc} LOC</text>'
        )
        svg_parts.append('</g>')

    svg_parts.append('</svg>')
    return "".join(svg_parts)


def generate_architecture_diagram(model: ProjectModel, config: FwLensConfig) -> Path:
    """
    Write a whole-codebase Mermaid flowchart to <reports_dir>/diagrams/architecture.md,
    modules grouped by layer, coloured by zone. Returns the written path.
    """
    dep_graph: Optional[nx.DiGraph] = getattr(model, "_module_dep_graph", None)
    fp_modules = model.first_party_modules()
    fp_paths = {str(m.path) for m in fp_modules}
    module_by_path = {str(m.path): m for m in fp_modules}

    lines = ["```mermaid", "flowchart TD", _MERMAID_CLASSDEFS.rstrip("\n")]

    node_id = {p: f"n{_safe_id(p)}" for p in fp_paths}

    layers: dict[str, list[str]] = {}
    for p, m in module_by_path.items():
        layers.setdefault(m.layer or "Unknown", []).append(p)

    layer_order = [rule.name for rule in config.layers] + ["Unknown"]
    ordered_layers = [l for l in layer_order if l in layers] + \
                      [l for l in layers if l not in layer_order]

    class_lines = []
    for layer_name in ordered_layers:
        paths_in_layer = layers[layer_name]
        lines.append(f'    subgraph {_safe_id(layer_name)}["{_safe_label(layer_name)}"]')
        for p in sorted(paths_in_layer):
            m = module_by_path[p]
            label = f"{_safe_label(m.path.name)}<br/>{m.loc} LOC"
            lines.append(f'        {node_id[p]}["{label}"]')
            zone_class = _ZONE_CLASS.get(getattr(m, "zone", ""), "unknown")
            class_lines.append(f"    class {node_id[p]} {zone_class}")
        lines.append("    end")

    if dep_graph is not None:
        for src, dst in dep_graph.edges():
            if src in fp_paths and dst in fp_paths and src != dst:
                lines.append(f"    {node_id[src]} --> {node_id[dst]}")

    lines.extend(class_lines)
    lines.append("```")

    out_dir = config.output.reports_dir / "diagrams"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "architecture.md"
    out_path.write_text(
        "# Architecture Diagram\n\n"
        "Auto-generated from the module dependency graph -- modules grouped by layer, "
        "coloured by zone (red = zone of pain, yellow = zone of uselessness / warning, "
        "green = main sequence).\n\n" + "\n".join(lines) + "\n",
        encoding="utf-8",
    )
    return out_path


def generate_dependency_svg(model: ProjectModel, config: FwLensConfig) -> Path:
    """Write the module dependency graph as an SVG to <reports_dir>/diagrams/dependency_graph.svg."""
    dep_graph: Optional[nx.DiGraph] = getattr(model, "_module_dep_graph", None)
    fp_modules = model.first_party_modules()
    fp_paths = {str(m.path) for m in fp_modules}
    module_by_path = {str(m.path): m for m in fp_modules}

    out_dir = config.output.reports_dir / "diagrams"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "dependency_graph.svg"

    G = nx.DiGraph()
    G.add_nodes_from(fp_paths)
    if dep_graph is not None:
        for src, dst in dep_graph.edges():
            if src in fp_paths and dst in fp_paths and src != dst:
                G.add_edge(src, dst)

    if not G.nodes():
        fig, ax = plt.subplots(figsize=(4, 2))
        ax.text(0.5, 0.5, "No first-party modules", ha="center", va="center")
        ax.axis("off")
        fig.savefig(out_path)
        plt.close(fig)
        return out_path

    pos = nx.spring_layout(G, seed=42, k=1.2 / max(1, len(G.nodes()) ** 0.5))

    locs = [max(module_by_path[p].loc, 1) for p in G.nodes()]
    max_loc = max(locs)
    sizes = [200 + 1800 * (l / max_loc) for l in locs]
    colours = [_ZONE_COLOUR.get(getattr(module_by_path[p], "zone", ""), _ZONE_COLOUR["unknown"])
               for p in G.nodes()]
    labels = {p: module_by_path[p].path.name for p in G.nodes()}

    fig, ax = plt.subplots(figsize=(max(10, len(G.nodes()) * 0.4), max(8, len(G.nodes()) * 0.3)))
    nx.draw_networkx_edges(G, pos, ax=ax, arrows=True, arrowsize=10, alpha=0.4, edge_color="#94a3b8")
    nx.draw_networkx_nodes(G, pos, ax=ax, node_size=sizes, node_color=colours, alpha=0.9)
    nx.draw_networkx_labels(G, pos, labels=labels, ax=ax, font_size=8)
    ax.set_title("Module Dependency Graph  (node size = LOC, colour = zone)")
    ax.axis("off")
    fig.tight_layout()
    fig.savefig(out_path)
    plt.close(fig)
    return out_path


def generate_call_graph_diagram(
    model: ProjectModel,
    function_name: str,
    direction: str = "both",
    depth: int = 4,
) -> str:
    """
    Return a Mermaid flowchart (as a string, ```mermaid fenced) scoped to one function.

    direction:
      "callees" -- dispatch chain: what function_name reaches, forward from it
      "callers" -- blast radius: what would be affected if function_name changes
      "both"    -- both directions in one diagram
    """
    call_graph = getattr(model, "_call_graph", None)
    if call_graph is None or function_name not in call_graph:
        available = ""
        if call_graph is not None:
            close = [n for n in call_graph.nodes() if function_name.lower() in n.lower()]
            if close:
                available = "  Did you mean: " + ", ".join(sorted(close)[:5])
        raise ValueError(f"'{function_name}' not found in the call graph.{available}")

    func_map = {f.name: f for f in model.all_functions()}

    nodes: set[str] = {function_name}
    edges: set[tuple[str, str]] = set()

    if direction in ("callees", "both"):
        frontier = {function_name}
        for _ in range(depth):
            nxt = set()
            for n in frontier:
                for callee in call_graph.successors(n):
                    edges.add((n, callee))
                    if callee not in nodes:
                        nxt.add(callee)
                    nodes.add(callee)
            frontier = nxt
            if not frontier:
                break

    if direction in ("callers", "both"):
        frontier = {function_name}
        for _ in range(depth):
            nxt = set()
            for n in frontier:
                for caller in call_graph.predecessors(n):
                    edges.add((caller, n))
                    if caller not in nodes:
                        nxt.add(caller)
                    nodes.add(caller)
            frontier = nxt
            if not frontier:
                break

    lines = ["```mermaid", "flowchart TD", _MERMAID_CLASSDEFS.rstrip("\n")]
    node_id = {n: f"n{_safe_id(n)}" for n in nodes}
    class_lines = []

    for n in sorted(nodes):
        f = func_map.get(n)
        if f:
            label = f"{_safe_label(n)}<br/>CC={f.cyclomatic_complexity}  LOC={f.loc}"
            zone_class = "root" if n == function_name else (
                "pain" if f.structural_debt_index >= 0.6 else "ok"
            )
        else:
            label = f"{_safe_label(n)}<br/>(external/unresolved)"
            zone_class = "unknown"
        lines.append(f'    {node_id[n]}["{label}"]')
        class_lines.append(f"    class {node_id[n]} {zone_class}")

    for src, dst in sorted(edges):
        lines.append(f"    {node_id[src]} --> {node_id[dst]}")

    lines.extend(class_lines)
    lines.append("```")
    return "\n".join(lines)


_RTOS_KIND_COLOUR = {
    "semaphore": "#a855f7", "mutex": "#ec4899", "mailbox": "#06b6d4",
    "queue": "#06b6d4", "event": "#eab308", "rwlock": "#f97316",
}


def generate_rtos_object_graph_svg_inline(model: ProjectModel) -> str:
    """
    Return raw <svg>...</svg> markup for the RTOS object graph: tasks in a left
    column (sorted by priority), synchronisation objects in a right column, edges
    coloured by access kind (amber = wait/blocking-acquire, green = signal/release,
    grey = other). A different architecture axis from the file/module dependency
    graph -- organised by runtime concurrency structure rather than source layout.
    """
    tasks = model.rtos_tasks
    objects = model.rtos_sync_objects
    usages = model.rtos_object_usages

    if not tasks and not objects:
        return ('<svg width="360" height="60"><text x="10" y="35" fill="#6b7280" '
                'font-size="13">No RTOS objects detected.</text></svg>')

    TASK_W, TASK_H = 190, 52
    OBJ_W, OBJ_H = 150, 42
    V_GAP = 18
    COL_GAP = 240
    MARGIN = 20

    sorted_tasks = sorted(
        tasks, key=lambda t: (t.priority_value is None, -(t.priority_value if t.priority_value is not None else 0))
    )
    task_pos: dict[str, tuple] = {}
    y = MARGIN
    for t in sorted_tasks:
        task_pos[t.name] = (MARGIN, y, TASK_W, TASK_H)
        y += TASK_H + V_GAP
    tasks_bottom = y

    obj_pos: dict[str, tuple] = {}
    y = MARGIN
    ox = MARGIN + TASK_W + COL_GAP
    for o in objects:
        obj_pos[o.var_name] = (ox, y, OBJ_W, OBJ_H)
        y += OBJ_H + V_GAP
    objs_bottom = y

    total_h = max(tasks_bottom, objs_bottom) + MARGIN
    total_w = ox + OBJ_W + MARGIN

    parts = [
        f'<svg viewBox="0 0 {total_w} {total_h}" width="100%" '
        f'style="max-width:{total_w}px;background:#111827;border-radius:8px" '
        f'xmlns="http://www.w3.org/2000/svg">',
        '<defs>'
        '<marker id="rtos-wait" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" '
        'markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#f59e0b"/></marker>'
        '<marker id="rtos-signal" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" '
        'markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#22c55e"/></marker>'
        '<marker id="rtos-other" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" '
        'markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#64748b"/></marker>'
        '</defs>',
    ]

    seen = set()
    for u in usages:
        if u.task_name not in task_pos or u.object_var not in obj_pos:
            continue
        key = (u.task_name, u.object_var, u.access_kind)
        if key in seen:
            continue
        seen.add(key)
        tx, ty, tw, th = task_pos[u.task_name]
        ox_, oy, ow, oh = obj_pos[u.object_var]
        x1, y1 = tx + tw, ty + th / 2
        x2, y2 = ox_, oy + oh / 2
        colour = {"wait": "#f59e0b", "signal": "#22c55e"}.get(u.access_kind, "#64748b")
        marker = {"wait": "rtos-wait", "signal": "rtos-signal"}.get(u.access_kind, "rtos-other")
        mx, my = (x1 + x2) / 2, (y1 + y2) / 2
        parts.append(
            f'<path d="M{x1:.0f},{y1:.0f} Q{mx:.0f},{my:.0f} {x2:.0f},{y2:.0f}" '
            f'fill="none" stroke="{colour}" stroke-width="1.3" stroke-opacity="0.75" '
            f'marker-end="url(#{marker})"/>'
        )

    for t in sorted_tasks:
        x, y, w, h = task_pos[t.name]
        label = t.name if len(t.name) <= 22 else t.name[:20] + "…"
        prio = t.priority_value if t.priority_value is not None else (t.priority_expr or "?")
        parts.append(
            f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="6" '
            f'fill="#1e3a8a33" stroke="#3b82f6" stroke-width="1.5"/>'
        )
        parts.append(
            f'<text x="{x + w / 2:.0f}" y="{y + h / 2 - 4:.0f}" fill="#e5e7eb" font-size="12" '
            f'text-anchor="middle" font-family="sans-serif">{_xml_escape(label)}</text>'
        )
        parts.append(
            f'<text x="{x + w / 2:.0f}" y="{y + h / 2 + 12:.0f}" fill="#9ca3af" font-size="10" '
            f'text-anchor="middle" font-family="sans-serif">priority {_xml_escape(str(prio))}</text>'
        )

    for o in objects:
        x, y, w, h = obj_pos[o.var_name]
        colour = _RTOS_KIND_COLOUR.get(o.kind, "#64748b")
        label = o.var_name if len(o.var_name) <= 18 else o.var_name[:16] + "…"
        parts.append(
            f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="6" '
            f'fill="{colour}22" stroke="{colour}" stroke-width="1.5"/>'
        )
        parts.append(
            f'<text x="{x + w / 2:.0f}" y="{y + h / 2 - 3:.0f}" fill="#e5e7eb" font-size="11" '
            f'text-anchor="middle" font-family="sans-serif">{_xml_escape(label)}</text>'
        )
        parts.append(
            f'<text x="{x + w / 2:.0f}" y="{y + h / 2 + 11:.0f}" fill="#9ca3af" font-size="9" '
            f'text-anchor="middle" font-family="sans-serif">{o.kind}</text>'
        )

    parts.append('</svg>')
    return "".join(parts)


def generate_state_machine_svg_inline(sm: StateMachine) -> str:
    """
    Return raw <svg>...</svg> markup for one state machine: states arranged in a
    circle (classic state-diagram layout), directed edges for transitions, self-loops
    drawn as a small loop above the node.
    """
    import math

    states = sm.states
    n = len(states)
    if n == 0:
        return ('<svg width="320" height="60"><text x="10" y="35" fill="#6b7280" '
                'font-size="12">No resolvable states.</text></svg>')

    NODE_R = 34
    R = max(110, 34 * n / 2)
    cx = cy = R + NODE_R + 20
    positions = {}
    for i, s in enumerate(states):
        angle = 2 * math.pi * i / n - math.pi / 2
        positions[s] = (cx + R * math.cos(angle), cy + R * math.sin(angle))

    total = int(2 * (R + NODE_R + 20))
    parts = [
        f'<svg viewBox="0 0 {total} {total}" width="100%" '
        f'style="max-width:{min(total, 520)}px;background:#111827;border-radius:8px" '
        f'xmlns="http://www.w3.org/2000/svg">',
        '<defs><marker id="sm-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" '
        'markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#64748b"/></marker></defs>',
    ]

    for frm, to in sm.transitions:
        if frm not in positions or to not in positions:
            continue
        x1, y1 = positions[frm]
        if frm == to:
            parts.append(
                f'<circle cx="{x1:.0f}" cy="{y1 - NODE_R - 16:.0f}" r="13" fill="none" '
                f'stroke="#64748b" stroke-width="1.3" marker-end="url(#sm-arrow)"/>'
            )
            continue
        x2, y2 = positions[to]
        dx, dy = x2 - x1, y2 - y1
        dist = max(1.0, (dx ** 2 + dy ** 2) ** 0.5)
        ux, uy = dx / dist, dy / dist
        sx, sy = x1 + ux * NODE_R, y1 + uy * NODE_R
        ex, ey = x2 - ux * NODE_R, y2 - uy * NODE_R
        mx, my = (sx + ex) / 2 - uy * 20, (sy + ey) / 2 + ux * 20
        parts.append(
            f'<path d="M{sx:.0f},{sy:.0f} Q{mx:.0f},{my:.0f} {ex:.0f},{ey:.0f}" '
            f'fill="none" stroke="#64748b" stroke-width="1.3" stroke-opacity="0.75" '
            f'marker-end="url(#sm-arrow)"/>'
        )

    for s in states:
        x, y = positions[s]
        label = s if len(s) <= 14 else s[:12] + "…"
        parts.append(f'<circle cx="{x:.0f}" cy="{y:.0f}" r="{NODE_R}" fill="#1f2937" stroke="#3b82f6" stroke-width="1.5"/>')
        parts.append(
            f'<text x="{x:.0f}" y="{y + 4:.0f}" fill="#e5e7eb" font-size="11" '
            f'text-anchor="middle" font-family="sans-serif">{_xml_escape(label)}</text>'
        )

    parts.append('</svg>')
    return "".join(parts)
