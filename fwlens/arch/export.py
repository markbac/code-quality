"""The architecture model as docs-as-code: PlantUML (component diagram) and Structurizr DSL (C4)."""

from __future__ import annotations

import re

from fwlens.arch.layers import component_graph
from fwlens.arch.model import ArchModel
from fwlens.arch.pubsub import event_flows


def _id(name: str) -> str:
    return "c_" + re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_")


def _q(text: str) -> str:
    return '"' + str(text).replace('"', "'") + '"'


def _label(kinds) -> str:
    return ", ".join(sorted(kinds))


def _flows(arch: ArchModel) -> list:
    """Event flows between components, by component name."""
    owner = {u: c.name for c in arch.components for u in c.units}
    return event_flows(arch.events, owner)


def plantuml(arch: ArchModel) -> str:
    """Components in a package per inferred level (top first), interfaces for those that have one,
    dependencies labelled by kind, and back-edges inside cycles in red."""
    layering = arch.layering
    graph = component_graph(arch.components, arch.edges)
    domains = {s.name: s for s in arch.subsystems}
    has_api = {c.name for c in arch.components if any(
        i.unit in c.units and (i.tables or i.abstract_headers) for i in arch.interfaces)}
    lines = ["@startuml", "skinparam componentStyle rectangle", "skinparam roundCorner 8", ""]
    for layer in layering.layers:
        cyc = " (cycle)" if layer["cycle"] else ""
        lines.append(f"package {_q(f'Level {layer['level']}{cyc}')} {{")
        for name in layer["components"]:
            sub = domains.get(name)
            note = f"\\n<<{sub.domain}>>" if sub and sub.domain != "unclassified" else ""
            lines.append(f"  [{name}{note}] as {_id(name)}")
            if name in has_api:
                lines.append(f"  interface {_q(name + ' API')} as {_id(name)}_api")
        lines.append("}")
    lines.append("")
    for name in sorted(has_api):
        lines.append(f"{_id(name)} -up- {_id(name)}_api")
    back = {(e["source"], e["target"]) for e in layering.back_edges}
    for a, b, data in sorted(graph.edges(data=True)):
        if (a, b) in back:
            lines.append(f"{_id(a)} .[#red,thickness=2].> {_id(b)} : <<violation: cycle>>")
        else:
            lines.append(f"{_id(a)} ..> {_id(b)} : {_label(data['kinds'])}")
    for a, b, ev, _broker in _flows(arch):
        lines.append(f"{_id(a)} .[#blue].> {_id(b)} : <<event {ev}>>")
    for d in layering.disagreements:
        lines.append(f"{_id(d['source'])} .[#orange,thickness=2].> {_id(d['target'])} : <<configured layers disagree>>")
    lines.append("@enduml")
    return "\n".join(lines) + "\n"


def structurizr(arch: ArchModel, title: str = "Firmware") -> str:
    """Subsystems (by domain) as containers and components as components."""
    graph = component_graph(arch.components, arch.edges)
    by_domain: dict = {}
    for s in arch.subsystems:
        by_domain.setdefault((s.domain, s.domain_name), []).append(s)
    lines = [f"workspace {_q(title + ' model')} {_q('Recovered by FWLens')} {{", "    model {",
             f"        system = softwareSystem {_q(title)} {{"]
    for (domain, domain_name), subs in sorted(by_domain.items()):
        lines.append(f"            {_id(domain)} = container {_q(domain_name)} {{")
        for s in sorted(subs, key=lambda s: s.name):
            description = f"{s.confidence} confidence" + (f": {s.evidence[0]}" if s.evidence else "")
            lines.append(f"                {_id(s.name)} = component {_q(s.name)} {_q(description)} {_q('C')}")
        lines.append("            }")
    lines.append("        }")
    for a, b, data in sorted(graph.edges(data=True)):
        lines.append(f"        {_id(a)} -> {_id(b)} {_q(_label(data['kinds']))}")
    for a, b, ev, broker in _flows(arch):
        lines.append(f"        {_id(a)} -> {_id(b)} {_q('publishes ' + ev)} {_q('via ' + broker)}")
    lines += ["    }", "    views {", "        container system \"Containers\" {", "            include *",
              "            autoLayout lr", "        }"]
    for (domain, domain_name), _subs in sorted(by_domain.items()):
        lines += [f"        component {_id(domain)} {_q(domain_name)} {{", "            include *",
                  "            autoLayout lr", "        }"]
    lines += ["    }", "}"]
    return "\n".join(lines) + "\n"


def write_exports(arch: ArchModel, directory, title: str = "Firmware") -> list:
    directory.mkdir(parents=True, exist_ok=True)
    out = []
    for name, text in (("architecture.puml", plantuml(arch)), ("architecture.dsl", structurizr(arch, title))):
        path = directory / name
        path.write_text(text, encoding="utf-8")
        out.append(path)
    return out
