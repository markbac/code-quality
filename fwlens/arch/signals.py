"""
Signals: small named checks on the parsed project that pattern rules combine (fwlens/arch/patterns.yaml).

A signal takes a `Context` (the whole system, or one subsystem's units) and returns `(fired, detail)`.
The detail is shown as evidence, so it says what was found, not just that something was.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any, Callable

import networkx as nx

from fwlens.arch.edges import norm, read_text, struct_bodies
from fwlens.arch.layers import component_graph
from fwlens.crypto.keywords import words_of

SIGNALS: dict[str, Callable] = {}
_LOOP = re.compile(r"\bwhile\s*\(\s*(?:1|true|TRUE)\s*\)|\bfor\s*\(\s*;\s*;\s*\)")
_FUNC_PTR_TYPE = re.compile(r"\(\s*\*\s*[A-Za-z_]\w*\s*\)\s*\(")
_REGISTER_WORDS = {"subscribe", "register", "attach", "listen", "listener", "install", "connect"}
_PUBLISH_WORDS = {"publish", "post", "emit", "notify", "dispatch", "raise", "fire", "broadcast"}
_STATE_TABLE_WORDS = {"state", "states", "event", "events", "transition", "transitions", "fsm"}


def signal(fn: Callable) -> Callable:
    SIGNALS[fn.__name__] = fn
    return fn


@dataclass
class Context:
    """What a signal can look at. `units` limits it to one subsystem, or all units for the system."""
    model: Any
    arch: Any
    config: Any
    units: set = field(default_factory=set)
    component: Any = None
    _text: dict = field(default_factory=dict)

    def raw(self, path) -> str:
        key = "raw:" + norm(path)
        if key not in self._text:
            self._text[key] = read_text(path, keep_strings=True)
        return self._text[key]

    def text(self, path) -> str:
        key = norm(path)
        if key not in self._text:
            self._text[key] = read_text(path)
        return self._text[key]

    @property
    def modules(self) -> list:
        return [m for m in self.model.modules if norm(m.path) in self.units]

    @property
    def functions(self) -> list:
        return [f for m in self.modules for f in m.functions]

    def body(self, function) -> str:
        lines = self.text(function.file).splitlines()
        return "\n".join(lines[max(function.line - 1, 0):function.line - 1 + max(function.loc, 1) + 2])

    def callee_words(self) -> dict:
        found: dict = defaultdict(set)
        for f in self.functions:
            for callee in f.callees:
                for w in words_of(callee):
                    found[w].add(callee)
        return found

    def ops_types(self) -> dict:
        """Struct types made of function pointers -> the names of the objects of that type."""
        types: set = set()
        for h in self.arch.ops_headers:
            text = self.text(h)
            for start, body in struct_bodies(text):
                if _FUNC_PTR_TYPE.search(body):
                    tag = re.search(r"\b(?:struct|union)\s+([A-Za-z_]\w*)\s*$", text[max(start - 80, 0):start - 1].rstrip())
                    after = re.match(r"\s*([A-Za-z_]\w*)\s*;", text[start + len(body) + 1:])
                    types.update(m.group(1) for m in (tag, after) if m)
        found: dict = {}
        for t in sorted(types):
            instances = []
            for m in self.model.modules:
                for hit in re.finditer(rf"\b{re.escape(t)}\s+([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*=", self.text(m.path)):
                    instances.append(hit.group(1))
            found[t] = sorted(set(instances))
        return found


def _fired(ok: bool, detail: str = "") -> tuple:
    return (bool(ok), detail)


# --- layering ---------------------------------------------------------------------------------

@signal
def layers_3plus(ctx):
    n = len(ctx.arch.layering.layers)
    return _fired(n >= 3, f"{n} inferred layers")


@signal
def acyclic(ctx):
    cycles = ctx.arch.layering.cycles
    return _fired(not cycles and ctx.arch.components, "no dependency cycles between components" if not cycles
                  else f"{len(cycles)} cycle(s)")


@signal
def next_layer_share_high(ctx):
    share = ctx.arch.layering.next_layer_share
    return _fired(share >= 0.6 and len(ctx.arch.layering.layers) >= 2, f"{share:.0%} of downward weight goes to the next layer")


@signal
def configured_layers(ctx):
    return _fired(bool(ctx.config.layers), f"{len(ctx.config.layers)} configured layers")


# --- interfaces and registries ----------------------------------------------------------------

@signal
def ops_structs(ctx):
    types = ctx.ops_types()
    return _fired(types, "function-pointer structs: " + ", ".join(sorted(types)[:4]))


@signal
def multiple_implementations(ctx):
    many = {t: i for t, i in ctx.ops_types().items() if len(i) >= 2}
    return _fired(many, "; ".join(f"{t} implemented by {', '.join(i[:3])}" for t, i in sorted(many.items())[:3]))


@signal
def dispatch_tables(ctx):
    names = sorted(t for i in ctx.arch.interfaces if i.unit in ctx.units for t in i.tables)
    return _fired(names, "tables: " + ", ".join(names[:4]))


@signal
def hal_lowest(ctx):
    levels = ctx.arch.layering.level_of
    hal = [s.name for s in ctx.arch.subsystems if s.domain == "hal"]
    low = [n for n in hal if levels.get(n, 99) <= 1]
    return _fired(hal and len(low) == len(hal), "hardware abstraction at the bottom: " + ", ".join(hal[:3]))


@signal
def registration_calls(ctx):
    words = ctx.callee_words()
    names = sorted({c for w in _REGISTER_WORDS for c in words.get(w, ())})
    return _fired(names, "registration calls: " + ", ".join(names[:4]))


@signal
def publish_calls(ctx):
    words = ctx.callee_words()
    names = sorted({c for w in _PUBLISH_WORDS for c in words.get(w, ())})
    return _fired(names, "publish calls: " + ", ".join(names[:4]))


@signal
def events_mapped(ctx):
    both = [e.event for e in ctx.arch.events if e.publishers and e.subscribers]
    return _fired(both, f"{len(both)} event(s) with a publisher and a subscriber: {', '.join(both[:3])}")


@signal
def event_ids(ctx):
    seen: set = set()
    for m in ctx.modules:
        seen |= set(re.findall(r"\b(?:EVENT|EVT)_[A-Z0-9_]+\b", ctx.text(m.path)))
    return _fired(len(seen) >= 3, f"{len(seen)} event identifiers ({', '.join(sorted(seen)[:3])})")


# --- control structure ------------------------------------------------------------------------

@signal
def main_loop(ctx):
    for name in dict.fromkeys([*ctx.config.entry_points, "main"]):
        for f in ctx.functions:
            if f.name == name and _LOOP.search(ctx.body(f)):
                return (True, f"{name} loops forever")
    return (False, "")


@signal
def loop_calls_several(ctx):
    for name in dict.fromkeys([*ctx.config.entry_points, "main"]):
        for f in ctx.functions:
            if f.name == name and len(set(f.callees)) >= 3 and _LOOP.search(ctx.body(f)):
                return (True, f"{name} calls {len(set(f.callees))} functions in its loop")
    return (False, "")


@signal
def isrs_light(ctx):
    isrs = [f for f in ctx.functions if f.is_isr]
    light = [f for f in isrs if f.loc <= 25 and len(set(f.callees)) <= 3]
    return _fired(isrs and len(light) == len(isrs), f"{len(isrs)} interrupt handlers, all short")


@signal
def no_rtos(ctx):
    return _fired(ctx.model.rtos_kind == "none" and not ctx.model.rtos_tasks, "no RTOS tasks found")


@signal
def tasks_2plus(ctx):
    tasks = ctx.model.rtos_tasks
    return _fired(len(tasks) >= 2, f"{len(tasks)} RTOS tasks")


@signal
def sync_objects(ctx):
    n = len(ctx.model.rtos_sync_objects)
    return _fired(n >= 1, f"{n} semaphores, mutexes, queues or mailboxes")


@signal
def queue_between_tasks(ctx):
    kinds = {o.var_name: o.kind for o in ctx.model.rtos_sync_objects}
    users: dict = defaultdict(set)
    for u in ctx.model.rtos_object_usages:
        if kinds.get(u.object_var) in ("queue", "mailbox"):
            users[u.object_var].add(u.task_name)
    shared = sorted(o for o, t in users.items() if len(t) >= 2)
    return _fired(shared, "queues or mailboxes shared by tasks: " + ", ".join(shared[:3]))


# --- state machines and pipelines -------------------------------------------------------------

@signal
def state_machines_present(ctx):
    n = len(ctx.model.state_machines)
    return _fired(n >= 1, f"{n} state machine(s)")


@signal
def several_state_machines(ctx):
    n = len(ctx.model.state_machines)
    return _fired(n >= 3, f"{n} state machines")


@signal
def state_tables(ctx):
    names = sorted(t for i in ctx.arch.interfaces for t in i.tables if _STATE_TABLE_WORDS & set(words_of(t)))
    return _fired(names, "tables indexed by state or event: " + ", ".join(names[:3]))


@signal
def linear_chain(ctx):
    g = component_graph(ctx.arch.components, ctx.arch.edges)
    dag = nx.DiGraph((a, b) for a, b in g.edges() if ctx.arch.layering.level_of[a] > ctx.arch.layering.level_of[b])
    if dag.number_of_nodes() < 4:
        return (False, "")
    path = nx.dag_longest_path(dag)
    thin = all(dag.out_degree(n) <= 2 for n in path)
    ok = len(path) >= 3 and len(path) >= 0.6 * g.number_of_nodes() and thin
    return _fired(ok, "chain: " + " -> ".join(path[:6]))


# --- anti-patterns ----------------------------------------------------------------------------

@signal
def many_cycles(ctx):
    n = len(ctx.arch.components)
    cyclic = {c for cyc in ctx.arch.layering.cycles for c in cyc}
    return _fired(n >= 4 and len(cyclic) / n >= 0.4, f"{len(cyclic)} of {n} components are in cycles")


@signal
def no_layering(ctx):
    n = len(ctx.arch.components)
    flat = len(ctx.arch.layering.layers) < 3 or ctx.arch.layering.next_layer_share < 0.3
    return _fired(n >= 4 and flat, f"{len(ctx.arch.layering.layers)} layers for {n} components")


@signal
def dense_dependencies(ctx):
    g = component_graph(ctx.arch.components, ctx.arch.edges)
    n = g.number_of_nodes()
    density = g.number_of_edges() / (n * (n - 1)) if n > 1 else 0
    return _fired(n >= 4 and density > 0.4, f"{density:.0%} of possible dependencies between components exist")


@signal
def dominant_component(ctx):
    comps = ctx.arch.components
    total = sum(len(c.units) for c in comps)
    if len(comps) < 3 or not total:
        return (False, "")
    big = max(comps, key=lambda c: (len(c.units), c.name))
    return _fired(len(big.units) / total >= 0.4, f"{big.name} holds {len(big.units)} of {total} units")


@signal
def hub_component(ctx):
    comps = ctx.arch.components
    if len(comps) < 4:
        return (False, "")
    g = component_graph(comps, ctx.arch.edges)
    hub = max(g.nodes, key=lambda n: (len(set(g.pred[n]) | set(g.succ[n])), n))
    reach = len(set(g.pred[hub]) | set(g.succ[hub]))
    return _fired(reach / (len(comps) - 1) >= 0.6, f"{hub} is linked to {reach} of {len(comps) - 1} other components")


# --- subsystem signals: user interface -------------------------------------------------------

_WIDGET_PREFIX = ("lv_", "WM_", "GUI_", "BUTTON_", "TEXT_", "LISTBOX_", "FRAMEWIN_", "u8g2_", "ssd1306_")
_SCREEN_WORDS = {"screen", "screens", "page", "pages", "view", "views", "menu", "menus", "state", "states"}
_UI_WORDS = {"ui", "screen", "menu", "display", "lcd", "gui", "page", "view"}
_INPUT_WORDS = {"key", "keys", "button", "buttons", "touch", "keypad", "joystick", "encoder"}
_QUEUE_WORDS = {"event", "events", "queue", "pop", "get", "wait", "poll", "pend", "read", "scan"}
_DISPLAY_WORDS = {"flush", "framebuffer", "fb", "blit", "pixel", "pixels", "frame", "refresh"}


def _names(ctx):
    return [f.name for f in ctx.functions]


@signal
def widget_api(ctx):
    calls = sorted({c for f in ctx.functions for c in f.callees if c.startswith(_WIDGET_PREFIX)})
    return _fired(len(calls) >= 3, f"widget library calls: {', '.join(calls[:4])}")


@signal
def screen_table(ctx):
    names = sorted(t for i in ctx.arch.interfaces if i.unit in ctx.units for t in i.tables if _SCREEN_WORDS & set(words_of(t)))
    return _fired(names, "tables of screens or menus: " + ", ".join(names[:3]))


@signal
def menu_table(ctx):
    pattern = re.compile(r'\{\s*"[^"\n]*"\s*,\s*&?[A-Za-z_]\w*\s*[,}]')
    count = sum(len(pattern.findall(ctx.raw(m.path))) for m in ctx.modules)
    return _fired(count >= 3, f"{count} entries pairing a label with a handler")


@signal
def ui_state_machine(ctx):
    machines = [sm for sm in ctx.model.state_machines if norm(sm.file) in ctx.units]
    return _fired(machines, "state machine(s): " + ", ".join(sm.function_name for sm in machines[:3]))


@signal
def input_events(ctx):
    names = sorted(n for n in _names(ctx) if _INPUT_WORDS & set(words_of(n)) and _QUEUE_WORDS & set(words_of(n)))
    return _fired(names, "input event functions: " + ", ".join(names[:3]))


@signal
def queue_in_subsystem(ctx):
    queues = [o.var_name for o in ctx.model.rtos_sync_objects if o.kind in ("queue", "mailbox") and norm(o.file) in ctx.units]
    return _fired(queues, "queues or mailboxes: " + ", ".join(queues[:3]))


@signal
def model_view_split(ctx):
    owned = {f.name for f in ctx.functions}
    read, written = [], []
    for g in ctx.model.globals:
        if norm(g.file) in ctx.units:
            continue
        if owned & set(g.readers):
            read.append(g.name)
        if owned & set(g.writers):
            written.append(g.name)
    return _fired(len(read) >= 2 and not written, f"reads {len(read)} globals owned elsewhere ({', '.join(sorted(read)[:3])}), writes none")


@signal
def display_driver(ctx):
    names = sorted(n for n in _names(ctx) if _DISPLAY_WORDS & set(words_of(n)))
    return _fired(names, "framebuffer and flush functions: " + ", ".join(names[:3]))


@signal
def hal_below(ctx):
    if not ctx.component:
        return (False, "")
    by_name = {s.name: s.domain for s in ctx.arch.subsystems}
    comp_graph = component_graph(ctx.arch.components, ctx.arch.edges)
    below = sorted(n for n in comp_graph.successors(ctx.component.name) if by_name.get(n) == "hal")
    return _fired(below, "depends on the hardware abstraction: " + ", ".join(below[:3]))


# --- subsystem signals: communications --------------------------------------------------------

_PARSER_WORDS = {"parse", "parser", "decode", "deframe", "unpack", "frame", "packet", "decapsulate"}
_COMMAND_WORDS = {"cmd", "command", "commands", "opcode", "request", "handler", "handlers", "dispatch", "service"}
_INTERFACES = {"uart", "usart", "spi", "i2c", "can", "usb", "tcp", "udp", "modbus", "eth", "ethernet", "ble", "lora", "modem", "serial", "rs485", "dlms", "wmbus"}
_RECEIVE = {"rx", "receive", "recv", "received", "read", "incoming"}
_TRANSMIT = {"tx", "send", "write", "transmit", "forward", "relay"}
_BUFFER = {"ring", "fifo", "buf", "buffer", "rx", "tx", "queue"}
_DMA_SWAP = {"half", "cplt", "complete", "ping", "pong", "double", "swap", "toggle"}


@signal
def stack_layers(ctx):
    if len(ctx.units) < 3:
        return (False, "")
    g = nx.DiGraph()
    g.add_nodes_from(ctx.units)
    g.add_edges_from((e.source, e.target) for e in ctx.arch.edges if e.source in ctx.units and e.target in ctx.units
                     and e.kind in ("call", "callback"))
    if not nx.is_directed_acyclic_graph(g):
        return (False, "")
    depth = len(nx.dag_longest_path(g))
    return _fired(depth >= 3, f"{depth} layers of units, calls only go down")


@signal
def parser_functions(ctx):
    names = sorted(n for n in _names(ctx) if _PARSER_WORDS & set(words_of(n)))
    return _fired(names, "parser functions: " + ", ".join(names[:3]))


@signal
def unit_state_machine(ctx):
    machines = [sm for sm in ctx.model.state_machines if norm(sm.file) in ctx.units]
    return _fired(machines, "state machine(s): " + ", ".join(sm.function_name for sm in machines[:3]))


@signal
def command_table(ctx):
    names = sorted(t for i in ctx.arch.interfaces if i.unit in ctx.units for t in i.tables if _COMMAND_WORDS & set(words_of(t)))
    return _fired(names, "command tables: " + ", ".join(names[:3]))


@signal
def isr_ring_buffer(ctx):
    isr_names = {f.name for f in ctx.functions if f.is_isr}
    found = sorted(g.name for g in ctx.model.globals   # an indexed store counts as a read in the parse, so use both
                   if _BUFFER & set(words_of(g.name)) and isr_names & (set(g.writers) | set(g.readers))
                   and (set(g.readers) | set(g.writers)) - isr_names)
    return _fired(found, "buffer filled by an interrupt and read elsewhere: " + ", ".join(found[:3]))


@signal
def dma_double_buffer(ctx):
    names = set()
    for m in ctx.modules:
        for token in set(re.findall(r"[A-Za-z_]\w*", ctx.text(m.path))):
            w = set(words_of(token))
            if "dma" in w and _DMA_SWAP & w:
                names.add(token)
    return _fired(names, "DMA half or complete handling: " + ", ".join(sorted(names)[:3]))


@signal
def tasks_in_subsystem(ctx):
    owned = {f.name for f in ctx.functions}
    tasks = [t.name for t in ctx.model.rtos_tasks if t.entry_function in owned]
    return _fired(len(tasks) >= 2, f"{len(tasks)} tasks: {', '.join(tasks[:3])}")


@signal
def gateway_bridge(ctx):
    for f in ctx.functions:
        w = set(words_of(f.name)) | set(words_of(PurePosixPath(norm(f.file)).stem))
        if not _RECEIVE & w:
            continue
        here = _INTERFACES & w
        for callee in f.callees:
            cw = set(words_of(callee))
            there = _INTERFACES & cw
            if _TRANSMIT & cw and there and here and not (there & here):
                return (True, f"{f.name} forwards from {sorted(here)[0]} to {sorted(there)[0]} via {callee}")
    return (False, "")


def stem(unit: str) -> str:
    return PurePosixPath(unit).stem
