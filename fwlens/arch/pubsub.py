"""
Publish and subscribe mapping: which code publishes an event, which function is registered to receive it,
and through which registration function (the broker).

A call is a registration when its name has a word like subscribe, register or attach and one argument is a
function defined in the project (the callback); the event is the first other argument. A call is a
publication when its name has a word like publish, post or notify; the event is its first argument.
`architecture.register_calls` and `architecture.publish_calls` give exact function names and argument
positions (0 is the first argument) for broker functions whose names say nothing.
"""

from __future__ import annotations

import re
from collections import defaultdict

from fwlens.arch.edges import Units, line_of, norm, read_text
from fwlens.arch.model import Event
from fwlens.config import ConfigError
from fwlens.crypto.keywords import words_of
from fwlens.model.project import ProjectModel

REGISTER_WORDS = {"subscribe", "register", "attach", "listen", "listener", "install", "connect", "on"}
PUBLISH_WORDS = {"publish", "post", "emit", "notify", "raise", "fire", "broadcast", "signal"}
_CALL = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
_NOT_CALLS = {"if", "while", "for", "switch", "return", "sizeof", "defined", "do", "else", "case"}


def validate(register, publish) -> None:
    for key, items, needs in (("register_calls", register, ("function", "id_arg", "callback_arg")),
                              ("publish_calls", publish, ("function", "id_arg"))):
        for i, item in enumerate(items or []):
            if not isinstance(item, dict) or set(item) != set(needs) or not isinstance(item["function"], str) or any(
                    isinstance(item[k], bool) or not isinstance(item[k], int) or item[k] < 0 for k in needs[1:]):
                raise ConfigError(f"architecture.{key}[{i}] needs exactly {list(needs)} (argument positions start at 0)")


def call_args(text: str, open_at: int) -> list[str]:
    """The arguments of the call whose `(` is at `open_at`, split at top-level commas."""
    depth, start = 0, open_at + 1
    args: list[str] = []
    for i in range(open_at, len(text)):
        c = text[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                tail = text[start:i].strip()
                if tail or args:
                    args.append(tail)
                return args
        elif c == "," and depth == 1:
            args.append(text[start:i].strip())
            start = i + 1
    return []


def _bare(arg: str) -> str:
    return re.sub(r"\(\s*[\w\s\*]+\)\s*", "", arg).lstrip("&* ").strip()


def map_events(model: ProjectModel, units: Units, register_calls: list | None = None,
               publish_calls: list | None = None) -> list[Event]:
    reg_cfg = {c["function"]: c for c in register_calls or []}
    pub_cfg = {c["function"]: c for c in publish_calls or []}
    defined: dict = {}
    functions: dict = defaultdict(list)
    for m in model.modules:
        for f in m.functions:
            defined.setdefault(f.name, norm(m.path))
            functions[norm(f.file)].append(f)

    def owner_of(file: str, line: int):
        inside = [f for f in functions.get(file, []) if f.line <= line]
        return max(inside, key=lambda f: f.line) if inside else None

    events: dict = {}

    def event(name: str) -> Event:
        return events.setdefault(name, Event(name))

    for m in model.modules:
        file = norm(m.path)
        text = read_text(m.path)
        for hit in _CALL.finditer(text):
            name = hit.group(1)
            if name in _NOT_CALLS:
                continue
            words = set(words_of(name))
            is_reg = name in reg_cfg or (name not in pub_cfg and words & REGISTER_WORDS and not words & PUBLISH_WORDS)
            is_pub = name in pub_cfg or (name not in reg_cfg and words & PUBLISH_WORDS)
            if not (is_reg or is_pub):
                continue
            line = line_of(text, hit.start())
            owner = owner_of(file, line)
            if owner is None or owner.name == name:           # a definition or a recursive call, not a call site
                continue
            args = call_args(text, hit.end() - 1)
            where = {"function": owner.name, "component": units.owner(m.path) or "", "file": file, "line": line}
            if is_reg and name in reg_cfg:
                c = reg_cfg[name]
                ids, cb = c["id_arg"], c["callback_arg"]
                if max(ids, cb) >= len(args):
                    continue
                callback, ident = _bare(args[cb]), args[ids].strip()
            elif is_reg:
                callbacks = [i for i, a in enumerate(args) if _bare(a) in defined]
                if not callbacks:
                    continue
                cb = callbacks[0]
                others = [a for i, a in enumerate(args) if i != cb]
                if not others:
                    continue
                callback, ident = _bare(args[cb]), others[0].strip()
            else:
                ids = pub_cfg[name]["id_arg"] if name in pub_cfg else 0
                if ids >= len(args):
                    continue
                event(args[ids].strip()).publishers.append({**where, "broker": name})
                continue
            event(ident).subscribers.append({**where, "broker": name, "callback": callback,
                                             "callback_component": units.owner(defined[callback]) or ""})
    out = [e for e in events.values() if e.publishers or e.subscribers]
    for e in out:
        for lst in (e.publishers, e.subscribers):
            lst.sort(key=lambda r: (r["file"], r["line"], r["function"]))
    return sorted(out, key=lambda e: e.event)


def event_flows(events: list[Event], component_name: dict) -> list:
    """(publisher component, subscriber component, event, broker) for every event that has both sides."""
    flows = set()
    for e in events:
        for p in e.publishers:
            for s in e.subscribers:
                a = component_name.get(p["component"])
                b = component_name.get(s["callback_component"])
                if a and b and a != b:
                    flows.add((a, b, e.event, s["broker"]))
    return sorted(flows)
