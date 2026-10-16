"""
Cross-cutting concerns (clock and time, firmware update, power, watchdog, storage, comms, security,
logging) from the catalogue in concerns.yaml, plus the checks that are specific to time handling
and to firmware update.
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path

import yaml

from fwlens.crypto.keywords import words_of

CATALOGUE = Path(__file__).with_name("concerns.yaml")
EVIDENCE_KEPT = 4
PATH_DEPTH = 8                       # longest call chain followed from an update entry to a flash write

UPDATE_FLOW = ["image_receive", "flash_erase", "flash_write", "verify_integrity", "verify_signature",
               "version_check", "activate", "confirm_rollback", "reset"]
_TIME_WORDS = {"tick", "ticks", "time", "ms", "now", "deadline", "timeout", "timestamp", "uptime", "expire", "expiry",
               "elapsed", "start", "last", "next", "due", "millis"}
_TIME_CALLS = {"HAL_GetTick", "xTaskGetTickCount", "xTaskGetTickCountFromISR", "OS_GetTime", "OS_GetTime32",
               "osKernelGetTickCount", "k_uptime_get_32", "millis", "micros", "tx_time_get"}
_OPERAND = r"[A-Za-z_](?:[\w.]|->)*(?:\s*\(\s*\))?"
_COMPARE = re.compile(rf"\b({_OPERAND})\s*(>=|<=|>|<)\s*({_OPERAND})(?=\s*[;)&|?,])")


@dataclass
class Role:
    calls: list = field(default_factory=list)
    names: list = field(default_factory=list)
    words: list = field(default_factory=list)       # each a set of words that must all be present
    text: list = field(default_factory=list)        # compiled regular expressions


@dataclass
class Concern:
    id: str
    name: str
    roles: dict


def load_catalogue(path: Path = CATALOGUE) -> list[Concern]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    out = []
    for c in raw.get("concerns", []):
        roles = {}
        for rid, r in (c.get("roles") or {}).items():
            roles[rid] = Role(calls=list(r.get("calls", [])), names=list(r.get("names", [])),
                              words=[set(str(w).lower().split()) for w in r.get("words", [])],
                              text=[re.compile(t) for t in r.get("text", [])])
        out.append(Concern(c["id"], c.get("name", c["id"]), roles))
    return out


def _glob(name: str, patterns: list) -> str:
    for p in patterns:
        if ("*" in p and fnmatchcase(name, p)) or name == p:
            return p
    return ""


def match_role(role: Role, name: str, callees: list, body: str) -> list[str]:
    """Why a function takes a role, as short evidence strings (empty when it does not)."""
    evidence = []
    if _glob(name, role.names):
        evidence.append(f"name {name}")
    words = set(words_of(name))
    for ws in role.words:
        if ws <= words:
            evidence.append(f"name has '{' '.join(sorted(ws))}'")
            break
    for callee in callees:
        if _glob(callee, role.calls):
            evidence.append(f"calls {callee}")
            if len(evidence) >= EVIDENCE_KEPT:
                break
    for rx in role.text:
        m = rx.search(body)
        if m:
            evidence.append(f"uses {m.group(0).strip()}")
    return evidence


def analyse(fns: list, catalogue: list[Concern], reached_from: dict) -> dict:
    """Every concern: the functions in each role with their evidence, the entry points that reach
    them, and the roles nothing matched. `fns` are brief Fn records; `reached_from` maps a function
    name to the entry points whose call trees include it."""
    out = {}
    for c in catalogue:
        roles: dict = {}
        for rid, role in c.roles.items():
            hits = []
            for f in fns:
                ev = match_role(role, f.name, f.callees, f.body)
                if ev:
                    hits.append({"function": f.name, "file": f.rel, "line": f.line, "evidence": ev[:EVIDENCE_KEPT],
                                 "in_isr": f.is_isr, "reached_from": reached_from.get(f.name, [])[:10]})
            roles[rid] = hits
        names = sorted({h["function"] for hits in roles.values() for h in hits})
        entries = sorted({e for n in names for e in reached_from.get(n, [])})
        files = sorted({h["file"] for hits in roles.values() for h in hits})
        out[c.id] = {"name": c.name, "functions": names, "files": files, "entry_points": entries,
                     "roles": roles, "not_found": [r for r, hits in roles.items() if not hits]}
    return out


def time_findings(fns: list, concerns: dict, globals_: list, isr_names: set, reached_from: dict) -> dict:
    """Risks in time handling: tick comparisons that break when the counter wraps, blocking delays
    reached from an interrupt, and tick counters shared with an ISR without volatile."""
    wrap = []
    for f in fns:
        for m in _COMPARE.finditer(f.body):
            a, op, b = m.group(1), m.group(2), m.group(3)
            before = f.body[:m.start()].rstrip()
            if before.endswith(("-", "+", "*", "/", "%", ">", "<", "&", "|", "^", "]", ".")):
                continue                            # part of a longer expression, such as now - start > timeout
            if not (_timeish(a) and _timeish(b)):
                continue
            if _is_constant(a) or _is_constant(b):
                continue
            line = f.line_at(m.start())
            wrap.append({"function": f.name, "file": f.rel, "line": line,
                         "expression": f"{a} {op} {b}",
                         "note": "compares two time values directly; if they are tick counts this breaks when the "
                                 "counter wraps (the wrap-safe form compares the difference, (int32_t)(a - b) > 0)"})
    delay_hits = concerns.get("time", {}).get("roles", {}).get("delay", [])
    delays_in_isr = [{"function": h["function"], "file": h["file"], "line": h["line"],
                      "isrs": [e for e in reached_from.get(h["function"], []) if e in isr_names]}
                     for h in delay_hits if h["in_isr"] or any(e in isr_names for e in reached_from.get(h["function"], []))]
    counters = []
    for g in globals_:
        words = set(words_of(g.name))
        if words & {"tick", "ticks", "uptime", "millis", "ms", "time", "timestamp", "seconds", "epoch"}:
            counters.append({"name": g.name, "file": g.file, "volatile": g.is_volatile, "writers": g.writers,
                             "readers": g.readers, "isr_writers": g.isr_writers, "isr_readers": g.isr_readers,
                             "risk": "shared with an ISR and not volatile" if g.volatile_risk else ""})
    return {"wrap_unsafe_comparisons": wrap, "blocking_delays_reached_from_isr": delays_in_isr,
            "time_counters": counters}


def _timeish(expr: str) -> bool:
    name = re.sub(r"\s*\(\s*\)$", "", expr)
    if name in _TIME_CALLS:
        return True
    last = re.split(r"\.|->", name)[-1]
    return bool(set(words_of(last)) & _TIME_WORDS)


def _is_constant(expr: str) -> bool:
    last = re.split(r"\.|->", expr)[-1]
    return last.isupper() and "(" not in expr


def update_flow(concerns: dict, callees_of: dict) -> dict:
    """The firmware update path: each step with the functions found for it, the call chains from
    the update code to the flash writes, and the steps that are missing."""
    roles = concerns.get("update", {}).get("roles", {})
    steps = [{"step": s, "functions": [{"function": h["function"], "file": h["file"], "line": h["line"],
                                        "evidence": h["evidence"]} for h in roles.get(s, [])]}
             for s in UPDATE_FLOW]
    found = {s["step"] for s in steps if s["functions"]}
    receivers = [h["function"] for h in roles.get("image_receive", [])]
    targets = {h["function"] for h in roles.get("flash_write", []) + roles.get("flash_erase", [])}
    checks = {h["function"]: s for s in ("verify_integrity", "verify_signature") for h in roles.get(s, [])}
    chains = []
    for start in receivers:
        path = _path(start, targets - {start}, callees_of)
        if path:
            on_path = [checks[p] for p in path if p in checks]
            chains.append({"from": start, "to": path[-1], "path": path, "checks_on_path": sorted(set(on_path))})
    gaps = []
    if found & {"image_receive", "flash_write", "activate"} or roles.get("bootloader"):
        if "verify_signature" not in found:
            gaps.append("no signature check found in the update code")
        if "verify_integrity" not in found:
            gaps.append("no CRC or hash check found in the update code")
        if "confirm_rollback" not in found:
            gaps.append("no confirm or rollback step found")
        if "version_check" not in found:
            gaps.append("no version or anti-rollback check found")
        if chains and not any(c["checks_on_path"] for c in chains):
            gaps.append("no CRC, hash or signature check found on the call path from receiving an image to writing flash")
    else:
        gaps.append("no firmware update code detected")
    bootloader = [{"function": h["function"], "file": h["file"], "line": h["line"], "evidence": h["evidence"]}
                  for h in roles.get("bootloader", [])]
    return {"bootloader": bootloader, "steps": steps, "receive_to_flash_paths": chains, "gaps": gaps}


def _path(start: str, targets: set, callees_of: dict) -> list:
    """Shortest call chain from `start` to any of `targets`, or an empty list."""
    prev: dict[str, str | None] = {start: None}
    queue = deque([(start, 0)])
    while queue:
        node, depth = queue.popleft()
        if node in targets:
            path: list[str] = []
            step: str | None = node
            while step is not None:
                path.append(step)
                step = prev[step]
            return path[::-1]
        if depth >= PATH_DEPTH:
            continue
        for nxt in sorted(callees_of.get(node, ())):
            if nxt not in prev:
                prev[nxt] = node
                queue.append((nxt, depth + 1))
    return []
