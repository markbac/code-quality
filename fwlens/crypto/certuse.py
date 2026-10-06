"""
Which functions use certificates, in two steps.

Step 1 finds candidates cheaply: functions whose name or parameter list has a certificate word
(cert, x509, ca, pem ...). Step 2 reads each function body for evidence and follows calls between
functions, so a wrapper whose name says nothing is still found when it calls one that does, and a
function with a promising name that never touches certificate data stays at low confidence.

    high    calls a certificate API directly (a catalogue entry, such as mbedtls_x509_crt_verify)
    medium  named like a certificate function and its body handles certificate data, or it calls a
            function that is high or medium (up to two calls away)
    low     named like a certificate function, nothing else seen

The scan is lexical (comments and strings blanked, braces matched), so a function reached through a
pointer or built by a macro is not seen.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_NOT_CALLS = {"if", "while", "for", "switch", "return", "sizeof", "defined", "do", "else", "case", "typeof", "alignof",
              "__attribute__", "_Alignof", "_Static_assert", "static_assert"}
_IDENT = re.compile(r"[A-Za-z_]\w*")
_CALL = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
_DATA_STRING = re.compile(r"BEGIN [A-Z ]*(?:CERTIFICATE|KEY)|\.(?:pem|crt|cer|der)\b|X\.?509", re.IGNORECASE)
_BRACE = re.compile(r"[{}]")
PRIORITY = ("verify-disabled", "verify-relaxed", "verify", "trust-anchor", "own-certificate", "private-key", "parse",
            "hostname", "other")
HOPS = 2
LEVELS = {"high": "calls a certificate API directly",
          "medium": "named like a certificate function and handles certificate data, or calls one that does",
          "low": "named like a certificate function, nothing else seen"}


@dataclass
class Function:
    name: str
    where: str
    line: int
    header: str
    body: str
    strings: str            # the body with string literals kept


@dataclass
class Use:
    function: Function
    usage: str
    confidence: str
    reason: str


@dataclass
class _State:
    usages: set[str] = field(default_factory=set)
    level: str = ""
    reasons: list[str] = field(default_factory=list)


def functions_in(code: str, with_strings: str, where: str, line_of) -> list[Function]:
    """Function definitions at brace depth 0: the text before `{` ends in `)` and has no `=`."""
    out: list[Function] = []
    depth = 0
    boundary = 0
    open_at = 0
    for m in _BRACE.finditer(code):
        if m.group(0) == "{":
            if depth == 0:
                open_at = m.start()
            depth += 1
            continue
        depth = max(depth - 1, 0)
        if depth:
            continue
        head_start, boundary = boundary, m.end()
        raw = code[head_start:open_at]
        head_start += raw.rfind(";") + 1                       # earlier prototypes and declarations are not part of it
        header = "\n".join(line for line in code[head_start:open_at].splitlines() if not line.lstrip().startswith("#"))
        text = header.strip()
        if "=" in text or not text.endswith(")") or "(" not in text:
            continue
        names = _IDENT.findall(text[:text.index("(")])
        if not names or names[-1] in _NOT_CALLS:
            continue
        name = names[-1]
        found = re.search(rf"\b{re.escape(name)}\s*\(", code[head_start:open_at])
        line = line_of(head_start + found.start()) if found else line_of(open_at)
        out.append(Function(name, where, line, text, code[open_at + 1:m.start()], with_strings[open_at + 1:m.start()]))
    return out


def analyse(funcs: list[Function], api_usage, name_usage) -> list[Use]:
    """
    `api_usage(token)` gives the usage of a certificate API (or None); `name_usage(token)` gives the
    usage a certificate word in an identifier suggests (or None, and "other" when it has no verb).
    """
    by_name: dict[str, list[Function]] = {}
    for f in funcs:
        by_name.setdefault(f.name, []).append(f)
    state: dict[str, _State] = {n: _State() for n in by_name}
    calls: dict[str, set[str]] = {}

    for name, defs in by_name.items():
        st = state[name]
        for f in defs:
            idents = set(_IDENT.findall(f.body))
            calls.setdefault(name, set()).update(c for c in _CALL.findall(f.body) if c not in _NOT_CALLS and c != name)
            direct = {}
            for token in idents:
                usage = api_usage(token)
                if usage:
                    direct[token] = usage
            if direct:
                st.level = "high"
                st.usages.update(direct.values())
                st.reasons.append("calls " + ", ".join(sorted(direct)[:3]))
                continue
            named = name_usage(name)
            if named is None:
                for token in _IDENT.findall(f.header):
                    named = name_usage(token)
                    if named is not None:
                        break
            if named is None:
                continue
            data = sorted(t for t in idents if t != name and name_usage(t) is not None)[:3]
            data_text = bool(_DATA_STRING.search(f.strings))
            level = "medium" if (data or data_text) else "low"
            if _rank(level) > _rank(st.level):
                st.level = level
            st.usages.add(named)
            st.reasons.append("name" + (f" and body uses {', '.join(data)}" if data else " and a certificate string" if data_text else " only"))

    for _ in range(HOPS):
        before = {n: st.level for n, st in state.items()}
        changed = False
        for name, called in calls.items():
            st = state[name]
            via = sorted(c for c in called if before.get(c) in ("high", "medium"))
            if via and st.level in ("", "low"):
                st.level = "medium"
                st.usages.update(u for c in via for u in state[c].usages)
                st.reasons.append(f"calls function {via[0]}")
                changed = True
        if not changed:
            break

    uses = []
    for name, st in state.items():
        if not st.level:
            continue
        first = by_name[name][0]
        for usage in sorted(st.usages or {"other"}, key=PRIORITY.index):
            uses.append(Use(first, usage, st.level, "; ".join(dict.fromkeys(st.reasons))))
    return uses


def _rank(level: str) -> int:
    return {"": 0, "low": 1, "medium": 2, "high": 3}[level]
