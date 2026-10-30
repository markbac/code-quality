"""
Lexical facts for the architecture brief, read from the source text: comments, signatures, function
bodies, enums, structs, constants, log strings, interrupt priorities, peripheral use and linker
memory regions. The parse already gives the call graph and globals; these are the parts it keeps
no record of. Everything here is a heuristic on text and says so in the brief.
"""

from __future__ import annotations

import ast
import operator
import re
from dataclasses import dataclass, field
from pathlib import Path

from fwlens.arch.edges import blank
from fwlens.crypto.keywords import words_of

COMMENT_CHARS = 600                 # a comment longer than this is cut, with "..." at the end
_COMMENT = re.compile(r"/\*.*?\*/|//[^\n]*", re.DOTALL)
_SPACE = re.compile(r"\s+")
_KEYWORDS = {"if", "while", "for", "switch", "return", "sizeof", "defined", "case", "do", "else", "_Static_assert",
             "__attribute__", "__asm", "asm", "__asm__", "typeof", "alignof", "_Alignof", "offsetof"}
_CALL = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
_LOOP = re.compile(r"\bwhile\s*\(\s*(?:1|true|TRUE|1U|1u)\s*\)|\bfor\s*\(\s*;\s*;\s*\)")
_ENUM = re.compile(r"\b(typedef\s+)?enum\s*([A-Za-z_]\w*)?\s*(?::\s*[\w\s]+)?\{")
_STRUCT = re.compile(r"\b(typedef\s+)?(struct|union)\s*([A-Za-z_]\w*)?\s*\{")
_DEFINE = re.compile(r"^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)(?![\w(])[ \t]+([^\n]*?)[ \t]*$", re.M)
_NUMBER = re.compile(r"^\(?\s*-?(?:0[xX][0-9A-Fa-f]+|\d+(?:\.\d+)?)[uUlLfF]*\s*\)?$")
_NVIC = re.compile(r"\b(HAL_NVIC_SetPriority|NVIC_SetPriority|NVIC_EnableIRQ|HAL_NVIC_EnableIRQ)\s*\(\s*([^,)]+?)\s*(?:,\s*([^,)]+?)\s*)?(?:,\s*([^,)]+?)\s*)?\)")
_DECLARATION = re.compile(r"^(?:const\s+|volatile\s+|unsigned\s+|signed\s+|struct\s+|enum\s+)*[A-Za-z_]\w*[\s*]+[A-Za-z_]\w*$")
_LICENCE = re.compile(r"\b(?:copyright|licen[cs]ed?|spdx-license-identifier|all rights reserved|permission is hereby granted)\b", re.I)
_HAL_PERIPH = re.compile(r"^(?:HAL|LL)_([A-Z][A-Z0-9]*?)(?:Ex)?_")
_REGISTER = re.compile(r"\b((?:LP)?(?:USART|UART|SPI|I2C|TIM|GPIO|ADC|DAC|DMA|RTC|IWDG|WWDG|FDCAN|CAN|USB_OTG|USB|ETH|SDMMC|SDIO|"
                       r"QUADSPI|OCTOSPI|FLASH|PWR|RCC|EXTI|SYSCFG|CRC|RNG|AES|HASH|LCD|LTDC|DCMI|COMP|OPAMP|SAI|I2S)"
                       r"[0-9]*[A-Z]?(?:_[A-Za-z0-9]+)?)\s*->")
_LOG_WORDS = {"log", "logger", "printf", "print", "trace", "debug", "dbg", "info", "warn", "warning", "error", "err", "verbose", "puts"}
_STRING_ARG = re.compile(r'"((?:\\.|[^"\\\n])*)"')
_LD_REGION = re.compile(r"^\s*([A-Za-z_][\w.]*)\s*(?:\(\s*([rwxaiRWXAIl!]*)\s*\))?\s*:\s*(?:ORIGIN|org|o)\s*=\s*([^,]+?)\s*,\s*"
                        r"(?:LENGTH|len|l)\s*=\s*([^\n/]+?)\s*$", re.M)
_ICF_REGION = re.compile(r"define\s+region\s+(\w+)\s*=\s*mem\s*:\s*\[\s*from\s+([^\s\]]+)\s+(to|size)\s+([^\s\]]+)\s*\]")
_ICF_SYMBOL = re.compile(r"define\s+symbol\s+(__ICFEDIT_region_\w+?__|__region_\w+__)\s*=\s*([^;]+);")

CONSTANT_CATEGORIES = [
    ("time", {"ms", "msec", "us", "usec", "sec", "secs", "seconds", "timeout", "period", "interval", "delay", "tick", "ticks", "ns", "minutes", "hours"}),
    ("clock", {"hz", "khz", "mhz", "freq", "frequency", "clk", "clock", "pll", "osc", "hse", "hsi", "lse", "lsi"}),
    ("comms", {"baud", "baudrate", "bps", "port", "mtu", "retries", "retry"}),
    ("memory", {"addr", "address", "base", "offset", "start", "end", "origin", "flash", "ram", "sector", "page", "bank", "slot"}),
    ("size", {"size", "len", "length", "max", "min", "count", "num", "capacity", "depth", "bytes", "buf", "buffer"}),
    ("version", {"version", "ver", "major", "minor", "patch", "build", "revision"}),
    ("priority", {"prio", "priority", "irq", "nvic"}),
]


def collapse(text: str, limit: int = COMMENT_CHARS) -> str:
    text = _SPACE.sub(" ", text).strip()
    return text if len(text) <= limit else text[:limit - 3].rstrip() + "..."


def comment_text(raw: str) -> str:
    """A comment without its markers and decoration (/*, */, //, leading *, rows of = or -)."""
    lines = []
    for line in raw.splitlines():
        line = line.strip()
        line = re.sub(r"^/\*+!?<?|\*+/$|^//+!?<?", "", line).strip()
        line = re.sub(r"^\*+\s?", "", line)
        if re.fullmatch(r"[-=*#~_ ]*", line):
            continue
        lines.append(line)
    return collapse(" ".join(lines))


@dataclass
class Body:
    start: int          # offset of the opening brace
    end: int            # offset just past the closing brace
    start_line: int
    end_line: int


@dataclass
class SourceFile:
    path: Path
    raw: str
    code: str = ""      # comments and strings blanked
    strings: str = ""   # comments blanked, strings kept
    _line_starts: list = field(default_factory=list)
    _enums: list | None = None

    def __post_init__(self):
        self.code = blank(self.raw)
        self.strings = _COMMENT.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), self.raw)
        self._line_starts = [0] + [m.end() for m in re.finditer(r"\n", self.raw)]

    def line_of(self, pos: int) -> int:
        lo, hi = 0, len(self._line_starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self._line_starts[mid] <= pos:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1

    def offset(self, line: int) -> int:
        return self._line_starts[min(max(line, 1), len(self._line_starts)) - 1]

    # -- comments ------------------------------------------------------------------------

    def header_comment(self) -> str:
        """The first comment at the top of the file, before any code, that is not a licence or
        copyright notice."""
        m = re.match(r"\s*((?:(?:/\*.*?\*/|//[^\n]*)\s*)+)", self.raw, re.DOTALL)
        if not m:
            return ""
        blocks = re.findall(r"/\*.*?\*/|(?://[^\n]*\n?\s*)+", m.group(1), re.DOTALL)
        texts = [comment_text(b) for b in blocks]
        return next((t for t in texts if t and not _LICENCE.search(t)), "")

    def comment_before(self, line: int) -> str:
        """The comment that ends on the line above `line` (or on the line before an attribute or
        storage-class line), the usual place for a function's or type's description."""
        lines = self.raw.splitlines()
        i = line - 2
        if i >= 0 and i < len(lines) and lines[i].strip() and not _ends_comment(lines[i]) and \
                not lines[i].rstrip().endswith((";", "}", "{")) and not lines[i].lstrip().startswith("#"):
            i -= 1                                  # a return type on its own line
        if i < 0 or i >= len(lines) or not _ends_comment(lines[i]):
            return ""
        end = i
        if "*/" in lines[i]:
            while i >= 0 and "/*" not in lines[i]:
                i -= 1
        else:
            while i - 1 >= 0 and lines[i - 1].lstrip().startswith("//"):
                i -= 1
        return comment_text("\n".join(lines[max(i, 0):end + 1]))

    # -- functions -----------------------------------------------------------------------

    def body_at(self, line: int) -> Body | None:
        """The brace block of the function defined at `line`."""
        pos = self.code.find("{", self.offset(line))
        if pos < 0:
            return None
        semi = self.code.find(";", self.offset(line), pos)
        if semi >= 0 and self.code.count("(", self.offset(line), semi) == self.code.count(")", self.offset(line), semi):
            return None                             # a declaration, not a definition
        end = match_brace(self.code, pos)
        return Body(pos, end, self.line_of(pos), self.line_of(max(end - 1, pos)))

    def signature_at(self, line: int, name: str) -> str:
        start = self.offset(line)
        prev = self.offset(line - 1) if line > 1 else start
        prev_text = self.code[prev:start].strip()
        if prev_text and not prev_text.endswith((";", "}", "{", ")")) and not prev_text.startswith("#"):
            start = prev                            # the return type on the line above
        brace = self.code.find("{", start)
        semi = self.code.find(";", start)
        stops = [p for p in (brace, semi) if p >= 0]
        end = min(stops) if stops else min(len(self.code), start + 400)
        text = collapse(self.code[start:end], 400)
        return text if name in text else ""

    def calls_in(self, start: int, end: int) -> list[tuple[str, int]]:
        """(name, line) of each call between two offsets, in order."""
        out = []
        for m in _CALL.finditer(self.code, start, end):
            if m.group(1) not in _KEYWORDS:
                out.append((m.group(1), self.line_of(m.start())))
        return out

    def first_loop(self, start: int, end: int) -> tuple[int, Body | None] | None:
        """The first unbounded loop between two offsets: its offset and its body."""
        m = _LOOP.search(self.code, start, end)
        if not m:
            return None
        brace = self.code.find("{", m.end(), end)
        if brace < 0 or self.code[m.end():brace].strip():
            return m.start(), None
        close = match_brace(self.code, brace)
        return m.start(), Body(brace, close, self.line_of(brace), self.line_of(close - 1))

    # -- types and constants -------------------------------------------------------------

    def enums(self) -> list[dict]:
        if self._enums is None:
            self._enums = self._find_enums()
        return self._enums

    def _find_enums(self) -> list[dict]:
        out = []
        for m in _ENUM.finditer(self.code):
            brace = m.end() - 1
            close = match_brace(self.code, brace)
            tail = re.match(r"\s*([A-Za-z_]\w*)?", self.code[close:])
            name = (tail.group(1) if m.group(1) and tail and tail.group(1) else None) or m.group(2) or ""
            constants: list[dict] = []
            value: int | None = -1
            known: dict[str, int] = {}
            for item in _split_top(self.code[brace + 1:close - 1], ","):
                cm = re.match(r"\s*([A-Za-z_]\w*)\s*(?:=\s*(.+))?$", item, re.DOTALL)
                if not cm:
                    continue
                expr = collapse(cm.group(2) or "", 120)
                if expr:
                    parsed = _int_value(expr, known)
                    value = parsed if parsed is not None else None
                elif value is not None:
                    value += 1
                if value is not None:
                    known[cm.group(1)] = value
                constants.append({"name": cm.group(1), "value": value if value is not None else expr})
            line = self.line_of(m.start())
            out.append({"name": name, "line": line, "constants": constants, "doc": self.comment_before(line)})
        return out

    def structs(self) -> list[dict]:
        out = []
        for m in _STRUCT.finditer(self.code):
            brace = m.end() - 1
            if _inside_parens(self.code, m.start()):
                continue
            close = match_brace(self.code, brace)
            tail = re.match(r"\s*([A-Za-z_]\w*)?", self.code[close:])
            name = (tail.group(1) if m.group(1) and tail and tail.group(1) else None) or m.group(3) or ""
            if not name:
                continue                            # an anonymous member struct is shown in its parent's fields
            fields = []
            for item in _split_top(self.code[brace + 1:close - 1], ";"):
                text = collapse(item, 160)
                if text:
                    fields.append(text)
            line = self.line_of(m.start())
            out.append({"name": name, "kind": m.group(2), "line": line, "fields": fields, "doc": self.comment_before(line)})
        return out

    def defines(self) -> list[dict]:
        out = []
        for m in _DEFINE.finditer(self.strings):
            value = collapse(m.group(2), 160)
            if not value:
                continue
            line = self.line_of(m.start())
            words = set(words_of(m.group(1)))
            category = next((c for c, ws in CONSTANT_CATEGORIES if words & ws), "")
            out.append({"name": m.group(1), "value": value, "line": line, "numeric": bool(_NUMBER.match(value)),
                        "category": category})
        return out

    # -- runtime clues -------------------------------------------------------------------

    def log_strings(self, start: int, end: int) -> list[dict]:
        out = []
        for m in _CALL.finditer(self.strings, start, end):
            name = m.group(1)
            if not set(words_of(name)) & _LOG_WORDS:
                continue
            close = match_paren(self.strings, m.end() - 1)
            s = _STRING_ARG.search(self.strings, m.end(), close)
            if s:
                out.append({"call": name, "line": self.line_of(m.start()), "text": collapse(s.group(1), 200)})
        return out

    def nvic(self) -> list[dict]:
        out = []
        for m in _NVIC.finditer(self.code):
            if _DECLARATION.match(m.group(2)):
                continue                            # the function's own declaration or definition
            entry = {"call": m.group(1), "irq": m.group(2).strip(), "line": self.line_of(m.start())}
            if "SetPriority" in m.group(1):
                entry["priority"] = (m.group(3) or "").strip()
                if m.group(4):
                    entry["sub_priority"] = m.group(4).strip()
            out.append(entry)
        return out

    def registers(self, start: int, end: int) -> set[str]:
        return {m.group(1) for m in _REGISTER.finditer(self.code, start, end)}


def _ends_comment(line: str) -> bool:
    s = line.strip()
    return s.endswith("*/") or s.startswith("//")


def match_brace(text: str, pos: int) -> int:
    """Offset just past the brace that closes the one at `pos`."""
    depth, i = 0, pos
    while i < len(text):
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return len(text)


def match_paren(text: str, pos: int) -> int:
    depth, i = 0, pos
    while i < len(text):
        c = text[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return len(text)


def _inside_parens(text: str, pos: int) -> bool:
    """True when `pos` is inside parentheses on its line, as in a cast or a parameter list."""
    line_start = text.rfind("\n", 0, pos) + 1
    before = text[line_start:pos]
    return before.count("(") > before.count(")")


def _split_top(text: str, sep: str) -> list[str]:
    """Split on `sep` outside braces, brackets and parentheses."""
    parts: list[str] = []
    cur: list[str] = []
    depth = 0
    for c in text:
        if c in "{[(":
            depth += 1
        elif c in "}])":
            depth -= 1
        if c == sep and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(c)
    parts.append("".join(cur))
    return [p for p in (p.strip() for p in parts) if p and not p.startswith("#")]


_BINOPS = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul, ast.LShift: operator.lshift,
           ast.RShift: operator.rshift, ast.BitOr: operator.or_, ast.BitAnd: operator.and_, ast.BitXor: operator.xor}


def _int_value(expr: str, known: dict[str, int]) -> int | None:
    """The value of an enum initialiser made of integers, earlier constants and simple operators."""
    expr = re.sub(r"\b(0[xX][0-9A-Fa-f]+|\d+)[uUlL]+\b", r"\1", expr.strip())

    def ev(node):
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return node.value
        if isinstance(node, ast.Name) and node.id in known:
            return known[node.id]
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.Invert)):
            v = ev(node.operand)
            return -v if isinstance(node.op, ast.USub) else ~v
        if isinstance(node, ast.BinOp) and type(node.op) in _BINOPS:
            left, right = ev(node.left), ev(node.right)
            if isinstance(node.op, ast.LShift) and right > 64:
                raise ValueError(expr)
            return _BINOPS[type(node.op)](left, right)
        raise ValueError(expr)

    try:
        return ev(ast.parse(expr, mode="eval").body)
    except (ValueError, SyntaxError, TypeError, RecursionError):
        return None


def peripheral_of_call(name: str) -> str:
    """UART for HAL_UART_Transmit, GPIO for LL_GPIO_SetOutputPin, empty for anything else."""
    m = _HAL_PERIPH.match(name)
    return m.group(1) if m else ""


def register_peripheral(name: str) -> str:
    """USART for USART1, GPIO for GPIOA, TIM for TIM2: the peripheral family of a register block."""
    m = re.match(r"(LP)?([A-Z]+?)(?:[0-9]+[A-Z]?|[A-K])?(?:_|$)", name)
    return ((m.group(1) or "") + m.group(2)) if m else name


def memory_regions(path: Path) -> list[dict]:
    """MEMORY regions of a GNU linker script, or regions and region symbols of an IAR .icf file."""
    try:
        text = blank(path.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return []
    out = []
    if path.suffix.lower() == ".icf":
        for m in _ICF_REGION.finditer(text):
            entry = {"name": m.group(1), "origin": m.group(2)}
            entry["end" if m.group(3) == "to" else "length"] = m.group(4)
            out.append(entry)
        for m in _ICF_SYMBOL.finditer(text):
            out.append({"symbol": m.group(1), "value": m.group(2).strip()})
        return out
    memory = re.search(r"\bMEMORY\s*\{", text)
    if memory:
        block = text[memory.end():match_brace(text, memory.end() - 1) - 1]
        for m in _LD_REGION.finditer(block):
            out.append({"name": m.group(1), "attributes": m.group(2) or "", "origin": m.group(3).strip(),
                        "length": m.group(4).strip()})
    return out
