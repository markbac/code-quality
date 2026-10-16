"""
Hidden-finding checks: code where a MISRA C finding was probably silenced rather than fixed.

A cast, a ``(void)``, a ``while (1)``, an empty ``default``, a variable nobody reads or an analyser
suppression can make a checker go quiet while the truncation, misaligned read, ignored failure or
lock-up is still there. These checks look for the shapes such edits leave behind (hide signatures),
not for the language features themselves, so ordinary uses of a cast or ``(void)`` are not reported.

Ported from misra_hide_scan. The checks are text based: they run on the ``code`` view of a
SourceFile (comments and literal contents blanked) with bracket matching and a small text-order
data-flow pass, and have no type information or macro expansion. Every file is analysed once and
the results are shared by all the rules of the fwlens-hides standard, each of which selects one
check id and severity:

    check: { type: native, engine: source, match: { name: hidden_finding, check: discarded-return, severity: high } }

Severity is confidence that a hazard is hidden, not the MISRA category of the rule.
"""

from __future__ import annotations

import bisect
import re
from typing import NamedTuple

from fwlens.standards.engines import source_check
from fwlens.standards.sourcechecks import _LEX, SourceFile

# --- configuration ------------------------------------------------------------------------------
# Integer types narrower than int on a typical 32-bit target. A cast *to* one
# of these, applied to the result of arithmetic, is the classic Rule 10.3
# hide: the arithmetic happens in int, the cast throws the high bits away.
# Includes stdint names, AUTOSAR names (uint8, sint16) and common house
# abbreviations (u8, S16). Add your own typedefs here.
NARROW = (
    r"(?:u?int(?:8|16)_t|u?int_(?:least|fast)(?:8|16)_t"
    r"|uint8|uint16|sint8|sint16|[us](?:8|16)|[US](?:8|16)"
    r"|(?:(?:un)?signed\s+)?char|(?:(?:un)?signed\s+)?short(?:\s+int)?"
    r"|bool|boolean|_Bool)"
)

# Words that are accepted as type names when deciding whether "( ... )" is a
# cast or just a parenthesised expression. Without type information we cannot
# know that "(foo)" is a typedef, so we only accept recognisable type spellings:
# C keywords, anything ending in _t / _T, and the fixed-width naming schemes.
TYPE_WORD = (
    r"(?:void|char|short|int|long|float|double|signed|unsigned|_Bool|bool"
    r"|boolean|size_t|ptrdiff_t|u?intptr_t|[A-Za-z_]\w*_[tT]"
    r"|u?int\d+|sint\d+|float\d+|[usUS]\d+)"
)

# Candidate cast syntax: "(" qualifiers/tag-keywords, one or more words,
# optional pointer stars (each optionally const/volatile), ")". Whether the
# words really form a type is decided afterwards by looks_like_type().
CAST_RE = re.compile(
    r"\(\s*(?P<type>(?:(?:const|volatile|struct|enum|union)\s+)*"
    r"[A-Za-z_]\w*(?:\s+[A-Za-z_]\w*)*\s*(?:\*\s*(?:const\s*|volatile\s*)*)*)\)"
)

# Binary operators that can make a result too large for its destination type.
# ">>" and "&" are absent on purpose: (uint8_t)(v >> 8U) and
# (uint8_t)(v & 0xFFU) are the normal, intentional way to extract a byte and
# cannot overflow.
GROWING_OPS = {"+", "-", "*", "<<"}

# Operators that can overflow badly enough that widening *after* the
# operation is too late, e.g. (uint32_t)(u16a * u16b).
OVERFLOWING_OPS = {"*", "<<"}

# Pointer targets for which dereferencing a cast pointer is allowed by the C
# aliasing rules and has no alignment requirement. Reading an object byte by
# byte through (const uint8_t *) is legitimate and is not reported.
BYTE_TYPES = {"void", "char", "unsigned char", "signed char",
              "uint8_t", "uint8", "u8", "U8"}

# Standard functions whose return value carries no error information worth
# testing (memcpy returns its first argument, and so on). (void) on these is
# normal practice and is not reported.
DISCARD_OK = {"memset", "memcpy", "memmove", "strcpy", "strncpy", "strcat",
              "strncat", "printf", "fprintf", "sprintf", "snprintf", "puts",
              "putchar"}

# Fragments of function names that suggest the return value reports success
# or failure of something that matters (I/O, persistence, locking, set-up).
# Ignoring the result of such a call is reported as high severity.
CRITICAL_VERB = re.compile(
    r"write|send|transmit|erase|program|flash|init|start|stop|lock|take|give"
    r"|post|pend|set|save|store|flush|commit|open|close|read|recv|receive"
    r"|verify|check|alloc|register|enable|disable|config|update|load|crc",
    re.IGNORECASE,
)

# Standard library functions banned by MISRA C:2012 Rules 21.3 to 21.10,
# mapped to the rule. Used to spot thin wrappers and look-alike
# reimplementations that stop callers matching the rule.
BANNED = {}
for _rule, _names in {
    "21.3": "malloc calloc realloc free aligned_alloc",
    "21.4": "setjmp longjmp",
    "21.5": "signal raise",
    "21.6": "printf fprintf sprintf snprintf vprintf vfprintf vsprintf "
            "vsnprintf scanf fscanf sscanf fopen fclose fread fwrite fgets "
            "fputs gets puts getchar putchar fgetc fputc fflush remove rename",
    "21.7": "atoi atol atoll atof",
    "21.8": "abort exit _Exit quick_exit getenv system",
    "21.9": "bsearch qsort",
    "21.10": "time localtime gmtime mktime clock strftime difftime ctime asctime",
}.items():
    for _n in _names.split():
        BANNED[_n] = _rule

# Banned names too generic to match inside a project function's *name*
# ("Calc_Time" is not a reimplementation of time()). They are still matched
# as *calls* inside a wrapper.
BANNED_NAME_TOO_GENERIC = {"time", "clock", "free", "exit", "signal", "raise",
                           "remove", "rename", "system", "abort"}

# Variable names conventionally used to carry a status or error code. If one
# of these is assigned and then overwritten before anyone reads it, an error
# has probably been lost.
STATUS_NAME = re.compile(r"(?:ret|retval|ret_val|rv|rc|res|result|status|stat|err|error|e)",
                         re.IGNORECASE)

# Comment syntax used by common analysers to silence a finding in place.
SUPPRESSION = re.compile(
    r"polyspace|PRQA\s+S|cppcheck-suppress|NOLINT|\blint\s*[-!]e|-esym"
    r"|parasoft-(?:begin-)?suppress|coverity\[|LDRA_|klocwork|codesonar"
    r"|\bMISRA\b.*\b(?:suppress|ignore|off|disable)",
    re.IGNORECASE,
)

# #pragma forms that switch diagnostics off (compiler or analyser).
PRAGMA_SUPPRESSION = re.compile(
    r"^\s*#\s*pragma\s+(?:GCC\s+diagnostic\s+ignored|clang\s+diagnostic\s+ignored"
    r"|warning\s*\(\s*(?:disable|suppress)|diag_suppress|diag_remark|nowarn"
    r"|ghs\s+nowarning|polyspace|PRQA|coverity|cppcheck|MISRA|lint|parasoft|ldra"
    r"|CHECK_MISRA|section\s+suppress)",
    re.IGNORECASE | re.MULTILINE,
)

# What a reference to a formal deviation record looks like. A construct with
# one of these nearby is treated as documented. A rule can override it with
# the deviation_pattern match parameter.
DEFAULT_DEVIATION = r"\bDEV(?:IATION)?[-_ ]?#?\s*\d+|\bdeviation\s+(?:record|id|ref)"

# How many lines above a construct to search for a deviation reference. Large
# enough for a typical multi-line deviation header comment.
DEVIATION_LOOKBACK = 15

# How many lines above "buf[i - 1U]" to search for a guard such as i > 0U.
GUARD_LOOKBACK = 5

C_KEYWORDS = {"if", "else", "while", "for", "do", "switch", "case", "default",
              "return", "break", "continue", "goto", "sizeof", "typedef",
              "_Alignof", "defined"}


class Hit(NamedTuple):
    """One problem found by a check. ``offset`` is a character offset into the file."""
    offset: int
    severity: str
    check: str
    message: str


class Finding(NamedTuple):
    line: int
    severity: str
    check: str
    message: str


class Function(NamedTuple):
    """A function definition: name, parameter names and the offsets of its braces in the code."""
    name: str
    params: list
    start: int
    end: int


class Source:
    """One C file with the structure the checks need.

    text      the original source, used for snippets, comment content and deviation searches.
    code      the SourceFile ``code`` view: comments and literal contents blanked, offsets kept,
              so a construct inside a comment or a string is never reported.
    comments  (offset, comment text) for every comment, used by the suppression check.
    functions every function definition, found by find_functions().
    blocks    sorted (open, close) offsets of every {...} pair.
    """

    def __init__(self, sf: SourceFile):
        self.path = sf.path
        self.text = sf.raw
        self.code = sf.code
        self.comments = [(m.start(), m.group(0)) for m in _LEX.finditer(sf.raw) if m.group(0)[0] not in "\"'"]
        # Offset of the first character of each line, for offset -> line.
        self.line_starts = [0] + [m.end() for m in re.finditer(r"\n", self.text)]
        self.lines = self.text.splitlines()
        self.functions = find_functions(self.code)
        self.blocks = find_blocks(self.code)

    def line_of(self, offset):
        """1-based line number containing `offset`."""
        return bisect.bisect_right(self.line_starts, offset)

    def function_at(self, offset):
        """The Function whose body contains `offset`, or None."""
        for fn in self.functions:
            if fn.start < offset < fn.end:
                return fn
        return None

    def innermost_block(self, offset):
        """(open, close) of the innermost {...} containing offset, or None."""
        best = None
        for b in self.blocks:
            if b[0] >= offset:
                break
            if offset < b[1]:
                best = b
        return best


# --- lexical helpers ----------------------------------------------------------------------------
# Small, deliberately simple tools for walking the blanked `code` text. They trade completeness for
# predictability: each does one thing that is easy to reason about when a finding looks wrong.


def match_forward(text, i, open_ch, close_ch):
    """Index of the bracket closing the one at text[i], or -1."""
    depth = 0
    for k in range(i, len(text)):
        if text[k] == open_ch:
            depth += 1
        elif text[k] == close_ch:
            depth -= 1
            if depth == 0:
                return k
    return -1


def match_backward(text, i, open_ch, close_ch):
    """Index of the bracket opening the one at text[i], or -1."""
    depth = 0
    for k in range(i, -1, -1):
        if text[k] == close_ch:
            depth += 1
        elif text[k] == open_ch:
            depth -= 1
            if depth == 0:
                return k
    return -1


def prev_char(text, i):
    """Nearest non-whitespace character before index i, or ''."""
    k = i - 1
    while k >= 0 and text[k].isspace():
        k -= 1
    return text[k] if k >= 0 else ""


def prev_char_index(text, i):
    """Index of the nearest non-whitespace character before i, or -1."""
    k = i - 1
    while k >= 0 and text[k].isspace():
        k -= 1
    return k


def prev_word(text, i):
    """Identifier immediately before index i (ignoring whitespace), or ''."""
    m = re.search(r"([A-Za-z_]\w*)\s*$", text[max(0, i - 200):i])
    return m.group(1) if m else ""


def next_char_index(text, i):
    """Index of the first non-whitespace character at or after i."""
    while i < len(text) and text[i].isspace():
        i += 1
    return i


def statement_start(code, i):
    """Offset just after the ';', '{' or '}' that precedes index i."""
    return max(code.rfind(";", 0, i), code.rfind("{", 0, i), code.rfind("}", 0, i)) + 1


def is_operand_end(ch):
    """True if ch can end an operand, so a following +, - or * is binary.

    This is how unary minus and pointer dereference are told apart from
    subtraction and multiplication: in "a * b" the '*' follows 'a'; in
    "x = *p" it follows '='.
    """
    return ch.isalnum() or ch in "_)]"


def looks_like_type(t):
    """Decide whether the words inside a candidate cast form a type name.

    Pointers and struct/enum/union tags are always accepted. Otherwise every
    word must be a recognisable type word (see TYPE_WORD), which rejects
    "(x)", "(a + b)" and similar parenthesised expressions.
    """
    t = t.strip()
    if "*" in t or re.match(r"(?:struct|enum|union)\b", t):
        return True
    words = re.sub(r"\b(?:const|volatile)\b", " ", t).split()
    return bool(words) and all(re.fullmatch(TYPE_WORD, w) for w in words)


def top_level_ops(expr):
    """Binary arithmetic operators at bracket depth 0 of expr.

    Only the outermost level matters: in (uint8_t)((a + b) & 0xFF) the
    operation whose result is cast is '&', not '+'. Compound assignment,
    increment, '->' and logical operators are skipped, and unary +, - and *
    are excluded via is_operand_end().
    """
    ops = set()
    depth = 0
    i = 0
    while i < len(expr):
        c = expr[i]
        two = expr[i:i + 2]
        if c in "([":
            depth += 1
        elif c in ")]":
            depth -= 1
        elif depth == 0:
            if two in ("<<", ">>"):
                if expr[i + 2:i + 3] != "=":
                    ops.add(two)
                i += 2
                continue
            if two in ("++", "--", "->", "+=", "-=", "*=", "&&", "||"):
                i += 2
                continue
            if c in "+-*" and is_operand_end(prev_char(expr, i)):
                ops.add(c)
        i += 1
    return ops


def normalise_type(t):
    """Collapse internal whitespace: 'unsigned   char' -> 'unsigned char'."""
    return " ".join(t.split())


def pointee(t_norm):
    """Base type a pointer type points at, without qualifiers or stars."""
    return " ".join(re.sub(r"\b(?:const|volatile)\b|\*", " ", t_norm).split())


def split_top_level(text, sep=","):
    """Split on `sep` where not nested inside brackets."""
    parts, depth, cur = [], 0, []
    for c in text:
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        if c == sep and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(c)
    parts.append("".join(cur))
    return parts


# A function header ending just before '{': name ( params ) where params may
# contain one level of nested parentheses (function-pointer parameters).
FUNC_HEAD = re.compile(
    r"([A-Za-z_]\w*)\s*\(((?:[^;{}()]|\([^;{}()]*\))*)\)\s*$")


def param_names(plist):
    """Names of the parameters in a function's parameter list text."""
    names = []
    for part in split_top_level(plist):
        part = re.sub(r"\[[^\]]*\]", "", part).strip()
        fp = re.search(r"\(\s*\*\s*([A-Za-z_]\w*)\s*\)", part)
        if fp:
            names.append(fp.group(1))
            continue
        m = re.search(r"([A-Za-z_]\w*)\s*$", part)
        if m and m.group(1) != "void" and len(part.split()) > 1 or (m and "*" in part):
            names.append(m.group(1))
    return names


def find_functions(code):
    """Find function definitions: a '{' outside any function, preceded by
    name(params). Struct bodies, initialisers and extern "C" blocks do not
    match FUNC_HEAD, so they are skipped and searched inside."""
    funcs = []
    i, n = 0, len(code)
    while i < n:
        if code[i] == "{":
            m = FUNC_HEAD.search(code, max(0, i - 2000), i)
            if m and m.group(1) not in C_KEYWORDS:
                close = match_forward(code, i, "{", "}")
                if close < 0:
                    break
                funcs.append(Function(m.group(1), param_names(m.group(2)), i, close))
                i = close + 1
                continue
        i += 1
    return funcs


def find_blocks(code):
    """All {...} pairs as (open, close) offsets, sorted by open."""
    stack, pairs = [], []
    for i, c in enumerate(code):
        if c == "{":
            stack.append(i)
        elif c == "}" and stack:
            pairs.append((stack.pop(), i))
    return sorted(pairs)


def find_casts(src):
    """Yield (match, type_text) for each probable cast expression in src.

    A candidate "( words )" is accepted as a cast only if:
    - the words look like a type (looks_like_type), and
    - it is not a function call or keyword: "foo(int)" and "sizeof(int)"
      have an identifier before the '(' (return and case are the exceptions,
      as "return (int)x;" is a cast), and
    - something that can start an operand follows it, so "(int) )" in a
      prototype or a bare "(void);" is not counted.
    """
    code = src.code
    for m in CAST_RE.finditer(code):
        t = m.group("type")
        if not looks_like_type(t):
            continue
        before = prev_char(code, m.start())
        if before and (before.isalnum() or before in "_]"):
            if prev_word(code, m.start()) not in ("return", "case"):
                continue
        nxt = next_char_index(code, m.end())
        if nxt >= len(code) or not re.match(r"[\w(&*~!+\-]", code[nxt]):
            continue
        yield m, t


def has_deviation(src, line, dev_re):
    """True if a deviation reference appears on `line` or the lines above."""
    lo = max(0, line - 1 - DEVIATION_LOOKBACK)
    return any(dev_re.search(l) for l in src.lines[lo:line])


def called_function(rhs):
    """Name of the function if `rhs` is a call (optionally cast), else None."""
    m = re.match(r"\s*(?:\(\s*[\w\s*]+\)\s*)?([A-Za-z_]\w*)\s*\(", rhs)
    return m.group(1) if m and m.group(1) not in C_KEYWORDS else None


# --- checks -------------------------------------------------------------------------------------
# Each check is a generator taking (src, dev_re) and yielding Hit tuples. Each docstring states:
#   Hide:    the shape that suggests a finding was silenced,
#   Why:     why that shape leaves the hazard in place,
#   Allowed: legitimate uses of the same feature that are NOT reported.
# The plain-English version of the same information is in the rules of builtin/fwlens-hides.yaml.

def check_arithmetic_casts(src, dev_re):
    """Casts applied to the result of arithmetic (Rules 10.3, 10.8).

    Hide:    (uint8_t)(len_a + len_b)
    Why:     the addition happens in int and may exceed 255; the cast makes
             the type mismatch go away but the value is still truncated.
             Likewise (uint32_t)(w * h) with 16-bit operands overflows in the
             operands' type before the cast widens anything.
    Allowed: casting an operand before the operation, (uint16_t)a + b;
             byte extraction, (uint8_t)(v >> 8U) and (uint8_t)(v & 0xFFU),
             which cannot grow the value; casting a single variable,
             (uint8_t)x, which may be correct after a range check and cannot
             be judged without types.
    """
    code = src.code
    for m, t in find_casts(src):
        t_norm = normalise_type(t)
        if "*" in t_norm or t_norm == "void":
            continue
        nxt = next_char_index(code, m.end())
        is_narrow = re.fullmatch(NARROW, t_norm) is not None

        if code[nxt] == "(":
            # Cast of a parenthesised expression: look at its outermost
            # operator, since that is the value the cast actually receives.
            close = match_forward(code, nxt, "(", ")")
            ops = top_level_ops(code[nxt + 1:close]) if close > 0 else set()
            growing = ops & GROWING_OPS
            if not growing:
                continue
            opstr = " ".join(sorted(growing))
            if is_narrow:
                yield Hit(m.start(), "high", "narrowing-cast-on-arithmetic",
                          f"({t_norm}) is applied to the result of '{opstr}', which "
                          f"can be too big for {t_norm}.")
            elif growing & OVERFLOWING_OPS:
                yield Hit(m.start(), "medium", "late-widening-cast",
                          f"({t_norm}) is applied after '{opstr}', so any overflow "
                          "has already happened.")
            else:
                yield Hit(m.start(), "low", "composite-cast",
                          f"({t_norm}) is applied to the result of '{opstr}'.")

        elif is_narrow and re.match(r"[A-Za-z_]\w*\s*\(", code[nxt:]):
            # Narrowing the return value of a call, e.g. (uint8_t)strlen(s).
            fn = re.match(r"[A-Za-z_]\w*", code[nxt:]).group(0)
            if fn not in ("sizeof", "_Alignof"):
                yield Hit(m.start(), "low", "narrowing-cast-on-call",
                          f"The result of {fn}() is cast to {t_norm} without a "
                          "visible range check.")


def check_discarded_returns(src, dev_re):
    """(void) applied to a function call (Rule 17.7, Dir 4.7).

    Hide:    (void)Flash_Write(addr, &cal, sizeof(cal));
    Why:     (void) is the recognised way to say "deliberately discarded",
             so it silences 17.7, but if the function reports failure the
             failure is now ignored silently.
    Allowed: (void)param; for unused parameters (not a call); (void) on
             functions in DISCARD_OK such as memcpy, whose return carries no
             error information. Calls whose name does not suggest a
             success/failure result are reported at low severity only.
    """
    code = src.code
    call = re.compile(r"(?:[A-Za-z_]\w*\s*(?:\.|->)\s*)*([A-Za-z_]\w*)\s*\(")
    for m, t in find_casts(src):
        if normalise_type(t) != "void":
            continue
        cm = call.match(code, next_char_index(code, m.end()))
        if not cm:
            continue
        fn = cm.group(1)
        if fn in DISCARD_OK:
            continue
        sev = "high" if CRITICAL_VERB.search(fn) else "low"
        yield Hit(m.start(), sev, "discarded-return",
                  f"The result of {fn}() is discarded with (void).")


def check_pointer_casts(src, dev_re):
    """Pointer casts used to reinterpret memory (Rules 11.3, 11.4, 11.5).

    cast-via-void-pointer
      Hide:    *(uint32_t *)(void *)&rx[1]
      Why:     routing through void * changes which rule the tool reports,
               or stops it reporting; the access is unchanged.
      Allowed: a single cast to or from void *, e.g. passing to memcpy.

    type-punned-access
      Hide:    *(uint32_t *)&rx[1], ((uint16_t *)buf)[i]
      Why:     misalignment faults, strict-aliasing violations, endianness.
      Allowed: access through a byte type (BYTE_TYPES); casts that are not
               immediately dereferenced. Member access, ((Obj *)p)->field,
               is reported at low severity as cast-pointer-member-access.

    int-to-pointer-undocumented
      Hide:    ((volatile uint32_t *)0x40001000UL) with no record
      Why:     MMIO needs this, but only with a recorded deviation.
      Allowed: the same cast with a deviation reference nearby.
    """
    code = src.code
    void_cast = re.compile(r"\(\s*(?:const\s+|volatile\s+)*void\s*\*\s*\)")
    int_const = re.compile(r"\(?\s*(?:0[xX][0-9A-Fa-f]+|\d+)[uUlL]*\b")

    for m, t in find_casts(src):
        t_norm = normalise_type(t)
        if "*" not in t_norm:
            continue
        nxt = next_char_index(code, m.end())
        target = pointee(t_norm)

        if void_cast.match(code, nxt) and target != "void":
            yield Hit(m.start(), "high", "cast-via-void-pointer",
                      f"A pointer is converted to ({t_norm}) by way of (void *).")

        if int_const.match(code, nxt):
            if not has_deviation(src, src.line_of(m.start()), dev_re):
                yield Hit(m.start(), "low", "int-to-pointer-undocumented",
                          f"An integer constant is cast to ({t_norm}) with no "
                          "deviation reference nearby.")
            # An address is not an object being reinterpreted, so the
            # punning analysis below does not apply.
            continue

        if target in BYTE_TYPES:
            continue

        # Is the cast pointer used immediately? Two forms:
        #   *(T *)expr          '*' before the cast, and that '*' is unary
        #   ((T *)expr)[i] / ->  cast wrapped in parens then indexed/derefd
        access = None
        if prev_char(code, m.start()) == "*":
            star = code.rfind("*", 0, m.start())
            if not is_operand_end(prev_char(code, star)):
                access = "deref"
        elif prev_char(code, m.start()) == "(":
            outer = code.rfind("(", 0, m.start())
            close = match_forward(code, outer, "(", ")")
            if close > 0:
                after = code[next_char_index(code, close + 1):][:2]
                if after.startswith("["):
                    access = "deref"
                elif after == "->":
                    access = "member"

        if access == "deref":
            yield Hit(m.start(), "high", "type-punned-access",
                      f"Memory is read or written as {target} through a "
                      f"({t_norm}) cast.")
        elif access == "member":
            yield Hit(m.start(), "low", "cast-pointer-member-access",
                      f"A member is accessed through a ({t_norm}) cast.")


def check_unsigned_invariant(src, dev_re):
    """Comparisons with 0U that can never change (Rule 14.3).

    Hide:    often what remains after a loop counter's type was changed to
             unsigned to silence a signedness finding: while (n >= 0U).
    Why:     an unsigned value is always >= 0, so the guard is dead.
    Allowed: comparisons with 0 (no U suffix) and != / == against 0U.
    """
    pat = re.compile(r"(?<![<>=!])>=\s*0[uU]\b|(?<![<])<(?![<=])\s*0[uU]\b"
                     r"|\b0[uU]\s*<=|\b0[uU]\s*>(?![>=])")
    for m in pat.finditer(src.code):
        yield Hit(m.start(), "high", "unsigned-invariant-compare",
                  "This comparison with 0U is always true or always false.")


def check_index_underflow(src, dev_re):
    """Array index of the form [i - 1U] with no guard (Rules 10.4, 18.1).

    Hide:    buf[i - 1] became buf[i - 1U] to silence a signed/unsigned
             mixing finding.
    Why:     if i is 0, i - 1U wraps to the maximum value and the access is
             far out of bounds.
    Allowed: the same index with a guard (i > 0U, i != 0U, i >= 1U, 0U < i)
             in the GUARD_LOOKBACK lines above. Only the U-suffixed form is
             reported, because the suffix is the hide signature.
    """
    code = src.code
    for m in re.finditer(r"\[\s*([A-Za-z_]\w*)\s*-\s*1[uU][lL]?\s*\]", code):
        var = re.escape(m.group(1))
        guard = re.compile(rf"\b{var}\s*(?:>|!=)\s*0[uU]?\b|\b{var}\s*>=\s*1[uU]?\b"
                           rf"|\b0[uU]?\s*<\s*{var}\b")
        line = src.line_of(m.start())
        lo = src.line_starts[max(0, line - 1 - GUARD_LOOKBACK)]
        if guard.search(code, lo, m.start()):
            continue
        yield Hit(m.start(), "low", "unsigned-index-underflow",
                  f"Index {m.group(1)} - 1U wraps to a huge value if "
                  f"{m.group(1)} is 0, and no guard is visible above.")


def check_infinite_loops(src, dev_re):
    """Constant loop conditions with an exit inside (Rules 14.3, 14.2).

    Hide:    while (1) { if (Radio_Send() == OK) { break; } }
             replacing a condition the tool called invariant.
    Why:     the tool stops complaining, but there is still no bound on the
             failure path.
    Allowed: a superloop or task body with no break, return or goto inside.
    """
    code = src.code
    pat = re.compile(r"\bwhile\s*\(\s*(?:1[uUlL]*|true|TRUE)\s*\)"
                     r"|\bfor\s*\(\s*;\s*;\s*\)")
    for m in pat.finditer(code):
        k = next_char_index(code, m.end())
        body = None
        if k < len(code) and code[k] == "{":
            # while (1) { ... }  or  for (;;) { ... }
            close = match_forward(code, k, "{", "}")
            body = code[k:close + 1]
        elif k < len(code) and code[k] == ";" and prev_char(code, m.start()) == "}":
            # do { ... } while (1);  -- the body is before the condition.
            end = code.rfind("}", 0, m.start())
            start = match_backward(code, end, "{", "}")
            body = code[start:end + 1]
        # A break inside a nested switch also matches; see Known limitations.
        if body and re.search(r"\b(?:break|return|goto)\b", body):
            yield Hit(m.start(), "medium", "constant-loop-with-exit",
                      "This loop has a constant condition and an exit inside; "
                      "check every failure path also leaves the loop.")


def check_empty_branches(src, dev_re):
    """default, else or if bodies that exist but do nothing (16.4, 15.7).

    Hide:    default: break;   else { }   if (err) { }   if (err);
    Why:     the structural rule is satisfied, but nobody decided what the
             unexpected value, remaining case or error means.
    Allowed: any statement in the body. A comment-only body is downgraded.
    """
    code = src.code
    empty_default = re.compile(
        r"\bdefault\s*:\s*(?:\{\s*)?(?:(?:break\s*)?;\s*)*(?:\}\s*)?(?=\}|\bcase\b)")
    for m in empty_default.finditer(code):
        yield Hit(m.start(), "medium", "empty-default",
                  "The default case does nothing.")

    for m in re.finditer(r"\belse\s*\{[\s;]*\}", code):
        # Comments were blanked in `code`; look in the original text.
        original = src.text[m.start():m.end()]
        has_comment = "/*" in original or "//" in original
        yield Hit(m.start(), "low" if has_comment else "medium", "empty-else",
                  "The final else is empty" +
                  (" apart from a comment." if has_comment else "."))

    for m in re.finditer(r"\bif\s*\(", code):
        close = match_forward(code, m.end() - 1, "(", ")")
        if close < 0:
            continue
        k = next_char_index(code, close + 1)
        if k < len(code) and code[k] == ";":
            original = src.text[close:k + 1]
            has_comment = "/*" in original or "//" in original
            yield Hit(m.start(), "medium" if has_comment else "high", "empty-if-body",
                      "This if statement ends in a semicolon, so its body is empty" +
                      (" apart from a comment." if has_comment else "."))
        elif k < len(code) and code[k] == "{":
            end = match_forward(code, k, "{", "}")
            if end > 0 and not code[k + 1:end].strip(" \t\r\n;"):
                original = src.text[k:end + 1]
                has_comment = "/*" in original or "//" in original
                yield Hit(m.start(), "medium" if has_comment else "high", "empty-if-body",
                          "This if statement tests a condition and does nothing" +
                          (" except hold a comment." if has_comment else "."))


def check_dummy_uses(src, dev_re):
    """Constructs that only exist to silence 'unused' warnings (2.2, 2.7).

    self-assignment
      Hide:    x = x;
      Why:     no effect; a trick to stop 'unused variable/parameter'.
      Allowed: nothing.

    discarded-local
      Hide:    status = Flash_Write(...); (void)status;
      Why:     on a local, (void) usually throws away a computed value.
      Allowed: (void)param; on a function parameter.
    """
    code = src.code
    for m in re.finditer(r"(?<![\w.>])([A-Za-z_]\w*)\s*=(?!=)\s*\1\s*;", code):
        if prev_char(code, m.start()) in "=!<>":
            continue
        yield Hit(m.start(), "high", "self-assignment",
                  f"'{m.group(1)}' is assigned to itself, which does nothing.")

    for m in re.finditer(r"\(\s*void\s*\)\s*([A-Za-z_]\w*)\s*;", code):
        fn = src.function_at(m.start())
        if fn is None or m.group(1) in fn.params:
            continue
        yield Hit(m.start(), "medium", "discarded-local",
                  f"Local variable '{m.group(1)}' is silenced with (void) rather "
                  "than used.")


def check_volatile_locals(src, dev_re):
    """volatile on an ordinary local variable (Rules 2.2, 14.3).

    Hide:    volatile uint8_t done = 0U;  added so 'condition always true'
             or 'value never used' stops being reported.
    Why:     volatile blinds analysers to the variable; the finding vanishes
             but the logic is unchanged.
    Allowed: pointers to volatile (hardware registers) and casts.
    """
    code = src.code
    for fn in src.functions:
        for m in re.finditer(r"\bvolatile\b", code[fn.start:fn.end]):
            pos = fn.start + m.start()
            stmt = code[statement_start(code, pos):code.find(";", pos)]
            head = stmt.split("=")[0]
            if "*" in head or "(" in head:
                continue
            name = re.search(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*$", head)
            yield Hit(pos, "medium", "volatile-local",
                      f"Local variable '{name.group(1) if name else '?'}' in "
                      f"{fn.name}() is declared volatile.")


def check_allocators(src, dev_re):
    """Replacement allocators (Rule 21.3, Dir 4.12).

    Hide:    void *App_Alloc(size_t n) { ...free list in static heap[]... }
    Why:     21.3 bans malloc by name; a renamed allocator silences it, but
             every hazard of dynamic allocation remains.
    Allowed: nothing by name; review decides.
    """
    code = src.code
    fn_def = re.compile(r"\bvoid\s*\*\s*([A-Za-z_]\w*)\s*\([^;{)]*\)\s*\{")
    for m in fn_def.finditer(code):
        if re.search(r"alloc|pool|heap|arena|get_?buf|get_?mem", m.group(1), re.IGNORECASE):
            yield Hit(m.start(), "medium", "custom-allocator",
                      f"{m.group(1)}() looks like a replacement for malloc.")

    backing = re.compile(r"\bstatic\s+(?:\w+\s+)*?(?:uint8_t|uint8|u8|unsigned\s+char|char)\s+"
                         r"(\w*(?:heap|pool|arena)\w*)\s*\[", re.IGNORECASE)
    for m in backing.finditer(code):
        yield Hit(m.start(), "low", "heap-backing-store",
                  f"Static byte array '{m.group(1)}' may be the storage for a "
                  "home-made heap.")


def check_banned_wrappers(src, dev_re):
    """Wrappers and look-alikes of banned library functions (21.3 to 21.10).

    Hide:    int Str_ToInt(const char *s) { return atoi(s); }
             int my_atoi(const char *s) { ...same behaviour... }
    Why:     callers of the wrapper no longer match the rule; the hazard is
             unchanged and now spread under another name.
    Allowed: a wrapper with a deviation reference nearby. Allocators are
             left to check_allocators.
    """
    code = src.code
    for fn in src.functions:
        line = src.line_of(fn.start)
        if has_deviation(src, line, dev_re):
            continue
        body = code[fn.start:fn.end]
        lname = fn.name.lower()

        # Look-alike by name: my_atoi, App_Printf, ...
        lookalike = None
        for b in BANNED:
            if b in BANNED_NAME_TOO_GENERIC or BANNED[b] == "21.3":
                continue
            if lname != b and (lname.endswith("_" + b) or lname.endswith(b)) \
                    and len(lname) > len(b):
                lookalike = b
                break
        if lookalike:
            yield Hit(fn.start, "medium", "banned-function-wrapper",
                      f"{fn.name}() looks like a project version of {lookalike}() "
                      f"(Rule {BANNED[lookalike]}).")
            continue

        # Thin wrapper: a short body (few statements) that calls a banned
        # function. Long functions that happen to call one are left to the
        # real MISRA checker.
        if body.count(";") > 4:
            continue
        for cm in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", body):
            b = cm.group(1)
            if b in BANNED and b != fn.name:
                yield Hit(fn.start, "medium", "banned-function-wrapper",
                          f"{fn.name}() is a thin wrapper around {b}() "
                          f"(Rule {BANNED[b]}).")
                break


def check_result_flow(src, dev_re):
    """Results stored then never read, or overwritten unread (17.7, 15.5).

    unchecked-result
      Hide:    ret = Flash_Write(...);   ...ret never read again
      Why:     assigning silences 'return value not used'; nothing tests it.

    overwritten-status
      Hide:    ret = Step_A();  ret = Step_B();   (single-exit rewrite)
      Why:     Step_A's error is lost; only Step_B's result reaches the
               caller.

    Allowed: values read before being overwritten (any use counts as a read,
             including &x, x++, x |= ..., *x = ..., x = f(x), and use inside
             a condition such as if ((ret = f()) != OK)); overwriting the
             declaration's initial value; writes in sibling branches
             (if/else, switch cases); writes inside a loop that also uses
             the variable (it may be read on the next pass); functions that
             use goto after the write; static locals.

    Only non-static locals declared in the function are analysed, so
    globals, parameters and out-parameters are never reported.
    """
    code = src.code
    decl_re = re.compile(
        r"(?:(?<=[;{}])|^)\s*((?:(?:static|const|volatile|register|struct|enum|union"
        r"|unsigned|signed)\s+)*[A-Za-z_]\w*(?:\s*\*+\s*|\s+))([A-Za-z_]\w*)\s*(?=[=;\[,])")

    def loop_may_read(offset, name):
        """True if a loop enclosing `offset` uses `name` anywhere else, in its
        condition or body. A value written late in a loop body can be read
        early in the next pass, so it is not lost."""
        var = re.compile(rf"(?<![\w.])\b{re.escape(name)}\b")

        def used_elsewhere(a, b):
            return any(m.start() != offset for m in var.finditer(code, a, b))

        for (o, c) in src.blocks:
            if not (o < offset < c):
                continue
            # while (...) { ... }  or  for (...) { ... }
            k = prev_char_index(code, o)
            if k >= 0 and code[k] == ")":
                j = match_backward(code, k, "(", ")")
                if j >= 0 and prev_word(code, j) in ("while", "for") and used_elsewhere(j, c):
                    return True
            # do { ... } while (...);
            k = next_char_index(code, c + 1)
            if prev_word(code, o) == "do" and code.startswith("while", k):
                q = code.find(";", k)
                if used_elsewhere(o, q):
                    return True
        return False

    for fn in src.functions:
        body_start, body_end = fn.start, fn.end
        locals_ = {}
        for d in decl_re.finditer(code, body_start + 1, body_end):
            typ = d.group(1).split()[0] if d.group(1).split() else ""
            if typ in C_KEYWORDS or d.group(2) in C_KEYWORDS:
                continue
            locals_.setdefault(d.group(2), "static" in d.group(1).split())

        for name, is_static in locals_.items():
            if is_static:
                continue
            occ = re.compile(rf"(?<![\w.])(?<!->)\b{re.escape(name)}\b")
            pending = None  # (offset, rhs_text, called_fn)
            for m in occ.finditer(code, body_start + 1, body_end):
                after = code[m.end():m.end() + 3]
                is_assign = re.match(r"\s*=(?!=)", after) is not None
                prefix = code[statement_start(code, m.start()):m.start()]
                is_decl = bool(prefix.strip()) and re.fullmatch(
                    r"\s*(?:(?:static|const|volatile|register|struct|enum|union|unsigned|signed)\s+)*"
                    r"[A-Za-z_]\w*(?:\s*\*+\s*|\s+)", prefix) is not None \
                    and prefix.split()[0] not in C_KEYWORDS
                before = prev_char(code, m.start())
                # "(x = f())" is used at once; "*x = v" writes through x,
                # which reads x itself.
                in_expr = before == "(" or (
                    before == "*" and not is_operand_end(
                        prev_char(code, code.rfind("*", 0, m.start()))))

                if not is_assign or in_expr:
                    if is_decl and not is_assign:
                        continue  # "int x;" -- declaration without a value
                    pending = None  # any other occurrence is a read
                    continue

                eq = code.find("=", m.end())
                semi = code.find(";", eq)
                rhs = code[eq + 1:semi]
                call = called_function(rhs)
                if re.search(rf"(?<![\w.])\b{re.escape(name)}\b", rhs):
                    pending = None  # x = f(x): the old value is read first

                if is_decl:
                    # Initial value: overwriting a constant initialiser is
                    # normal; an initialiser that is a call must be checked.
                    pending = (m.start(), rhs, call) if call else None
                    continue

                if pending is not None:
                    p_off, p_rhs, p_call = pending
                    between = code[p_off:m.start()]
                    blk = src.innermost_block(m.start())
                    contains = blk is None or blk[0] < p_off < blk[1]
                    diverges = re.search(r"\b(?:break|return|goto|continue|case|default|else)\b",
                                         between)
                    if contains and not diverges and not loop_may_read(p_off, name) \
                            and (p_call or STATUS_NAME.fullmatch(name)):
                        what = f"the result of {p_call}()" if p_call else \
                            f"the value {p_rhs.strip()}"
                        sev = "high" if p_call and CRITICAL_VERB.search(p_call) else "medium"
                        yield Hit(m.start(), sev, "overwritten-status",
                                  f"'{name}' holds {what} from line "
                                  f"{src.line_of(p_off)}, but is overwritten here "
                                  "before anything checks it.")
                pending = (m.start(), rhs, call)

            if pending is not None and pending[2] and not loop_may_read(pending[0], name) \
                    and not re.search(r"\bgoto\b", code[pending[0]:body_end]):
                p_off, _, p_call = pending
                sev = "high" if CRITICAL_VERB.search(p_call) else "medium"
                yield Hit(p_off, sev, "unchecked-result",
                          f"The result of {p_call}() is stored in '{name}' but "
                          f"'{name}' is never read afterwards.")


def check_suppressions(src, dev_re):
    """Analyser suppressions with no deviation reference.

    Hide:    x = a + b; /* cppcheck-suppress misra-c2012-10.4 */
             #pragma GCC diagnostic ignored "-Wconversion"
    Why:     MISRA Compliance:2020 requires a deviation record. A bare
             suppression is a hidden finding.
    Allowed: the same suppression with a deviation reference in the comment
             itself or in the DEVIATION_LOOKBACK lines above it.
    """
    for offset, comment in src.comments:
        if not SUPPRESSION.search(comment):
            continue
        if dev_re.search(comment) or has_deviation(src, src.line_of(offset), dev_re):
            continue
        yield Hit(offset, "high", "suppression-without-deviation",
                  "A tool suppression comment has no deviation reference.")

    # Pragmas are code, not comments, so search the blanked code. String
    # contents are blanked too, so the pragma's quoted warning name is lost,
    # but the snippet shows the original line.
    for m in PRAGMA_SUPPRESSION.finditer(src.code):
        line = src.line_of(m.start())
        if has_deviation(src, line, dev_re):
            continue
        yield Hit(m.start() + len(m.group(0)) - len(m.group(0).lstrip()), "high",
                  "suppression-without-deviation",
                  "A #pragma switches a diagnostic off with no deviation reference.")


# Every per-file check. To add a check, write a generator with the same signature, add it here and
# add a rule for each (check id, severity) it yields to builtin/fwlens-hides.yaml.
CHECKS = [
    check_arithmetic_casts,
    check_discarded_returns,
    check_pointer_casts,
    check_unsigned_invariant,
    check_index_underflow,
    check_infinite_loops,
    check_empty_branches,
    check_dummy_uses,
    check_volatile_locals,
    check_allocators,
    check_banned_wrappers,
    check_result_flow,
    check_suppressions,
]


def analyse(sf: SourceFile, deviation_pattern: str = DEFAULT_DEVIATION) -> list[Finding]:
    """Every hidden finding in one file, sorted by line. Cached on the SourceFile, so the rules that
    share a file run the checks once."""
    cache = sf.__dict__.setdefault("_hidden_findings", {})
    if deviation_pattern not in cache:
        src = Source(sf)
        dev_re = re.compile(deviation_pattern, re.IGNORECASE)
        found = {Finding(src.line_of(h.offset), h.severity, h.check, h.message)
                 for check in CHECKS for h in check(src, dev_re)}
        cache[deviation_pattern] = sorted(found)
    return cache[deviation_pattern]


@source_check("hidden_finding")
def hidden_finding(sf: SourceFile, params: dict):
    """Findings of one check id (``check``), optionally of one ``severity``."""
    for f in analyse(sf, params.get("deviation_pattern", DEFAULT_DEVIATION)):
        if f.check == params["check"] and params.get("severity") in (None, f.severity):
            yield f.line, sf.line_text(f.line)
