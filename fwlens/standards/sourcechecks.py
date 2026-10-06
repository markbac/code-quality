"""
Text-level checks: the source and diagnostic engines and the named source checks.

Source text is lexed into four views that keep every offset and newline, so a hit's line number
is the line in the file: ``raw`` (untouched), ``code`` (comments and the inside of string and
character literals blanked), ``text`` (comments blanked, literals kept) and ``comments``
(only comments kept). Directives are read from logical lines, with backslash continuations
joined.
"""

from __future__ import annotations

import bisect
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from fwlens.identity import project_root
from fwlens.standards.engines import SOURCE_CHECKS, Hit, source_check
from fwlens.standards.rules import Rule

_LEX = re.compile(
    r'"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'|//(?:\\\n|[^\n])*|/\*.*?\*/', re.DOTALL)


def _blank(text: str) -> str:
    return "".join(c if c == "\n" else " " for c in text)


@dataclass
class SourceFile:
    path: Path
    raw: str
    code: str = ""
    text: str = ""
    comments: str = ""
    _newlines: list[int] = field(default_factory=list)

    @classmethod
    def read(cls, path: Path) -> SourceFile | None:
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
        return cls.from_text(path, raw)

    @classmethod
    def from_text(cls, path: Path, raw: str) -> SourceFile:
        """Build the four views. Each is the raw text with some of its lexical parts blanked."""
        def view(blank_comments: bool, blank_literals: bool, blank_code: bool = False) -> str:
            out, last = [], 0
            for m in _LEX.finditer(raw):
                t = m.group(0)
                is_literal = t[0] in "\"'"
                out.append(_blank(raw[last:m.start()]) if blank_code else raw[last:m.start()])
                if is_literal:
                    out.append(_blank(t) if blank_code else t[0] + _blank(t[1:-1]) + t[-1] if blank_literals else t)
                else:
                    out.append(_blank(t) if blank_comments else t)
                last = m.end()
            out.append(_blank(raw[last:]) if blank_code else raw[last:])
            return "".join(out)

        sf = cls(path, raw, view(True, True), view(True, False), view(False, False, blank_code=True))
        sf._newlines = [i for i, c in enumerate(raw) if c == "\n"]
        return sf

    def line_of(self, offset: int) -> int:
        return bisect.bisect_left(self._newlines, offset) + 1

    def line_text(self, line: int) -> str:
        lines = self.raw.splitlines()
        return lines[line - 1].strip() if 0 < line <= len(lines) else ""

    def comment_blocks(self) -> Iterator[tuple[int, str]]:
        """(line, text) of every comment, delimiters included."""
        for m in _LEX.finditer(self.raw):
            if m.group(0)[0] not in "\"'":
                yield self.line_of(m.start()), m.group(0)

    def directives(self, view: str = "text") -> Iterator[tuple[int, str, str]]:
        """(line, name, rest) of every preprocessing directive; continuation lines are joined."""
        text = getattr(self, view)
        pos = 0
        n = len(text)
        while pos < n:
            end = text.find("\n", pos)
            end = n if end < 0 else end
            line_start = pos
            logical = text[pos:end]
            while logical.endswith("\\") and end < n:
                nxt = text.find("\n", end + 1)
                nxt = n if nxt < 0 else nxt
                logical = logical[:-1] + " " + text[end + 1:nxt]
                end = nxt
            stripped = logical.lstrip()
            if stripped.startswith("#"):
                body = stripped[1:].lstrip()
                m = re.match(r"([A-Za-z_]\w*)\s*(.*)", body, re.DOTALL)
                yield self.line_of(line_start + (len(logical) - len(stripped))), (m.group(1) if m else ""), \
                    (m.group(2).strip() if m else body)
            pos = end + 1


# --- engines ------------------------------------------------------------------------------------

def first_party_files(model, config) -> list[Path]:
    """First-party translation units plus the first-party headers they include."""
    root = project_root(config)
    scope = config.scope
    fp = {s.lower() for s in scope.first_party}
    other = {s.lower() for s in [*scope.sdk, *scope.third_party_lib]}

    def header_ok(path: Path) -> bool:
        try:
            parts = [p.lower() for p in path.relative_to(root).parts]
        except ValueError:
            return False
        if any(p in other for p in parts):
            return False
        return "." in fp or any(p in fp for p in parts)

    files = {Path(m.path) for m in model.first_party_modules()}
    for m in model.first_party_modules():
        for edge in m.all_include_edges:
            for p in edge:
                p = Path(p)
                if p.suffix.lower() in (".h", ".hpp") and header_ok(p):
                    files.add(p)
    return sorted(p for p in files if p.exists())


def run_source_engines(model, config, rules: list[Rule]) -> list[Hit]:
    if not rules:
        return []
    hits: list[Hit] = []
    for path in first_party_files(model, config):
        sf = SourceFile.read(path)
        if sf is None:
            continue
        hits.extend(source_hits(sf, rules))
    return hits


def source_hits(sf: SourceFile, rules: list[Rule]) -> list[Hit]:
    hits: list[Hit] = []
    for rule in rules:
        for check in rule.native_checks:
            if check.engine != "source":
                continue
            params = check.match
            if "pattern" in params:
                target = params.get("target", "code")
                if target not in ("code", "text", "raw", "comments"):
                    raise ValueError(f"{rule.key}: source target must be code, text, raw or comments")
                flags = re.MULTILINE | (re.IGNORECASE if params.get("ignore_case") else 0)
                for m in re.finditer(params["pattern"], getattr(sf, target), flags):
                    line = sf.line_of(m.start(1) if m.groups() and m.start(1) >= 0 else m.start())
                    hits.append(Hit(rule, sf.path, line, None, sf.line_text(line)))
            else:
                for line, text in SOURCE_CHECKS[params["name"]](sf, params) or ():
                    hits.append(Hit(rule, sf.path, line, None, text))
    return hits


def _wanted_options(match: dict) -> set[str]:
    opts = match.get("option") or []
    opts = [opts] if isinstance(opts, str) else opts
    return {o if o.startswith("-W") else "-W" + o for o in opts}


def diagnostic_flags(rules: list[Rule]) -> list[str]:
    """The clang warning flags the diagnostic rules need switched on, in a stable order."""
    flags: list[str] = []
    for r in rules:
        for check in r.native_checks:
            if check.engine == "diagnostic":
                for f in [*sorted(_wanted_options(check.match)), *check.match.get("flags", [])]:
                    if f not in flags:
                        flags.append(f)
    return flags


def run_diagnostic_engine(path: Path, parsed, rules: list[Rule]) -> list[Hit]:
    """
    Report parse diagnostics in the main file that match a rule: by the warning option that
    produced them (``option``), by a regular expression over the message (``pattern``), or both.
    Errors count as warnings unless the rule says ``severity: error``.
    """
    if not rules:
        return []
    hits: list[Hit] = []
    main = str(path)
    for d in parsed.diagnostics:
        loc = d.location
        if loc.file is None or loc.file.name != main:
            continue
        sev = "error" if d.severity >= 3 else "warning" if d.severity == 2 else "note"
        for rule in rules:
            for check in rule.native_checks:
                if check.engine != "diagnostic":
                    continue
                m = check.match
                want = m.get("severity", "warning")
                if (want == "error" and sev != "error") or (want == "warning" and sev == "note"):
                    continue
                options = _wanted_options(m)
                if options and d.option not in options:
                    continue
                if "pattern" in m and not re.search(m["pattern"], d.spelling):
                    continue
                hits.append(Hit(rule, path, loc.line, None, d.spelling))
    return hits


# --- named source checks ---------------------------------------------------------------------------

_C_KEYWORDS = (
    "auto break case char const continue default do double else enum extern float for goto if inline int long "
    "register restrict return short signed sizeof static struct switch typedef union unsigned void volatile while "
    "_Bool _Complex _Imaginary _Alignas _Alignof _Atomic _Generic _Noreturn _Static_assert _Thread_local").split()
_RESERVED_MACROS = set(
    "NULL EOF errno assert offsetof defined BUFSIZ FILENAME_MAX FOPEN_MAX L_tmpnam TMP_MAX SEEK_SET SEEK_CUR SEEK_END "
    "EXIT_SUCCESS EXIT_FAILURE RAND_MAX MB_CUR_MAX CHAR_BIT CHAR_MIN CHAR_MAX SCHAR_MIN SCHAR_MAX UCHAR_MAX SHRT_MIN "
    "SHRT_MAX USHRT_MAX INT_MIN INT_MAX UINT_MAX LONG_MIN LONG_MAX ULONG_MAX LLONG_MIN LLONG_MAX ULLONG_MAX "
    "INT8_MAX INT16_MAX INT32_MAX INT64_MAX UINT8_MAX UINT16_MAX UINT32_MAX UINT64_MAX SIZE_MAX INTPTR_MAX "
    "FLT_MAX FLT_MIN FLT_EPSILON DBL_MAX DBL_MIN DBL_EPSILON HUGE_VAL INFINITY NAN va_start va_arg va_end va_copy "
    "bool true false static_assert noreturn alignas alignof stdin stdout stderr CLOCKS_PER_SEC "
    "__LINE__ __FILE__ __DATE__ __TIME__ __STDC__ __STDC_VERSION__ __func__".split())
_DIRECTIVES = {"if", "ifdef", "ifndef", "elif", "else", "endif", "include", "define", "undef", "line", "error", "pragma"}


@source_check("comment_markers")
def _comment_markers(sf: SourceFile, params):
    """3.1: the sequences /* and // inside a comment."""
    for line, text in sf.comment_blocks():
        body = text[2:-2] if text.startswith("/*") and text.endswith("*/") else text[2:]
        if "/*" in body or "//" in body:
            yield line, sf.line_text(line)


@source_check("line_splice_comment")
def _line_splice_comment(sf: SourceFile, params):
    """3.2: a // comment whose line ends in a backslash."""
    for line, text in sf.comment_blocks():
        if text.startswith("//") and "\\\n" in text:
            yield line, sf.line_text(line)


_ESCAPE = re.compile(r"\\(x[0-9A-Fa-f]+|[0-7]{1,3})")


@source_check("unterminated_escape")
def _unterminated_escape(sf: SourceFile, params):
    """4.1: octal and hexadecimal escape sequences must end the literal or be followed by another escape."""
    for m in re.finditer(r'"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'', sf.text):
        lit = m.group(0)
        body = lit[1:-1]
        for e in _ESCAPE.finditer(body):
            nxt = body[e.end():e.end() + 1]
            if nxt and nxt != "\\":
                yield sf.line_of(m.start()), sf.line_text(sf.line_of(m.start()))
                break


@source_check("include_not_first")
def _include_not_first(sf: SourceFile, params):
    """20.1: #include after code, which only directives and comments may precede."""
    seen_code = False
    for ln, raw in enumerate(sf.code.splitlines(), 1):
        s = raw.strip()
        if not s:
            continue
        if s.startswith("#"):
            logical = s[1:].lstrip()
            if logical.startswith("include") and seen_code:
                yield ln, sf.line_text(ln)
            continue
        seen_code = True


@source_check("reserved_macro_name")
def _reserved_macro_name(sf: SourceFile, params):
    """21.1: #define or #undef of a reserved identifier or a standard library macro name."""
    for line, name, rest in sf.directives():
        if name not in ("define", "undef"):
            continue
        m = re.match(r"([A-Za-z_]\w*)", rest)
        if not m:
            continue
        ident = m.group(1)
        if ident in _RESERVED_MACROS or re.match(r"_[A-Z_]", ident):
            yield line, sf.line_text(line)


@source_check("keyword_macro")
def _keyword_macro(sf: SourceFile, params):
    """20.4: a macro with the name of a keyword."""
    for line, name, rest in sf.directives():
        m = re.match(r"([A-Za-z_]\w*)", rest)
        if name in ("define", "undef") and m and m.group(1) in _C_KEYWORDS:
            yield line, sf.line_text(line)


@source_check("invalid_directive")
def _invalid_directive(sf: SourceFile, params):
    """20.13: a line starting with # that is not a valid preprocessing directive."""
    for line, name, rest in sf.directives():
        if name and name not in _DIRECTIVES:
            yield line, sf.line_text(line)


@source_check("directive_balance")
def _directive_balance(sf: SourceFile, params):
    """20.14: #else, #elif and #endif must be in the file of the matching #if."""
    stack: list[int] = []
    for line, name, rest in sf.directives():
        if name in ("if", "ifdef", "ifndef"):
            stack.append(line)
        elif name in ("else", "elif", "endif"):
            if not stack:
                yield line, sf.line_text(line)
            elif name == "endif":
                stack.pop()
    for line in stack:
        yield line, sf.line_text(line)


@source_check("stringise_or_paste")
def _stringise_or_paste(sf: SourceFile, params):
    """20.10: the # and ## preprocessor operators in a macro definition."""
    for line, name, rest in sf.directives("code"):
        if name != "define":
            continue
        m = re.match(r"[A-Za-z_]\w*(\([^)]*\))?\s*(.*)", rest, re.DOTALL)
        if m and re.search(r"##|#\s*[A-Za-z_]", m.group(2)):
            yield line, sf.line_text(line)


@source_check("stringise_then_paste")
def _stringise_then_paste(sf: SourceFile, params):
    """20.11: a parameter after # that is immediately followed by ##."""
    for line, name, rest in sf.directives("code"):
        if name == "define" and re.search(r"(?<!#)#\s*[A-Za-z_]\w*\s*##", rest):
            yield line, sf.line_text(line)


@source_check("macro_param_parens")
def _macro_param_parens(sf: SourceFile, params):
    """20.7: each use of a macro parameter in the body must be parenthesised."""
    for line, name, rest in sf.directives("code"):
        if name != "define":
            continue
        m = re.match(r"[A-Za-z_]\w*\(([^)]*)\)\s*(.*)", rest, re.DOTALL)
        if not m:
            continue
        names = [p.strip() for p in m.group(1).split(",") if p.strip() and p.strip() != "..."]
        body = m.group(2)
        for p in names:
            for use in re.finditer(rf"(?<![\w#])({re.escape(p)})(?![\w])", body):
                before = body[:use.start()].rstrip()
                after = body[use.end():].lstrip()
                if before.endswith("#") or before.endswith("##") or after.startswith("##"):
                    continue
                enclosed = before[-1:] in ("(", ",") and after[:1] in (")", ",")
                if not enclosed:
                    yield line, sf.line_text(line)
                    break
            else:
                continue
            break


@source_check("missing_include_guard")
def _missing_include_guard(sf: SourceFile, params):
    """D4.10: a header must guard against being included twice."""
    if sf.path.suffix.lower() not in (".h", ".hpp"):
        return
    guard = None
    for line, name, rest in sf.directives("code"):
        if name == "pragma" and rest.strip() == "once":
            return
        if name == "ifndef" and guard is None:
            guard = rest.split()[0] if rest.split() else None
            continue
        if guard is not None:
            if name == "define" and rest.split() and rest.split()[0].split("(")[0] == guard:
                return
            break
        if name in ("ifndef", "if", "define", "include"):
            break
    yield 1, sf.line_text(1)


@source_check("macro_defined_unused")
def _macro_defined_unused(sf: SourceFile, params):
    """2.5: a macro defined in a source file and not mentioned again in it."""
    if sf.path.suffix.lower() in (".h", ".hpp"):
        return
    for line, name, rest in sf.directives("code"):
        if name != "define":
            continue
        m = re.match(r"([A-Za-z_]\w*)", rest)
        if not m:
            continue
        ident = m.group(1)
        if len(re.findall(rf"\b{re.escape(ident)}\b", sf.code)) == 1:
            yield line, sf.line_text(line)


_MACRO_HEAD = re.compile(r"([A-Za-z_]\w*)(?:\(([^)]*)\))?")


def _macros(sf: SourceFile):
    """(line, name, parameters or None, body) of each #define. A parameter list must touch the name."""
    for line, name, rest in sf.directives("code"):
        if name != "define":
            continue
        m = _MACRO_HEAD.match(rest)
        if not m:
            continue
        params = None if m.group(2) is None else [p.strip() for p in m.group(2).split(",") if p.strip()]
        yield line, m.group(1), params, rest[m.end():].strip()


_CODE_LINE = re.compile(
    r"^\s*(?:"
    r"(?:if|for|while|switch)\s*\(.*\)\s*\{?\s*$"
    r"|(?:else|do)\s*\{?\s*$"
    r"|return\b[^.!?]*;\s*$"
    r"|(?:break|continue)\s*;\s*$"
    r"|[\w\[\]\.\->\*]+\s*(?:=|\+=|-=|\|=|&=|<<=|>>=)[^=].*;\s*$"
    r"|[A-Za-z_]\w*\s*\([^)]*\)\s*;\s*$"
    r"|[A-Za-z_]\w*(?:\s+\**\s*[A-Za-z_]\w*)+\s*(?:=[^=].*)?;\s*$"
    r"|#\s*(?:include|define|if|ifdef|ifndef|endif|else|pragma)\b.*"
    r"|[{}]\s*$"
    r")")


@source_check("commented_out_code")
def _commented_out_code(sf: SourceFile, params):
    """D4.4: a comment that holds statements. Looks at lines, so prose that resembles code can trip it."""
    wanted = int(params.get("min_lines", 1))
    for line, text in sf.comment_blocks():
        body = text[2:-2] if text.startswith("/*") and text.endswith("*/") else text[2:]
        rows = [re.sub(r"^\s*\*+\s?", "", r) for r in body.splitlines()]
        hits = [r for r in rows if r.strip() and _CODE_LINE.match(r)
                and not re.match(r"^\s*[{}]\s*$", r)]
        braces = [r for r in rows if re.match(r"^\s*[{}]\s*$", r)]
        if len(hits) >= wanted or (hits and braces):
            yield line, sf.line_text(line)


_ASM = re.compile(r"(?<![\w.])(?:__asm__|__asm|asm)\b")


@source_check("asm_without_comment")
def _asm_without_comment(sf: SourceFile, params):
    """D4.2: assembly language used with no comment on the same line or the line before."""
    comment_lines = {sf.line_of(m.start()) for m in re.finditer(r"\S", sf.comments)}
    for m in _ASM.finditer(sf.code):
        line = sf.line_of(m.start())
        if line not in comment_lines and line - 1 not in comment_lines:
            yield line, sf.line_text(line)


@source_check("function_like_macro")
def _function_like_macro(sf: SourceFile, params):
    """D4.9: a function-like macro, which a function could often replace. Macros using # or ## are exempt."""
    for line, name, macro_params, body in _macros(sf):
        if macro_params is not None and not re.search(r"#|__VA_ARGS__", body) and body:
            yield line, sf.line_text(line)


@source_check("if_expression_not_boolean")
def _if_expression_not_boolean(sf: SourceFile, params):
    """20.8: the controlling expression of #if or #elif is a plain number other than 0 or 1."""
    for line, name, rest in sf.directives("code"):
        if name in ("if", "elif") and re.fullmatch(r"\(*\s*[-+]?\d+[uUlL]*\s*\)*", rest.strip()):
            if int(re.sub(r"[^\d]", "", rest) or 0) not in (0, 1) or rest.strip().startswith("-"):
                yield line, sf.line_text(line)


@source_check("macro_parameter_mixed_use")
def _macro_parameter_mixed_use(sf: SourceFile, params):
    """20.12: a parameter used as an operand of # or ## and also used on its own in the same macro."""
    for line, name, macro_params, body in _macros(sf):
        for p in macro_params or ():
            operand = re.search(rf"#\s*{re.escape(p)}\b|\b{re.escape(p)}\s*##|##\s*{re.escape(p)}\b", body)
            plain = [u for u in re.finditer(rf"(?<![\w#]){re.escape(p)}(?!\w)", body)
                     if not re.search(r"#\s*$", body[:u.start()]) and not re.match(r"\s*##", body[u.end():])]
            if operand and plain:
                yield line, sf.line_text(line)
                break


@source_check("macro_name_significance")
def _macro_name_significance(sf: SourceFile, params):
    """5.4: macro names that differ only after the 31st character (or the configured limit)."""
    limit = int(params.get("limit", 31))
    seen: dict[str, str] = {}
    for line, name, _, _ in _macros(sf):
        if len(name) > limit:
            head = name[:limit]
            if head in seen and seen[head] != name:
                yield line, sf.line_text(line)
            seen.setdefault(head, name)


@source_check("multi_statement_macro")
def _multi_statement_macro(sf: SourceFile, params):
    """A function-like macro with several statements that is not wrapped in do { } while (0)."""
    for line, name, macro_params, body in _macros(sf):
        if macro_params is not None and body.count(";") > 1 and not re.match(r"do\b", body):
            yield line, sf.line_text(line)


@source_check("macro_ends_with_semicolon")
def _macro_ends_with_semicolon(sf: SourceFile, params):
    for line, name, macro_params, body in _macros(sf):
        if body.endswith(";"):
            yield line, sf.line_text(line)


@source_check("macro_body_unparenthesised")
def _macro_body_unparenthesised(sf: SourceFile, params):
    """A macro whose body is an expression with operators and no enclosing parentheses."""
    for line, name, macro_params, body in _macros(sf):
        if not body or body.endswith(";") or re.match(r"(?:do|if|for|while|switch|\{|\"|\')", body):
            continue
        if re.search(r"[-+*/%&|^?]|<<|>>", body) and not (body.startswith("(") and body.endswith(")")):
            if re.fullmatch(r"[-+]?\s*[\w.]+", body):
                continue                        # a signed literal or a name
            yield line, sf.line_text(line)
