"""
Checks for the BARR-C:2018 Embedded C Coding Standard: naming, layout and a few declaration and
statement rules that MISRA C does not cover. Source checks read the text of a file, detectors
read the syntax tree. Layout checks are approximate, so the rules that use them are partial.
"""

from __future__ import annotations

import re

from fwlens.standards.astutil import (
    binary_operator,
    canon,
    const_int,
    for_parts,
    is_constant_expr,
    is_float_type,
    kids,
    kind_name,
    peel,
    tokens,
    unary_operator,
)
from fwlens.standards.engines import detector, source_check, system_check
from fwlens.standards.essential import ASSIGN_ARITH, essential, is_nonneg_constant


def _hit(ctx, cursor):
    line = cursor.location.line
    return line, ctx.line_text(line)


# --- naming -------------------------------------------------------------------------------------------------

_PREFIX = re.compile(r"^g?(?:pp|p)?[bh]?_")


def _is_global(cursor) -> bool:
    parent = cursor.semantic_parent
    return parent is not None and kind_name(parent) == "TRANSLATION_UNIT"


@detector("variable_naming", "VAR_DECL")
def variable_naming(ctx, cursor, params):
    """7.1: names of variables. ``check`` picks the property: length, min_length, lowercase, underscore_start,
    global_prefix, pointer_prefix, bool_prefix."""
    name = cursor.spelling
    if not name:
        return
    check = params.get("check", "lowercase")
    t = canon(cursor.type)
    kind = t.kind.name
    bad = False
    if check == "length":
        bad = len(name) > int(params.get("limit", 31))
    elif check == "min_length":
        bad = len(name) < int(params.get("limit", 3))
    elif check == "lowercase":
        bad = name != name.lower() and not t.is_const_qualified()
    elif check == "underscore_start":
        bad = name.startswith("_")
    elif check == "global_prefix":
        bad = _is_global(cursor) and not t.is_const_qualified() and not re.match(r"^g(?:pp|p)?[bh]?_", name)
    elif check == "pointer_prefix":
        if kind == "POINTER" and canon(t.get_pointee()).kind.name not in ("FUNCTIONPROTO", "FUNCTIONNOPROTO"):
            want = "pp" if canon(t.get_pointee()).kind.name == "POINTER" else "p"
            bad = not re.match(rf"^g?{want}[bh]?_", name)
    elif check == "bool_prefix":
        bad = kind == "BOOL" and not re.match(r"^g?(?:pp|p)?b_", name)
    if bad:
        yield _hit(ctx, cursor)


@detector("function_naming", "FUNCTION_DECL")
def function_naming(ctx, cursor, params):
    """6.1: names of functions defined in the file. ``check``: lowercase, length, underscore_start, module_prefix."""
    if not cursor.is_definition():
        return
    name = cursor.spelling
    check = params.get("check", "lowercase")
    if check == "lowercase":
        bad = name != name.lower()
    elif check == "length":
        bad = len(name) > int(params.get("limit", 31))
    elif check == "underscore_start":
        bad = name.startswith("_")
    else:
        stem = ctx.tu_path.stem.lower()
        bad = (name != "main" and cursor.linkage.name == "EXTERNAL" and not name.lower().startswith(stem + "_"))
    if bad:
        yield _hit(ctx, cursor)


@detector("type_naming", "TYPEDEF_DECL")
def type_naming(ctx, cursor, params):
    """5.1.a: typedef names are lowercase words ending in _t."""
    if not re.match(r"^[a-z][a-z0-9_]*_t$", cursor.spelling):
        yield _hit(ctx, cursor)


@detector("tagged_type_without_typedef", "STRUCT_DECL", "UNION_DECL", "ENUM_DECL")
def tagged_type_without_typedef(ctx, cursor, params):
    """5.1.b: a structure, union or enumeration defined at file scope is also named through a typedef."""
    if not cursor.is_definition() or not _is_global(cursor):
        return
    typedefs = ctx.state.get("typedef_targets")
    if typedefs is None:
        typedefs = set()
        for c in ctx.top_level:
            if kind_name(c) == "TYPEDEF_DECL":
                decl = c.underlying_typedef_type.get_canonical().get_declaration()
                if decl is not None:
                    typedefs.add(decl.get_usr())
        ctx.state["typedef_targets"] = typedefs
    if cursor.get_usr() not in typedefs:
        yield _hit(ctx, cursor)


# --- data types ---------------------------------------------------------------------------------------------

@detector("signed_bit_field", "FIELD_DECL")
def signed_bit_field(ctx, cursor, params):
    """5.3.a: a bit-field declared with a signed integer type."""
    if cursor.is_bitfield() and canon(cursor.type).kind.name in ("SCHAR", "CHAR_S", "SHORT", "INT", "LONG", "LONGLONG"):
        yield _hit(ctx, cursor)


@detector("bitwise_signed_operand", "BINARY_OPERATOR", "COMPOUND_ASSIGNMENT_OPERATOR", "UNARY_OPERATOR")
def bitwise_signed_operand(ctx, cursor, params):
    """5.3.b: a bitwise or shift operator applied to a signed integer."""
    if kind_name(cursor) == "UNARY_OPERATOR":
        if unary_operator(cursor) != "~":
            return
        operands = kids(cursor)[:1]
    else:
        op = binary_operator(cursor)
        op = ASSIGN_ARITH.get(op, op)
        if op not in ("&", "|", "^", "<<", ">>"):
            return
        operands = kids(cursor)[:2]
    for operand in operands:
        e = essential(operand)
        if e is not None and e.cat == "signed" and not is_nonneg_constant(e):
            yield _hit(ctx, cursor)
            return


@detector("float_equality", "BINARY_OPERATOR")
def float_equality(ctx, cursor, params):
    """5.4.b: floating-point values compared with == or !=."""
    if binary_operator(cursor) in ("==", "!=") and any(is_float_type(peel(k).type) for k in kids(cursor)[:2]):
        yield _hit(ctx, cursor)


# --- statements and expressions -----------------------------------------------------------------------------

@detector("constant_on_right", "BINARY_OPERATOR")
def constant_on_right(ctx, cursor, params):
    """8.6.a: in an equality test the constant is written on the left."""
    if binary_operator(cursor) not in ("==", "!="):
        return
    parts = kids(cursor)
    if len(parts) == 2 and is_constant_expr(parts[1]) and not is_constant_expr(parts[0]):
        yield _hit(ctx, cursor)


@detector("logical_operand_parens", "BINARY_OPERATOR")
def logical_operand_parens(ctx, cursor, params):
    """1.4.b: an operand of && or || that is itself an expression is written in parentheses."""
    op = binary_operator(cursor)
    if op not in ("&&", "||"):
        return
    for operand in kids(cursor)[:2]:
        node = peel(operand, implicit_only=True)
        name = kind_name(node)
        if name == "BINARY_OPERATOR" and binary_operator(node) == op:
            continue
        if name in ("BINARY_OPERATOR", "CONDITIONAL_OPERATOR"):
            yield _hit(ctx, cursor)
            return


@detector("if_else_nesting", "IF_STMT")
def if_else_nesting(ctx, cursor, params):
    """8.2.b: if statements nested deeper than two levels."""
    limit = int(params.get("limit", 2))
    depth, child = 0, cursor
    for parent in reversed(ctx.parents):
        if kind_name(parent) == "IF_STMT":
            if child not in kids(parent)[2:]:       # a chain link (else if) is not a new level
                depth += 1
        elif kind_name(parent) == "FUNCTION_DECL":
            break
        child = parent
    if depth >= limit:
        yield _hit(ctx, cursor)


def _written_number(node) -> bool:
    toks = tokens(node)
    return bool(toks) and toks[0][:1].isdigit()


@detector("loop_magic_number", "FOR_STMT")
def loop_magic_number(ctx, cursor, params):
    """8.4.a: a number other than 0 or 1 written in a for loop's initialisation or test."""
    init, cond, _inc, _body = for_parts(cursor)
    for clause in (init, cond):
        if clause is None:
            continue
        for node in clause.walk_preorder():
            if kind_name(node) == "INTEGER_LITERAL" and _written_number(node) and const_int(node) not in (0, 1):
                yield _hit(ctx, cursor)
                return


@detector("infinite_loop_form", "WHILE_STMT", "DO_STMT")
def infinite_loop_form(ctx, cursor, params):
    """8.4.c: an endless loop written as while (1) or do ... while (1) instead of for (;;)."""
    parts = kids(cursor)
    cond = parts[0] if kind_name(cursor) == "WHILE_STMT" else (parts[-1] if len(parts) > 1 else None)
    if cond is not None and is_constant_expr(cond) and const_int(cond) not in (None, 0):
        yield _hit(ctx, cursor)


@detector("pointer_uninitialised", "VAR_DECL")
def pointer_uninitialised(ctx, cursor, params):
    """7.2.d: a local pointer declared without an initial value (use NULL when there is no address yet)."""
    parent = cursor.semantic_parent
    if parent is None or kind_name(parent) != "FUNCTION_DECL" or cursor.storage_class.name in ("STATIC", "EXTERN"):
        return
    if canon(cursor.type).kind.name == "POINTER" and not any(c.kind.is_expression() for c in cursor.get_children()):
        yield _hit(ctx, cursor)


# --- source text: layout ------------------------------------------------------------------------------------

def _lines(text: str):
    return enumerate(text.split("\n"), 1)


@source_check("line_too_long")
def line_too_long(sf, params):
    limit = int(params.get("limit", 80))
    for n, line in _lines(sf.raw):
        if len(line.rstrip("\r").expandtabs(4)) > limit:
            yield n, line.strip()


@source_check("tab_character")
def tab_character(sf, params):
    for n, line in _lines(sf.raw):
        if "\t" in line:
            yield n, line.strip()


@source_check("crlf_line_ending")
def crlf_line_ending(sf, params):
    for n, line in _lines(sf.raw):
        if line.endswith("\r"):
            yield n, line.strip()
            return                                       # one finding per file is enough


@source_check("opening_brace_same_line")
def opening_brace_same_line(sf, params):
    """1.3.b: the brace of a function or control statement is on the line below it."""
    for n, line in _lines(sf.code):
        if re.search(r"(?:\)|\belse|\bdo)\s*\{", line) and not line.lstrip().startswith("#"):
            yield n, sf.line_text(n)


@source_check("several_statements_per_line")
def several_statements_per_line(sf, params):
    for n, line in _lines(sf.code):
        if line.lstrip().startswith("#"):
            continue
        stripped = re.sub(r"\bfor\s*\([^)]*\)", "for()", line)
        if re.search(r";[ \t]*[^\s;})\\/]", stripped):
            yield n, sf.line_text(n)


@source_check("no_end_of_file_comment")
def no_end_of_file_comment(sf, params):
    """3.3.c: the last non-blank line of the file is a comment."""
    rows = [(n, line) for n, line in _lines(sf.raw) if line.strip()]
    if rows:
        n, line = rows[-1]
        if not re.match(r"\s*(?:/\*|//)", line):
            yield n, line.strip()


@source_check("indent_not_multiple_of_four")
def indent_not_multiple_of_four(sf, params):
    """3.4.a: a statement starts at a multiple of four spaces. Continuation lines are not checked."""
    previous = ";"
    for n, line in _lines(sf.code):
        if not line.strip():
            continue
        stripped = line.strip()
        if previous.endswith((";", "{", "}")) and not stripped.startswith("#") and "\t" not in line[:len(line) - len(line.lstrip())]:
            indent = len(line) - len(line.lstrip(" "))
            if indent % 4:
                yield n, sf.line_text(n)
        previous = stripped if not stripped.startswith("#") else previous
        if stripped.startswith("#"):
            previous = ";"


@source_check("space_around_operators")
def space_around_operators(sf, params):
    """3.1.b and 3.1.c: assignment and binary operators have a space on both sides (approximate)."""
    for n, line in _lines(sf.code):
        s = line.strip()
        if not s or s.startswith("#") or s.startswith("for"):
            continue
        s = re.sub(r"->|\+\+|--|<<=|>>=|<<|>>", "  ", s)
        if re.search(r"[\w)\]](?:[-+*/%&|^]?=(?!=)|==|!=|<=|>=|&&|\|\|)[\w(]", s) or \
                re.search(r"[\w)\]](?:[-+/%])[\w(]", s):
            yield n, sf.line_text(n)


@source_check("space_after_comma")
def space_after_comma(sf, params):
    for n, line in _lines(sf.code):
        if not line.lstrip().startswith("#") and re.search(r",[^\s]", line):
            yield n, sf.line_text(n)


@source_check("space_before_semicolon")
def space_before_semicolon(sf, params):
    for n, line in _lines(sf.code):
        s = line.strip()
        if s.startswith("#") or s.startswith("for") or s == ";":
            continue
        if re.search(r"\S[ \t]+;", s) and not re.search(r"\)[ \t]+;$", s):
            yield n, sf.line_text(n)


@source_check("space_inside_parentheses")
def space_inside_parentheses(sf, params):
    for n, line in _lines(sf.code):
        if not line.lstrip().startswith("#") and (re.search(r"\([ \t]+\S", line) or re.search(r"\S[ \t]+\)", line)):
            yield n, sf.line_text(n)


@source_check("space_around_member_access")
def space_around_member_access(sf, params):
    for n, line in _lines(sf.code):
        if not line.lstrip().startswith("#") and re.search(r"\w[ \t]+(?:->|\.)[ \t]*\w|\w[ \t]*(?:->|\.)[ \t]+\w", line):
            yield n, sf.line_text(n)


# --- source text: modules and headers ---------------------------------------------------------------------

@source_check("module_file_name")
def module_file_name(sf, params):
    """4.1.a: file names use lowercase letters, digits and underscores."""
    if not re.match(r"^[a-z0-9_]+\.(?:c|h)$", sf.path.name):
        yield 1, sf.path.name


@source_check("main_file_name")
def main_file_name(sf, params):
    """4.1.d: the file that defines main has "main" in its name."""
    if sf.path.suffix == ".c" and re.search(r"\bint\s+main\s*\(", sf.code) and "main" not in sf.path.stem.lower():
        yield sf.line_of(re.search(r"\bint\s+main\s*\(", sf.code).start()), sf.path.name


@source_check("absolute_include_path")
def absolute_include_path(sf, params):
    for line, name, rest in sf.directives("text"):
        if name == "include" and re.match(r'[<"](?:/|[A-Za-z]:[\\/]|\\)', rest):
            yield line, sf.line_text(line)


@source_check("include_source_file")
def include_source_file(sf, params):
    for line, name, rest in sf.directives("text"):
        if name == "include" and re.match(r'[<"][^>"]*\.c[>"]', rest):
            yield line, sf.line_text(line)


@source_check("header_extern_variable")
def header_extern_variable(sf, params):
    """4.2.c.i: a header that declares a variable with extern."""
    if sf.path.suffix.lower() not in (".h", ".hpp"):
        return
    for m in re.finditer(r"^[ \t]*extern\b([^;(){}]*);", sf.code, re.MULTILINE):
        if not m.group(1).strip().startswith('"'):
            yield sf.line_of(m.start()), sf.line_text(sf.line_of(m.start()))


@source_check("own_header_not_included")
def own_header_not_included(sf, params):
    """4.3.c: a source file includes the header that declares its own functions."""
    header = sf.path.with_suffix(".h")
    if sf.path.suffix != ".c" or not header.exists():
        return
    names = {rest.strip('<>" ').split("/")[-1] for _, n, rest in sf.directives("text") if n == "include"}
    if header.name not in names:
        yield 1, sf.path.name


# --- source text: keywords and macros ---------------------------------------------------------------------

def _macros(sf):
    for line, name, rest in sf.directives("code"):
        if name == "define":
            m = re.match(r"([A-Za-z_]\w*)(\(([^)]*)\))?\s*(.*)", rest, re.DOTALL)
            if m:
                params = [p.strip() for p in (m.group(3) or "").split(",") if p.strip()] if m.group(2) else None
                yield line, m.group(1), params, m.group(4)


@source_check("macro_parameter_used_twice")
def macro_parameter_used_twice(sf, params):
    """6.3.b.iii: a function-like macro uses each parameter at most once."""
    for line, _name, plist, body in _macros(sf):
        if plist and any(len(re.findall(rf"\b{re.escape(p)}\b", body)) > 1 for p in plist if p != "..."):
            yield line, sf.line_text(line)


@source_check("macro_transfers_control")
def macro_transfers_control(sf, params):
    """6.3.b.iv: a macro that returns or jumps."""
    for line, _name, _plist, body in _macros(sf):
        if re.search(r"\b(?:return|goto)\b", body):
            yield line, sf.line_text(line)


@source_check("macro_name_has_lowercase")
def macro_name_has_lowercase(sf, params):
    """6.1.f: macro names are uppercase."""
    for line, name, _plist, _body in _macros(sf):
        if name != name.upper() and not name.startswith("__"):
            yield line, sf.line_text(line)


# --- whole project --------------------------------------------------------------------------------------------

@system_check("header_variable_definition")
def header_variable_definition(records, params):
    """4.2.c.ii: a header that allocates storage for a variable."""
    seen = set()
    for r in records:
        if r["what"] == "var" and r["defn"] and r["file"].lower().endswith((".h", ".hpp")) and r["linkage"] != "NONE":
            key = (r["file"], r["line"])
            if key not in seen:
                seen.add(key)
                try:
                    with open(r["file"], encoding="utf-8", errors="replace") as fh:
                        text = fh.read().splitlines()[r["line"] - 1].strip()
                except OSError:
                    text = ""
                yield r["file"], r["line"], text, None


@system_check("external_only_used_in_own_unit")
def external_only_used_in_own_unit(records, params):
    """1.8.a and 6.2.e: a function with external linkage that no other translation unit uses should be static."""
    from fwlens.standards.system import _entities, _hit as system_hit
    for usr, decls in _entities(records).items():
        defs = [d for d in decls if d["what"] == "func" and d["defn"] and d["linkage"] == "EXTERNAL"]
        if not defs or defs[0]["name"] == "main":
            continue
        used_in = records.refs.get(("usr", usr), set())
        if used_in and used_in <= {defs[0]["tu"]}:
            yield system_hit(defs[0])
