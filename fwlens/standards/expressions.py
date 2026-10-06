"""
Expression detectors: the essential type rules (MISRA C:2012 10.x), operator rules (12.x), side
effects (13.x) and literals (7.x). The essential type model is in fwlens.standards.essential and
stays silent where it cannot tell, so these detectors can miss a violation but should not invent
one.
"""

from __future__ import annotations

import re

from fwlens.standards.astutil import (
    binary_operator,
    canon,
    const_int,
    full_expression_root,
    int_literal_value,
    is_assignment_op,
    kids,
    kind_name,
    peel,
    side_effects,
    tokens,
    unary_operator,
    value_flows,
    value_unused,
)
from fwlens.standards.engines import detector, source_check
from fwlens.standards.essential import (
    ARITH,
    ASSIGN_ARITH,
    EQUALITY,
    LOGICAL,
    RELATIONAL,
    SHIFT,
    Ess,
    essential,
    from_type,
)

_ASSIGNMENT_KINDS = ("BINARY_OPERATOR", "COMPOUND_ASSIGNMENT_OPERATOR")


def _hit(ctx, cursor):
    line = cursor.location.line
    return line, ctx.line_text(line)


def _flows(ctx, cursor):
    for dest, expr in value_flows(cursor):
        if dest is None:
            function = ctx.enclosing("FUNCTION_DECL")
            if function is None:
                continue
            dest = function.result_type
        yield dest, expr


def _operator(cursor) -> str:
    return binary_operator(cursor) if kind_name(cursor) != "UNARY_OPERATOR" else unary_operator(cursor)


# --- MISRA 10.1: operands of the wrong essential type ------------------------------------------------------

_NUMERIC = {"signed", "unsigned", "floating"}
_PERMITTED = {
    "unary+": _NUMERIC, "unary-": {"signed", "floating"},
    "+": _NUMERIC | {"character"}, "-": _NUMERIC | {"character"},
    "*": _NUMERIC, "/": _NUMERIC, "%": {"signed", "unsigned"},
    "<": _NUMERIC | {"character", "enum"}, ">": _NUMERIC | {"character", "enum"},
    "<=": _NUMERIC | {"character", "enum"}, ">=": _NUMERIC | {"character", "enum"},
    "==": _NUMERIC | {"character", "enum", "boolean"}, "!=": _NUMERIC | {"character", "enum", "boolean"},
    "!": {"boolean"}, "&&": {"boolean"}, "||": {"boolean"},
    "<<": {"unsigned"}, ">>": {"unsigned"},
    "~": {"unsigned"}, "&": {"unsigned"}, "|": {"unsigned"}, "^": {"unsigned"},
    "++": _NUMERIC | {"character"}, "--": _NUMERIC | {"character"},
}


def _effective(e: Ess) -> str:
    """A non-negative signed constant counts as unsigned (and as the other category it is paired with)."""
    return "unsigned" if e.cat == "signed" and e.const and (e.value is None or e.value >= 0) else e.cat


def _inappropriate(op: str, e: Ess, *, operand_index: int = 0) -> bool:
    allowed = _PERMITTED.get(op)
    if allowed is None:
        return False
    if op in SHIFT and operand_index == 1:
        allowed = {"signed", "unsigned"}
    cat = _effective(e)
    if cat in allowed:
        return False
    if e.cat in allowed:
        return False
    return True


@detector("essential_operand_type", "BINARY_OPERATOR", "UNARY_OPERATOR", "COMPOUND_ASSIGNMENT_OPERATOR",
          "ARRAY_SUBSCRIPT_EXPR", "CONDITIONAL_OPERATOR")
def essential_operand_type(ctx, cursor, params):
    name = kind_name(cursor)
    operands = kids(cursor)
    reported = False
    if name == "ARRAY_SUBSCRIPT_EXPR" and len(operands) == 2:
        index = essential(operands[1])
        if index is not None and index.cat in ("boolean", "character", "enum"):
            reported = True
    elif name == "CONDITIONAL_OPERATOR" and operands:
        cond = essential(operands[0])
        if cond is not None and cond.cat != "boolean":
            reported = True
    else:
        op = _operator(cursor)
        if name == "COMPOUND_ASSIGNMENT_OPERATOR":
            op = ASSIGN_ARITH.get(op, "")
        elif name == "BINARY_OPERATOR" and (is_assignment_op(op) or op == ","):
            return
        elif name == "UNARY_OPERATOR" and op in ("+", "-"):
            op = "unary" + op
        if not op:
            return
        for i, operand in enumerate(operands[:2] if name != "UNARY_OPERATOR" else operands[:1]):
            e = essential(operand)
            if e is not None and _inappropriate(op, e, operand_index=i):
                reported = True
    if reported:
        yield _hit(ctx, cursor)


@detector("bitwise_boolean_operand", "BINARY_OPERATOR", "COMPOUND_ASSIGNMENT_OPERATOR")
def bitwise_boolean_operand(ctx, cursor, params):
    op = binary_operator(cursor)
    if op not in ("&", "|", "^", "&=", "|=", "^="):
        return
    for operand in kids(cursor)[:2]:
        inner = peel(operand)
        if kind_name(inner) == "BINARY_OPERATOR" and binary_operator(inner) in (RELATIONAL | EQUALITY | LOGICAL):
            yield _hit(ctx, cursor)
            return
        ess = essential(operand)
        if ess is not None and ess.cat == "boolean":
            yield _hit(ctx, cursor)
            return


# --- MISRA 10.2: character arithmetic ----------------------------------------------------------------------

@detector("character_arithmetic", "BINARY_OPERATOR")
def character_arithmetic(ctx, cursor, params):
    op = binary_operator(cursor)
    operands = kids(cursor)
    if op not in ("+", "-") or len(operands) != 2:
        return
    a, b = essential(operands[0]), essential(operands[1])
    if a is None or b is None:
        return
    chars = [x for x in (a, b) if x.cat == "character"]
    if not chars:
        return
    ints = {"signed", "unsigned"}
    if op == "+":
        ok = (a.cat == "character" and b.cat in ints) or (b.cat == "character" and a.cat in ints)
    else:
        ok = (a.cat == "character" and (b.cat in ints or b.cat == "character"))
    if not ok:
        yield _hit(ctx, cursor)


# --- MISRA 10.3, 10.6: assignment to a narrower or different category -----------------------------------

def _fits(value: int, dest: Ess) -> bool:
    bits = dest.bits
    if bits <= 0:
        return True
    if dest.cat == "unsigned":
        return 0 <= value < (1 << bits)
    if dest.cat == "signed":
        return -(1 << (bits - 1)) <= value < (1 << (bits - 1))
    return True


def _assignment_problem(dest: Ess, src: Ess, expr) -> bool:
    """Rule 10.3: a different category, or a narrower type of the same category."""
    if src.const and dest.cat in ("signed", "unsigned", "character"):
        if src.cat in ("signed", "unsigned", "character"):
            value = const_int(expr)
            return value is not None and not _fits(value, dest) if dest.cat != "character" else False
    if dest.cat == "boolean" and src.const:
        value = const_int(expr)
        return value not in (0, 1)
    if src.const and dest.cat == "floating" and src.cat in ("signed", "unsigned"):
        return False
    if dest.cat != src.cat:
        return True
    if dest.cat == "enum":
        return bool(dest.enum and src.enum and dest.enum != src.enum)
    if dest.cat in ("signed", "unsigned", "floating") and src.bits > dest.bits > 0:
        return True
    return False


@detector("assignment_category", "VAR_DECL", "BINARY_OPERATOR", "RETURN_STMT", "CALL_EXPR")
def assignment_category(ctx, cursor, params):
    for dest_type, expr in _flows(ctx, cursor):
        dest = from_type(dest_type)
        src = essential(expr)
        if dest is None or src is None:
            continue
        if _assignment_problem(dest, src, expr):
            yield _hit(ctx, expr)


@detector("composite_assigned_wider", "VAR_DECL", "BINARY_OPERATOR", "RETURN_STMT", "CALL_EXPR")
def composite_assigned_wider(ctx, cursor, params):
    for dest_type, expr in _flows(ctx, cursor):
        dest, src = from_type(dest_type), essential(expr)
        if dest is None or src is None or not src.composite:
            continue
        if dest.cat == src.cat and dest.cat in ("signed", "unsigned", "floating") and dest.bits > src.bits > 0:
            yield _hit(ctx, expr)


# --- MISRA 10.4, 10.7: operands that should match -----------------------------------------------------------

_USUAL = ARITH | RELATIONAL | EQUALITY


def _compatible(a: Ess, b: Ess) -> bool:
    if a.cat == b.cat:
        return a.cat != "enum" or not (a.enum and b.enum) or a.enum == b.enum
    ints = {"signed", "unsigned"}
    if a.cat in ints and b.cat in ints and (a.const or b.const):
        return True
    if (a.const and a.cat in ints and b.cat in ("character", "enum")) or \
            (b.const and b.cat in ints and a.cat in ("character", "enum")):
        return True                          # a constant against a character or enumeration is not judged
    return False


@detector("operands_same_category", "BINARY_OPERATOR", "CONDITIONAL_OPERATOR")
def operands_same_category(ctx, cursor, params):
    operands = kids(cursor)
    if kind_name(cursor) == "CONDITIONAL_OPERATOR":
        pair = operands[1:3]
    else:
        op = binary_operator(cursor)
        if op not in _USUAL:
            return
        pair = operands[:2]
    if len(pair) != 2:
        return
    a, b = essential(pair[0]), essential(pair[1])
    if a is None or b is None:
        return
    op = binary_operator(cursor) if kind_name(cursor) == "BINARY_OPERATOR" else ""
    if op in ("+", "-") and "character" in (a.cat, b.cat) and {a.cat, b.cat} <= {"character", "signed", "unsigned"}:
        return                               # character arithmetic is rule 10.2's business
    if not _compatible(a, b):
        yield _hit(ctx, cursor)


@detector("composite_wider_operand", "BINARY_OPERATOR")
def composite_wider_operand(ctx, cursor, params):
    op = binary_operator(cursor)
    operands = kids(cursor)
    if op not in _USUAL or len(operands) != 2:
        return
    a, b = essential(operands[0]), essential(operands[1])
    if a is None or b is None or a.cat != b.cat or a.cat not in ("signed", "unsigned", "floating"):
        return
    for mine, other in ((a, b), (b, a)):
        if mine.composite and other.bits > mine.bits > 0:
            yield _hit(ctx, cursor)
            return


# --- MISRA 10.5, 10.8: casts -----------------------------------------------------------------------------------

_CAST_OK = {
    ("signed", "unsigned"), ("unsigned", "signed"), ("signed", "floating"), ("unsigned", "floating"),
    ("floating", "signed"), ("floating", "unsigned"), ("floating", "floating"),
}


def _cast_operand(cursor):
    operands = [k for k in kids(cursor) if kind_name(k) != "TYPE_REF"]
    return operands[-1] if operands else None


@detector("cast_inappropriate_type", "CSTYLE_CAST_EXPR")
def cast_inappropriate_type(ctx, cursor, params):
    operand = _cast_operand(cursor)
    if operand is None:
        return
    dest, src = from_type(cursor.type), essential(operand)
    if dest is None or src is None:
        return
    if src.cat == dest.cat:
        if dest.cat == "enum" and dest.enum and src.enum and dest.enum != src.enum:
            yield _hit(ctx, cursor)
        return
    if (src.cat, dest.cat) in _CAST_OK:
        return
    if src.const and src.cat in ("signed", "unsigned") and dest.cat in ("character", "boolean"):
        return
    yield _hit(ctx, cursor)


@detector("composite_cast_wider", "CSTYLE_CAST_EXPR")
def composite_cast_wider(ctx, cursor, params):
    operand = _cast_operand(cursor)
    if operand is None:
        return
    dest, src = from_type(cursor.type), essential(operand)
    if dest is None or src is None or not src.composite:
        return
    if dest.cat != src.cat or dest.bits > src.bits > 0:
        if dest.cat != "boolean":
            yield _hit(ctx, cursor)


# --- MISRA 12.x: operators ------------------------------------------------------------------------------------

_GROUP = {"*": "mul", "/": "mul", "%": "mul", "+": "add", "-": "add", "<<": "shift", ">>": "shift",
          "<": "rel", ">": "rel", "<=": "rel", ">=": "rel", "==": "eq", "!=": "eq",
          "&": "band", "^": "bxor", "|": "bor", "&&": "and", "||": "or"}


@detector("implicit_precedence", "BINARY_OPERATOR")
def implicit_precedence(ctx, cursor, params):
    op = binary_operator(cursor)
    group = _GROUP.get(op)
    if group is None:
        return
    for operand in kids(cursor):
        inner = peel(operand, implicit_only=True)       # a PAREN_EXPR stops the peel: it is explicit
        if kind_name(inner) != "BINARY_OPERATOR":
            continue
        inner_group = _GROUP.get(binary_operator(inner))
        if inner_group is None or inner_group == group:
            continue
        if group in ("and", "or") and inner_group in ("rel", "eq"):
            continue                                    # a < b && c < d is not judged
        if group in ("rel", "eq") and inner_group in ("add", "mul", "shift"):
            continue                                    # a + 1 < b is not judged
        yield _hit(ctx, cursor)
        return


@detector("comma_operator", "BINARY_OPERATOR")
def comma_operator(ctx, cursor, params):
    if binary_operator(cursor) == ",":
        yield _hit(ctx, cursor)


@detector("shift_range", "BINARY_OPERATOR", "COMPOUND_ASSIGNMENT_OPERATOR")
def shift_range(ctx, cursor, params):
    op = binary_operator(cursor)
    if op not in ("<<", ">>", "<<=", ">>="):
        return
    operands = kids(cursor)
    if len(operands) != 2:
        return
    amount = const_int(operands[1])
    left = essential(operands[0])
    if amount is None or left is None or left.bits <= 0:
        return
    if amount < 0 or amount >= left.bits:
        yield _hit(ctx, cursor)


@detector("constant_wraparound", "BINARY_OPERATOR")
def constant_wraparound(ctx, cursor, params):
    op = binary_operator(cursor)
    operands = kids(cursor)
    if op not in ("+", "-", "*", "<<") or len(operands) != 2:
        return
    ess = from_type(cursor.type)
    if ess is None or ess.cat != "unsigned" or ess.bits <= 0:
        return
    a, b = const_int(operands[0]), const_int(operands[1])
    if a is None or b is None:
        return
    try:
        result = {"+": a + b, "-": a - b, "*": a * b, "<<": a << b if 0 <= b < 128 else a}[op]
    except OverflowError:
        return
    if not 0 <= result < (1 << ess.bits):
        yield _hit(ctx, cursor)


@detector("sizeof_array_parameter", "UNARY_EXPR")
def sizeof_array_parameter(ctx, cursor, params):
    toks = tokens(cursor)
    if not toks or toks[0] != "sizeof":
        return
    for operand in kids(cursor):
        ref = peel(operand)
        if kind_name(ref) == "DECL_REF_EXPR" and ref.referenced is not None \
                and kind_name(ref.referenced) == "PARM_DECL" \
                and ref.referenced.type.kind.name in ("CONSTANTARRAY", "INCOMPLETEARRAY", "VARIABLEARRAY"):
            yield _hit(ctx, cursor)
            return


# --- MISRA 13.x: side effects ----------------------------------------------------------------------------------

@detector("init_list_side_effects", "INIT_LIST_EXPR")
def init_list_side_effects(ctx, cursor, params):
    if ctx.parents and kind_name(ctx.parents[-1]) == "INIT_LIST_EXPR":
        return                               # reported once, for the outermost list
    effects = side_effects(cursor)
    if effects:
        yield _hit(ctx, effects[0])


@detector("increment_with_side_effects", "UNARY_OPERATOR")
def increment_with_side_effects(ctx, cursor, params):
    if unary_operator(cursor) not in ("++", "--"):
        return
    root = full_expression_root(ctx, cursor)
    others = [n for n in side_effects(root) if n != cursor]
    if others:
        yield _hit(ctx, cursor)


@detector("assignment_result_used", "BINARY_OPERATOR", "COMPOUND_ASSIGNMENT_OPERATOR")
def assignment_result_used(ctx, cursor, params):
    if kind_name(cursor) == "BINARY_OPERATOR" and not is_assignment_op(binary_operator(cursor)):
        return
    if not value_unused(ctx, cursor):
        yield _hit(ctx, cursor)


@detector("logical_rhs_side_effects", "BINARY_OPERATOR")
def logical_rhs_side_effects(ctx, cursor, params):
    if binary_operator(cursor) not in LOGICAL:
        return
    operands = kids(cursor)
    if len(operands) == 2 and side_effects(operands[1]):
        yield _hit(ctx, cursor)


@detector("sizeof_side_effects", "UNARY_EXPR")
def sizeof_side_effects(ctx, cursor, params):
    toks = tokens(cursor)
    if toks and toks[0] == "sizeof" and any(side_effects(k) for k in kids(cursor)):
        yield _hit(ctx, cursor)


# --- MISRA 7.x: literals ----------------------------------------------------------------------------------------

_UNSIGNED = {"UCHAR", "USHORT", "UINT", "ULONG", "ULONGLONG", "UINT128"}


@detector("unsigned_literal_suffix", "INTEGER_LITERAL")
def unsigned_literal_suffix(ctx, cursor, params):
    toks = tokens(cursor)
    if len(toks) != 1 or not toks[0][:1].isdigit() or int_literal_value(cursor) is None:
        return
    if canon(cursor.type).kind.name in _UNSIGNED and not re.search(r"[uU]", re.sub(r"^0[xXbB]", "", toks[0])):
        yield _hit(ctx, cursor)


_OCTAL = re.compile(r"(?<![\w.])0[0-7]+(?![\w.])")
_NUMBER = re.compile(r"(?<![\w.])\d[\w.]*")


def _skip_line(sf, offset: int) -> bool:
    start = sf.code.rfind("\n", 0, offset) + 1
    return sf.code[start:offset].lstrip().startswith("#") and "include" in sf.code[start:offset]


@source_check("octal_constant")
def octal_constant(sf, params):
    for m in _OCTAL.finditer(sf.code):
        if not _skip_line(sf, m.start()):
            line = sf.line_of(m.start())
            yield line, sf.line_text(line)


@source_check("lowercase_literal_suffix")
def lowercase_literal_suffix(sf, params):
    for m in _NUMBER.finditer(sf.code):
        tail = re.search(r"[uUlL]+$", m.group(0))
        if tail and "l" in tail.group() and not _skip_line(sf, m.start()):
            line = sf.line_of(m.start())
            yield line, sf.line_text(line)
