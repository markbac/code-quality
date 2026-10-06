"""
A conservative model of MISRA's essential type categories over libclang expressions.

It is used by the 10.x rules. Whenever an expression's category cannot be worked out with
confidence, essential() returns None and the rules stay silent, so a rule built on it can miss a
violation but should not invent one.
"""

from __future__ import annotations

from dataclasses import dataclass

from fwlens.standards.astutil import (
    binary_operator,
    canon,
    is_constant_expr,
    kids,
    kind_name,
    peel,
    tokens,
    unary_operator,
)

_SIGNED = {"SCHAR", "SHORT", "INT", "LONG", "LONGLONG", "INT128"}
_UNSIGNED = {"UCHAR", "USHORT", "UINT", "ULONG", "ULONGLONG", "UINT128"}
_FLOAT = {"FLOAT", "DOUBLE", "LONGDOUBLE", "FLOAT128", "HALF"}
ARITH = {"+", "-", "*", "/", "%", "&", "|", "^"}
SHIFT = {"<<", ">>"}
RELATIONAL = {"<", ">", "<=", ">="}
EQUALITY = {"==", "!="}
LOGICAL = {"&&", "||"}
ASSIGN_ARITH = {"+=": "+", "-=": "-", "*=": "*", "/=": "/", "%=": "%", "&=": "&", "|=": "|", "^=": "^",
                "<<=": "<<", ">>=": ">>"}


@dataclass(frozen=True)
class Ess:
    cat: str                    # boolean | character | signed | unsigned | enum | floating
    bits: int
    const: bool = False         # an integer constant expression
    composite: bool = False     # the result of an arithmetic, bitwise, shift or conditional operator
    enum: str = ""              # the enumerated type's name when cat is enum
    value: int | None = None    # value of a literal


def from_type(t) -> Ess | None:
    ct = canon(t)
    kind = ct.kind.name
    try:
        bits = max(ct.get_size(), 0) * 8
    except Exception:
        bits = 0
    if kind == "BOOL":
        return Ess("boolean", 8)
    if kind in ("CHAR_S", "CHAR_U"):
        return Ess("character", 8)
    if kind in _SIGNED:
        return Ess("signed", bits)
    if kind in _UNSIGNED:
        return Ess("unsigned", bits)
    if kind in _FLOAT:
        return Ess("floating", bits)
    if kind == "ENUM":
        return Ess("enum", bits, enum=ct.get_declaration().spelling or ct.spelling)
    return None


def _literal_value(cursor) -> int | None:
    toks = tokens(cursor)
    if not toks:
        return None
    text = toks[0].rstrip("uUlL")
    try:
        return int(text, 8) if len(text) > 1 and text.startswith("0") and text.isdigit() else int(text, 0)
    except ValueError:
        return None


def essential(cursor) -> Ess | None:
    c = peel(cursor)
    name = kind_name(c)
    if name == "INTEGER_LITERAL":
        base = from_type(c.type)
        if base is None:
            return None
        return Ess(base.cat, base.bits, const=True, value=_literal_value(c))
    if name == "CHARACTER_LITERAL":
        return Ess("character", 8, const=True)
    if name == "FLOATING_LITERAL":
        base = from_type(c.type)
        return Ess("floating", base.bits if base else 64, const=True)
    if name == "DECL_REF_EXPR":
        ref = c.referenced
        if ref is not None and kind_name(ref) == "ENUM_CONSTANT_DECL":
            enum_decl = ref.semantic_parent
            return Ess("enum", 32, const=True, enum=enum_decl.spelling if enum_decl is not None else "")
        return from_type(c.type)
    if name == "BINARY_OPERATOR":
        return _binary(c)
    if name == "UNARY_OPERATOR":
        return _unary(c)
    if name == "CONDITIONAL_OPERATOR":
        operands = kids(c)
        if len(operands) == 3:
            a, b = essential(operands[1]), essential(operands[2])
            if a is None or b is None:
                return None
            pick = a if a.bits >= b.bits else b
            return Ess(pick.cat, pick.bits, const=a.const and b.const, composite=True, enum=pick.enum)
        return None
    if name == "UNARY_EXPR":      # sizeof, alignof
        return Ess("unsigned", canon(c.type).get_size() * 8, const=True)
    if name == "CSTYLE_CAST_EXPR":
        return from_type(c.type)
    return from_type(c.type)


def _binary(c) -> Ess | None:
    op = binary_operator(c)
    operands = kids(c)
    if not op or len(operands) != 2:
        return None
    if op in RELATIONAL or op in EQUALITY or op in LOGICAL:
        return Ess("boolean", 8)
    left, right = essential(operands[0]), essential(operands[1])
    if op == ",":
        return right
    if op == "=" or op in ASSIGN_ARITH:
        return left
    if left is None or right is None:
        return None
    const = left.const and right.const
    if op in SHIFT:
        return Ess(left.cat, left.bits, const=const, composite=not const, enum=left.enum)
    if op in ARITH:
        if left.cat == right.cat == "character" and op == "-":
            return Ess("signed", 32, const=const, composite=not const)     # the difference of two characters
        if left.cat == right.cat:
            return Ess(left.cat, max(left.bits, right.bits), const=const, composite=not const,
                       enum=left.enum if left.enum == right.enum else "")
        if "character" in (left.cat, right.cat) and op in ("+", "-"):
            return Ess("character", 8, const=const, composite=not const)
        # categories differ: the usual arithmetic conversions decide, which the clang type records
        return None
    return None


def _unary(c) -> Ess | None:
    op = unary_operator(c)
    operands = kids(c)
    if not operands:
        return None
    if op == "!":
        return Ess("boolean", 8)
    inner = essential(operands[0])
    if op in ("-", "+", "~"):
        if inner is None:
            return None
        return Ess(inner.cat, inner.bits, const=inner.const, composite=not inner.const, enum=inner.enum,
                   value=-inner.value if op == "-" and inner.value is not None else None)
    if op in ("++", "--"):
        return inner
    return from_type(c.type) if op not in ("*", "&") else None


def is_nonneg_constant(e: Ess) -> bool:
    return e.const and (e.value is None or e.value >= 0)


def expression_children(cursor) -> list:
    """Children that are expressions (not type references and other non-expression nodes)."""
    out = []
    for k in kids(cursor):
        n = kind_name(k)
        if n.endswith(("EXPR", "LITERAL", "OPERATOR")) or n == "UNEXPOSED_EXPR":
            out.append(k)
    return out


def constant(cursor) -> bool:
    return is_constant_expr(cursor)
