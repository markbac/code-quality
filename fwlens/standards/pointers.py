"""
Pointer detectors: conversions and casts (MISRA C:2012 11.x), pointer arithmetic and arrays
(18.x), unions (19.2).
"""

from __future__ import annotations

from fwlens.standards.astutil import (
    binary_operator,
    canon,
    const_int,
    is_expression,
    kids,
    kind_name,
    peel,
    tokens,
    unary_operator,
    value_flows,
)
from fwlens.standards.engines import detector

_FLOAT = {"FLOAT", "DOUBLE", "LONGDOUBLE", "FLOAT128", "HALF"}
_INTEGER = {"BOOL", "CHAR_U", "UCHAR", "CHAR16", "CHAR32", "USHORT", "UINT", "ULONG", "ULONGLONG", "UINT128", "CHAR_S",
            "SCHAR", "WCHAR", "SHORT", "INT", "LONG", "LONGLONG", "INT128", "ENUM"}


def _hit(ctx, cursor):
    line = cursor.location.line
    return line, ctx.line_text(line)


def type_class(t, expr=None) -> str:
    """fnptr | voidptr | incomplete | objptr | integer | float | null | other"""
    ct = canon(t)
    kind = ct.kind.name
    if kind in ("FUNCTIONPROTO", "FUNCTIONNOPROTO"):
        return "fnptr"
    if kind in ("CONSTANTARRAY", "INCOMPLETEARRAY", "VARIABLEARRAY"):
        return "objptr"                                    # an array decays to a pointer to its element
    if kind == "POINTER":
        target = canon(ct.get_pointee())
        tk = target.kind.name
        if tk in ("FUNCTIONPROTO", "FUNCTIONNOPROTO"):
            return "fnptr"
        if tk == "VOID":
            return "voidptr"
        if tk in ("RECORD", "ENUM") and target.get_size() < 0:
            return "incomplete"
        return "objptr"
    if kind in _FLOAT:
        return "float"
    if kind in _INTEGER:
        if expr is not None and const_int(expr) == 0:
            return "null"
        return "integer"
    return "other"


def _unqualified(t) -> str:
    text = canon(t).spelling
    for q in ("const ", "volatile ", "restrict "):
        text = text.replace(q, "")
    return " ".join(text.split())


def _pointee_text(t) -> str:
    ct = canon(t)
    if ct.kind.name in ("CONSTANTARRAY", "INCOMPLETEARRAY", "VARIABLEARRAY"):
        return _unqualified(ct.get_array_element_type())
    return _unqualified(ct.get_pointee())


def _pointee(t):
    ct = canon(t)
    if ct.kind.name in ("CONSTANTARRAY", "INCOMPLETEARRAY", "VARIABLEARRAY"):
        return canon(ct.get_array_element_type())
    return canon(ct.get_pointee())


def _cast_parts(cursor):
    operands = [k for k in kids(cursor) if kind_name(k) != "TYPE_REF" and is_expression(k)]
    if not operands:
        return None
    operand = operands[-1]
    inner = peel(operand)
    return cursor.type, inner.type, inner


def _classes(cursor):
    parts = _cast_parts(cursor)
    if parts is None:
        return None
    dest_t, src_t, inner = parts
    return dest_t, src_t, type_class(dest_t), type_class(src_t, inner)


# --- MISRA 11.1 to 11.8: casts ---------------------------------------------------------------------------------

@detector("cast_function_pointer", "CSTYLE_CAST_EXPR")
def cast_function_pointer(ctx, cursor, params):
    c = _classes(cursor)
    if c is None:
        return
    dest_t, src_t, dest, src = c
    if "null" in (dest, src):
        return
    if (dest == "fnptr") != (src == "fnptr") or (
            dest == src == "fnptr" and _unqualified(dest_t) != _unqualified(src_t)):
        yield _hit(ctx, cursor)


@detector("cast_incomplete_pointer", "CSTYLE_CAST_EXPR")
def cast_incomplete_pointer(ctx, cursor, params):
    c = _classes(cursor)
    if c is None:
        return
    dest_t, src_t, dest, src = c
    if "incomplete" not in (dest, src) or "null" in (dest, src) or "voidptr" in (dest, src):
        return
    if dest == src == "incomplete" and _unqualified(dest_t) == _unqualified(src_t):
        return
    yield _hit(ctx, cursor)


@detector("cast_object_pointer", "CSTYLE_CAST_EXPR")
def cast_object_pointer(ctx, cursor, params):
    c = _classes(cursor)
    if c is None:
        return
    dest_t, src_t, dest, src = c
    if dest == "objptr" and src == "objptr" and _pointee_text(dest_t) != _pointee_text(src_t):
        yield _hit(ctx, cursor)


@detector("cast_pointer_integer", "CSTYLE_CAST_EXPR")
def cast_pointer_integer(ctx, cursor, params):
    c = _classes(cursor)
    if c is None:
        return
    _, _, dest, src = c
    if {dest, src} <= {"objptr", "integer", "incomplete"} and "objptr" in (dest, src) and "integer" in (dest, src):
        yield _hit(ctx, cursor)


@detector("cast_void_pointer_arithmetic", "CSTYLE_CAST_EXPR")
def cast_void_pointer_arithmetic(ctx, cursor, params):
    c = _classes(cursor)
    if c is None:
        return
    _, _, dest, src = c
    if "voidptr" in (dest, src) and ({dest, src} & {"integer", "float"}) and "null" not in (dest, src):
        yield _hit(ctx, cursor)


@detector("cast_pointer_float", "CSTYLE_CAST_EXPR")
def cast_pointer_float(ctx, cursor, params):
    c = _classes(cursor)
    if c is None:
        return
    _, _, dest, src = c
    if "float" in (dest, src) and ({dest, src} & {"objptr", "incomplete"}):
        yield _hit(ctx, cursor)


@detector("cast_removes_qualifier", "CSTYLE_CAST_EXPR")
def cast_removes_qualifier(ctx, cursor, params):
    c = _classes(cursor)
    if c is None:
        return
    dest_t, src_t, dest, src = c
    pointerish = {"objptr", "voidptr", "incomplete"}
    if dest not in pointerish or src not in pointerish:
        return
    d, s = _pointee(dest_t), _pointee(src_t)
    which = params.get("qualifier", "both")
    lost_const = s.is_const_qualified() and not d.is_const_qualified()
    lost_volatile = s.is_volatile_qualified() and not d.is_volatile_qualified()
    if (which in ("const", "both") and lost_const) or (which in ("volatile", "both") and lost_volatile):
        yield _hit(ctx, cursor)


@detector("cast_alignment", "CSTYLE_CAST_EXPR")
def cast_alignment(ctx, cursor, params):
    c = _classes(cursor)
    if c is None:
        return
    dest_t, src_t, dest, src = c
    if dest != "objptr" or src != "objptr":
        return
    d, s = _pointee(dest_t), _pointee(src_t)
    try:
        if d.get_align() > s.get_align() > 0:
            yield _hit(ctx, cursor)
    except Exception:
        return


# --- MISRA 11.5, 11.9: implicit conversions ---------------------------------------------------------------------

@detector("void_pointer_to_object", "CSTYLE_CAST_EXPR", "VAR_DECL", "BINARY_OPERATOR", "RETURN_STMT", "CALL_EXPR")
def void_pointer_to_object(ctx, cursor, params):
    if kind_name(cursor) == "CSTYLE_CAST_EXPR":
        c = _classes(cursor)
        if c and c[2] == "objptr" and c[3] == "voidptr":
            yield _hit(ctx, cursor)
        return
    from fwlens.standards.expressions import _flows
    for dest_t, expr in _flows(ctx, cursor):
        inner = peel(expr)
        if kind_name(inner) in ("CSTYLE_CAST_EXPR",):
            continue
        if type_class(dest_t) == "objptr" and type_class(inner.type, inner) == "voidptr":
            yield _hit(ctx, expr)


@detector("string_literal_to_mutable", "VAR_DECL", "BINARY_OPERATOR", "RETURN_STMT", "CALL_EXPR")
def string_literal_to_mutable(ctx, cursor, params):
    from fwlens.standards.expressions import _flows
    for dest_t, expr in _flows(ctx, cursor):
        if kind_name(peel(expr)) != "STRING_LITERAL":
            continue
        t = canon(dest_t)
        if t.kind.name == "POINTER":
            target = canon(t.get_pointee())
            if target.kind.name in ("CHAR_S", "CHAR_U", "SCHAR", "UCHAR") and not target.is_const_qualified():
                yield _hit(ctx, expr)


@detector("null_pointer_literal", "INTEGER_LITERAL")
def null_pointer_literal(ctx, cursor, params):
    parent = ctx.parents[-1] if ctx.parents else None
    if parent is None or kind_name(parent) != "UNEXPOSED_EXPR":
        return
    if canon(parent.type).kind.name != "POINTER":
        return
    toks = tokens(cursor)
    if toks == ["0"]:
        yield _hit(ctx, cursor)


# --- MISRA 18.x: pointer arithmetic and arrays ------------------------------------------------------------------

@detector("array_index_out_of_bounds", "ARRAY_SUBSCRIPT_EXPR")
def array_index_out_of_bounds(ctx, cursor, params):
    operands = kids(cursor)
    if len(operands) != 2:
        return
    base, index = peel(operands[0]), operands[1]
    t = canon(base.type)
    if t.kind.name != "CONSTANTARRAY":
        return
    value = const_int(index)
    if value is not None and not 0 <= value < t.get_array_size():
        yield _hit(ctx, cursor)


@detector("pointer_relational", "BINARY_OPERATOR")
def pointer_relational(ctx, cursor, params):
    if binary_operator(cursor) not in ("<", ">", "<=", ">="):
        return
    operands = kids(cursor)
    if len(operands) == 2 and all(canon(o.type).kind.name == "POINTER" for o in operands):
        yield _hit(ctx, cursor)


@detector("pointer_arithmetic", "BINARY_OPERATOR", "COMPOUND_ASSIGNMENT_OPERATOR")
def pointer_arithmetic(ctx, cursor, params):
    op = binary_operator(cursor)
    if op not in ("+", "-", "+=", "-="):
        return
    operands = kids(cursor)
    if len(operands) == 2 and any(canon(o.type).kind.name == "POINTER" for o in operands):
        yield _hit(ctx, cursor)


def _declared_depth(t) -> int:
    depth = 0
    while t.kind.name == "POINTER":
        depth += 1
        t = t.get_pointee()
    if t.kind.name in ("CONSTANTARRAY", "INCOMPLETEARRAY", "VARIABLEARRAY"):
        return depth + _declared_depth(t.get_array_element_type())
    return depth


@detector("pointer_nesting", "VAR_DECL", "PARM_DECL", "FIELD_DECL", "TYPEDEF_DECL", "FUNCTION_DECL")
def pointer_nesting(ctx, cursor, params):
    t = cursor.result_type if kind_name(cursor) == "FUNCTION_DECL" else (
        cursor.underlying_typedef_type if kind_name(cursor) == "TYPEDEF_DECL" else cursor.type)
    if _declared_depth(t) > int(params.get("limit", 2)):
        yield _hit(ctx, cursor)


@detector("function_pointer_declared", "VAR_DECL", "PARM_DECL", "FIELD_DECL", "TYPEDEF_DECL")
def function_pointer_declared(ctx, cursor, params):
    t = cursor.underlying_typedef_type if kind_name(cursor) == "TYPEDEF_DECL" else cursor.type
    while t.kind.name in ("CONSTANTARRAY", "INCOMPLETEARRAY"):
        t = t.get_array_element_type()
    if type_class(t) == "fnptr" and canon(t).kind.name == "POINTER":
        yield _hit(ctx, cursor)


def _is_automatic_variable(expr) -> bool:
    ref = peel(expr)
    if kind_name(ref) == "UNARY_OPERATOR" and unary_operator(ref) == "&":
        inner = peel(kids(ref)[0]) if kids(ref) else None
        while inner is not None and kind_name(inner) in ("MEMBER_REF_EXPR", "ARRAY_SUBSCRIPT_EXPR"):
            parts = kids(inner)
            inner = peel(parts[0]) if parts else None
        ref = inner
    if ref is None or kind_name(ref) != "DECL_REF_EXPR":
        return False
    decl = ref.referenced
    if decl is None or kind_name(decl) not in ("VAR_DECL", "PARM_DECL"):
        return False
    if kind_name(decl) == "VAR_DECL" and decl.storage_class.name in ("STATIC", "EXTERN"):
        return False
    return decl.semantic_parent is not None and kind_name(decl.semantic_parent) == "FUNCTION_DECL"


def _is_address_form(expr) -> bool:
    inner = peel(expr)
    if kind_name(inner) == "UNARY_OPERATOR" and unary_operator(inner) == "&":
        return True
    return kind_name(inner) == "DECL_REF_EXPR" and canon(inner.type).kind.name == "CONSTANTARRAY"


@detector("address_of_automatic_escapes", "RETURN_STMT", "BINARY_OPERATOR")
def address_of_automatic_escapes(ctx, cursor, params):
    if kind_name(cursor) == "RETURN_STMT":
        parts = kids(cursor)
        if parts and _is_address_form(parts[0]) and _is_automatic_variable(parts[0]):
            yield _hit(ctx, cursor)
        return
    if binary_operator(cursor) != "=":
        return
    operands = kids(cursor)
    if len(operands) != 2 or not (_is_address_form(operands[1]) and _is_automatic_variable(operands[1])):
        return
    target = peel(operands[0])
    # the left side lasts beyond the function when it is a file-scope or static object, or reached through a pointer
    if kind_name(target) == "DECL_REF_EXPR":
        decl = target.referenced
        persists = decl is not None and (kind_name(decl.semantic_parent) == "TRANSLATION_UNIT"
                                        or decl.storage_class.name == "STATIC")
        if persists:
            yield _hit(ctx, cursor)
    elif kind_name(target) in ("UNARY_OPERATOR", "MEMBER_REF_EXPR", "ARRAY_SUBSCRIPT_EXPR"):
        if kind_name(target) != "UNARY_OPERATOR" or unary_operator(target) == "*":
            yield _hit(ctx, cursor)


@detector("flexible_array_member", "FIELD_DECL")
def flexible_array_member(ctx, cursor, params):
    if cursor.type.kind.name == "INCOMPLETEARRAY":
        yield _hit(ctx, cursor)


@detector("flexible_array_hack", "STRUCT_DECL")
def flexible_array_hack(ctx, cursor, params):
    fields = [k for k in kids(cursor) if kind_name(k) == "FIELD_DECL"]
    if not fields or len(fields) < 2:
        return
    last = canon(fields[-1].type)
    if last.kind.name == "CONSTANTARRAY" and last.get_array_size() in (0, 1):
        yield _hit(ctx, fields[-1])


@detector("variable_length_array", "VAR_DECL", "PARM_DECL", "FIELD_DECL", "TYPEDEF_DECL")
def variable_length_array(ctx, cursor, params):
    t = cursor.underlying_typedef_type if kind_name(cursor) == "TYPEDEF_DECL" else cursor.type
    while True:
        k = t.kind.name
        if k == "VARIABLEARRAY":
            yield _hit(ctx, cursor)
            return
        if k == "POINTER":
            t = t.get_pointee()
        elif k in ("CONSTANTARRAY", "INCOMPLETEARRAY"):
            t = t.get_array_element_type()
        else:
            return


@detector("union_declared", "UNION_DECL")
def union_declared(ctx, cursor, params):
    if cursor.is_definition():
        yield _hit(ctx, cursor)


# value_flows is re-exported for the pointer rules in the library module
__all__ = ["type_class", "value_flows"]
