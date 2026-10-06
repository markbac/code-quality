"""Small helpers over libclang cursors and types shared by the standards detectors."""

from __future__ import annotations


def kids(cursor) -> list:
    return list(cursor.get_children())


# libclang's Python bindings have named the sizeof/alignof expression kind both UNARY_EXPR and
# CXX_UNARY_EXPR over the years. The detectors always say UNARY_EXPR.
KIND_ALIASES = {"UNARY_EXPR": ("UNARY_EXPR", "CXX_UNARY_EXPR")}


def kind_name(cursor) -> str:
    try:
        name = cursor.kind.name
    except ValueError:
        return ""
    return "UNARY_EXPR" if name == "CXX_UNARY_EXPR" else name


def resolve_kind(cursor_kinds, name: str):
    """The CursorKind for a name, trying known aliases. None when this libclang has no such kind."""
    for candidate in KIND_ALIASES.get(name, (name,)):
        found = getattr(cursor_kinds, candidate, None)
        if found is not None:
            return found
    return None


def peel(cursor, *, implicit_only: bool = False):
    """Strip implicit casts (UNEXPOSED_EXPR) and, unless implicit_only, parentheses."""
    while True:
        name = kind_name(cursor)
        if name == "UNEXPOSED_EXPR" or (name == "PAREN_EXPR" and not implicit_only):
            inner = kids(cursor)
            if len(inner) == 1:
                cursor = inner[0]
                continue
        return cursor


def gap_tokens(cursor, start_off: int, end_off: int, file) -> list[str]:
    """Token spellings between two offsets of one file (cheaper than tokenising a whole subtree)."""
    from clang import cindex as ci
    if file is None or not (0 <= start_off < end_off):
        return []
    try:
        tu = cursor.translation_unit
        rng = ci.SourceRange.from_locations(ci.SourceLocation.from_offset(tu, file, start_off),
                                            ci.SourceLocation.from_offset(tu, file, end_off))
        return [t.spelling for t in ci.TokenGroup.get_tokens(tu, rng)
                if t.location.offset < end_off and t.location.file and t.location.file.name == file.name]
    except Exception:
        return []


def binary_operator(cursor) -> str:
    """The spelling of a BINARY_OPERATOR's own operator, or "" (e.g. when it comes from a macro)."""
    try:
        operands = kids(cursor)
        if len(operands) != 2:
            return ""
        lhs_end, rhs_start = operands[0].extent.end, operands[1].extent.start
        for tok in gap_tokens(cursor, lhs_end.offset, rhs_start.offset, lhs_end.file):
            if tok != ")":
                return tok
    except Exception:
        pass
    return ""


def unary_operator(cursor) -> str:
    """The spelling of a UNARY_OPERATOR's own operator (prefix or postfix), or ""."""
    try:
        operands = kids(cursor)
        if len(operands) != 1:
            return ""
        ext, operand = cursor.extent, operands[0].extent
        toks = (gap_tokens(cursor, ext.start.offset, operand.start.offset, ext.start.file)
                or gap_tokens(cursor, operand.end.offset, ext.end.offset, ext.start.file))
        for tok in toks:
            if tok not in ("(", ")"):
                return tok
    except Exception:
        pass
    return ""


def is_assignment_op(op: str) -> bool:
    return op in ("=", "+=", "-=", "*=", "/=", "%=", "<<=", ">>=", "&=", "|=", "^=")


def tokens(cursor) -> list[str]:
    try:
        return [t.spelling for t in cursor.get_tokens()]
    except Exception:
        return []


def canon(t):
    return t.get_canonical()


def strip_cv(t):
    """The canonical type without top-level qualifiers (spelled out and compared as text)."""
    text = canon(t).spelling
    for q in ("const ", "volatile ", "restrict "):
        text = text.replace(q, "")
    return " ".join(text.split())


def pointer_depth(t) -> int:
    depth = 0
    t = canon(t)
    while t.kind.name == "POINTER":
        depth += 1
        t = canon(t.get_pointee())
    return depth


def is_pointer(t) -> bool:
    return canon(t).kind.name == "POINTER"


def pointee(t):
    return canon(canon(t).get_pointee())


def is_function_pointer(t) -> bool:
    t = canon(t)
    return t.kind.name == "POINTER" and canon(t.get_pointee()).kind.name in ("FUNCTIONPROTO", "FUNCTIONNOPROTO")


def is_void_pointer(t) -> bool:
    t = canon(t)
    return t.kind.name == "POINTER" and canon(t.get_pointee()).kind.name == "VOID"


def is_integer_type(t) -> bool:
    return canon(t).kind.name in {"BOOL", "CHAR_U", "UCHAR", "CHAR16", "CHAR32", "USHORT", "UINT", "ULONG", "ULONGLONG",
                                  "UINT128", "CHAR_S", "SCHAR", "WCHAR", "SHORT", "INT", "LONG", "LONGLONG", "INT128",
                                  "ENUM"}


def is_float_type(t) -> bool:
    return canon(t).kind.name in ("FLOAT", "DOUBLE", "LONGDOUBLE", "FLOAT128", "HALF")


def int_literal_value(cursor) -> int | None:
    """Value of an integer literal cursor from its token, or None if it is not a plain literal."""
    toks = tokens(cursor)
    if not toks:
        return None
    text = toks[0].rstrip("uUlL")
    try:
        return int(text, 0) if not (len(text) > 1 and text.startswith("0") and text[1].isdigit()) else int(text, 8)
    except ValueError:
        return None


def is_zero_constant(cursor) -> bool:
    c = peel(cursor)
    return kind_name(c) == "INTEGER_LITERAL" and int_literal_value(c) == 0


def is_constant_expr(cursor) -> bool:
    """A literal, or an operator tree of literals and sizeof (a conservative constant expression)."""
    c = peel(cursor)
    name = kind_name(c)
    if name in ("INTEGER_LITERAL", "CHARACTER_LITERAL", "FLOATING_LITERAL", "STRING_LITERAL"):
        return True
    if name == "UNARY_EXPR":      # sizeof / alignof
        return True
    if name == "DECL_REF_EXPR":
        ref = c.referenced
        return ref is not None and kind_name(ref) == "ENUM_CONSTANT_DECL"
    if name in ("BINARY_OPERATOR", "UNARY_OPERATOR", "CSTYLE_CAST_EXPR", "CONDITIONAL_OPERATOR"):
        return all(is_constant_expr(k) for k in kids(c) if kind_name(k) not in ("TYPE_REF",))
    return False


def has_side_effect(ctx_kinds, cursor) -> bool:
    """True if the subtree contains a call, an assignment or an increment/decrement."""
    for node in cursor.walk_preorder():
        name = kind_name(node)
        if name == "CALL_EXPR":
            return True
        if name == "BINARY_OPERATOR" and is_assignment_op(binary_operator(node)):
            return True
        if name == "COMPOUND_ASSIGNMENT_OPERATOR":
            return True
        if name == "UNARY_OPERATOR" and unary_operator(node) in ("++", "--"):
            return True
    return False


# --- constant evaluation (libclang's own evaluator) -----------------------------------------------

_eval_ready = False


def const_int(cursor) -> int | None:
    """
    The value of an integer constant expression, folded by libclang (macros, enumerators, sizeof
    and casts included), or None when the expression is not an integer constant.
    """
    global _eval_ready
    import ctypes

    from clang import cindex as ci
    lib = ci.conf.lib
    if not _eval_ready:
        lib.clang_Cursor_Evaluate.restype = ctypes.c_void_p
        lib.clang_Cursor_Evaluate.argtypes = [ci.Cursor]
        lib.clang_EvalResult_getKind.argtypes = [ctypes.c_void_p]
        lib.clang_EvalResult_getKind.restype = ctypes.c_int
        lib.clang_EvalResult_getAsLongLong.argtypes = [ctypes.c_void_p]
        lib.clang_EvalResult_getAsLongLong.restype = ctypes.c_longlong
        lib.clang_EvalResult_isUnsignedInt.argtypes = [ctypes.c_void_p]
        lib.clang_EvalResult_isUnsignedInt.restype = ctypes.c_uint
        lib.clang_EvalResult_getAsUnsigned.argtypes = [ctypes.c_void_p]
        lib.clang_EvalResult_getAsUnsigned.restype = ctypes.c_ulonglong
        lib.clang_EvalResult_dispose.argtypes = [ctypes.c_void_p]
        _eval_ready = True
    try:
        handle = lib.clang_Cursor_Evaluate(cursor)
    except Exception:
        return None
    if not handle:
        return None
    try:
        if lib.clang_EvalResult_getKind(handle) != 1:      # CXEval_Int
            return None
        if lib.clang_EvalResult_isUnsignedInt(handle):
            return int(lib.clang_EvalResult_getAsUnsigned(handle))
        return int(lib.clang_EvalResult_getAsLongLong(handle))
    finally:
        lib.clang_EvalResult_dispose(handle)


# --- statements -----------------------------------------------------------------------------------

LABELS = ("CASE_STMT", "DEFAULT_STMT", "LABEL_STMT")
JUMPS = ("RETURN_STMT", "BREAK_STMT", "CONTINUE_STMT", "GOTO_STMT")
LOOPS = ("WHILE_STMT", "DO_STMT", "FOR_STMT")


def terminal(stmt):
    """The statement control last runs in ``stmt``: through case/default/label wrappers and braces."""
    while True:
        name = kind_name(stmt)
        inner = kids(stmt)
        if name in LABELS and inner:
            stmt = inner[-1]
        elif name == "COMPOUND_STMT" and inner:
            stmt = inner[-1]
        else:
            return stmt


def for_parts(cursor) -> tuple:
    """(init, cond, inc, body) of a FOR_STMT, each None when the clause is empty."""
    children = kids(cursor)
    if not children:
        return None, None, None, None
    body, header = children[-1], children[:-1]
    if not header:
        return None, None, None, body
    offsets = _semicolon_offsets(cursor, body)
    parts = [None, None, None]
    for child in header:
        pos = child.extent.start.offset
        index = sum(1 for o in offsets if o < pos)
        if index < 3:
            parts[index] = child
    return parts[0], parts[1], parts[2], body


def _semicolon_offsets(cursor, body) -> list[int]:
    from clang import cindex as ci
    ext = cursor.extent
    file = ext.start.file
    try:
        tu = cursor.translation_unit
        rng = ci.SourceRange.from_locations(ci.SourceLocation.from_offset(tu, file, ext.start.offset),
                                            ci.SourceLocation.from_offset(tu, file, body.extent.start.offset))
        depth, out = 0, []
        for tok in ci.TokenGroup.get_tokens(tu, rng):
            sp = tok.spelling
            if sp == "(":
                depth += 1
            elif sp == ")":
                depth -= 1
            elif sp == ";" and depth == 1:
                out.append(tok.location.offset)
        return out
    except Exception:
        return []


def condition_of(cursor):
    """The controlling expression of an if, while, do, for, switch or ?:, or None."""
    name = kind_name(cursor)
    children = kids(cursor)
    if name in ("IF_STMT", "WHILE_STMT", "SWITCH_STMT", "CONDITIONAL_OPERATOR"):
        return children[0] if children else None
    if name == "DO_STMT":
        return children[-1] if len(children) > 1 else None
    if name == "FOR_STMT":
        return for_parts(cursor)[1]
    return None


# --- expression context ---------------------------------------------------------------------------

EXPRESSION_SUFFIXES = ("_EXPR", "_OPERATOR", "_LITERAL")


def is_expression(cursor) -> bool:
    name = kind_name(cursor)
    return name.endswith(EXPRESSION_SUFFIXES) or name in ("UNEXPOSED_EXPR", "INIT_LIST_EXPR")


def value_flows(cursor):
    """
    Yield (destination type, expression) for every place a value is converted to a declared type
    when ``cursor`` is a declaration with an initialiser, an assignment, a return or a call.
    """
    name = kind_name(cursor)
    children = kids(cursor)
    if name == "VAR_DECL":
        exprs = [k for k in children if is_expression(k)]
        if exprs and kind_name(peel(exprs[-1])) != "INIT_LIST_EXPR":
            yield cursor.type, exprs[-1]
    elif name == "BINARY_OPERATOR" and binary_operator(cursor) == "=" and len(children) == 2:
        yield children[0].type, children[1]
    elif name == "RETURN_STMT" and children:
        yield None, children[0]            # the function's result type is looked up by the caller
    elif name == "CALL_EXPR":
        callee = cursor.referenced
        if callee is not None and kind_name(callee) == "FUNCTION_DECL":
            params = [p.type for p in callee.get_arguments()]
            for t, arg in zip(params, children[1:], strict=False):
                yield t, arg


def full_expression_root(ctx, cursor):
    """The outermost expression containing ``cursor`` (stopping at the first statement or declaration)."""
    node = cursor
    for p in reversed(ctx.parents):
        if is_expression(p) or kind_name(p) in ("PAREN_EXPR",):
            node = p
        else:
            break
    return node


def side_effects(cursor) -> list:
    """Every call, assignment and increment/decrement in the subtree."""
    out = []
    for node in cursor.walk_preorder():
        name = kind_name(node)
        if name in ("CALL_EXPR", "COMPOUND_ASSIGNMENT_OPERATOR"):
            out.append(node)
        elif name == "BINARY_OPERATOR" and is_assignment_op(binary_operator(node)):
            out.append(node)
        elif name == "UNARY_OPERATOR" and unary_operator(node) in ("++", "--"):
            out.append(node)
    return out


def value_unused(ctx, cursor) -> bool:
    """True when the value of the expression ``cursor`` is thrown away (an expression statement)."""
    if not ctx.parents:
        return False
    parent = ctx.parents[-1]
    pname = kind_name(parent)
    if pname == "COMPOUND_STMT":
        return True
    siblings = kids(parent)
    if pname in ("CASE_STMT", "DEFAULT_STMT", "LABEL_STMT"):
        return bool(siblings) and siblings[-1] == cursor
    if pname == "IF_STMT":
        return cursor in siblings[1:]
    if pname in ("WHILE_STMT", "DO_STMT"):
        return bool(siblings) and (siblings[-1] == cursor if pname == "WHILE_STMT" else siblings[0] == cursor)
    if pname == "FOR_STMT":
        return for_parts(parent)[1] != cursor
    if pname == "SWITCH_STMT":
        return False
    if pname == "BINARY_OPERATOR" and binary_operator(parent) == ",":
        return siblings[0] == cursor
    return False


def callee_name(cursor) -> str:
    """The name of the function a CALL_EXPR calls, also when the name is parenthesised: (f)(x)."""
    ref = cursor.referenced
    if ref is not None and kind_name(ref) == "FUNCTION_DECL":
        return ref.spelling
    if not cursor.spelling:
        head = kids(cursor)[:1]
        for node in (head[0].walk_preorder() if head else ()):
            target = node.referenced if kind_name(node) == "DECL_REF_EXPR" else None
            if target is not None and kind_name(target) == "FUNCTION_DECL":
                return target.spelling
    return cursor.spelling
