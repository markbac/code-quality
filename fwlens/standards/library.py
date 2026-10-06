"""
Standard library detectors: memory and string functions, ctype, streams (MISRA C:2012 21.13 to
21.19, 22.2, 22.5).
"""

from __future__ import annotations

from fwlens.standards.astutil import (
    callee_name,
    side_effects,
    tokens,
    canon,
    const_int,
    kids,
    kind_name,
    peel,
    unary_operator,
    value_flows,
)
from fwlens.standards.engines import detector

_CTYPE = {"isalnum", "isalpha", "isblank", "iscntrl", "isdigit", "isgraph", "islower", "isprint", "ispunct", "isspace",
          "isupper", "isxdigit", "tolower", "toupper"}
_MEM = {"memcpy", "memmove", "memcmp"}
_STRING_FUNCTIONS = {"memcpy", "memmove", "memset", "memchr", "memcmp", "strncpy", "strncat", "strncmp", "strcpy",
                     "strcat"}
_CONST_RETURNING = {"localeconv", "getenv", "setlocale", "strerror"}


def _hit(ctx, cursor):
    line = cursor.location.line
    return line, ctx.line_text(line)


def _call(cursor, names) -> tuple[str, list] | None:
    name = callee_name(cursor)
    if name not in names:
        return None
    return name, kids(cursor)[1:]


@detector("ctype_argument", "CALL_EXPR")
def ctype_argument(ctx, cursor, params):
    call = _call(cursor, _CTYPE)
    if call and call[1]:
        arg = peel(call[1][0])
        if canon(arg.type).kind.name in ("CHAR_S", "SCHAR") and const_int(arg) is None:
            yield _hit(ctx, cursor)


@detector("memcmp_string_literal", "CALL_EXPR")
def memcmp_string_literal(ctx, cursor, params):
    call = _call(cursor, {"memcmp"})
    if call and any(kind_name(peel(a)) == "STRING_LITERAL" for a in call[1][:2]):
        yield _hit(ctx, cursor)


def _pointee_of_argument(arg):
    inner = peel(arg)
    t = canon(inner.type)
    if t.kind.name == "POINTER":
        return canon(t.get_pointee())
    if t.kind.name in ("CONSTANTARRAY", "INCOMPLETEARRAY"):
        return canon(t.get_array_element_type())
    return None


def _unqualified(t) -> str:
    text = t.spelling
    for q in ("const ", "volatile "):
        text = text.replace(q, "")
    return text.strip()


@detector("memory_pointer_types", "CALL_EXPR")
def memory_pointer_types(ctx, cursor, params):
    call = _call(cursor, _MEM)
    if not call or len(call[1]) < 2:
        return
    a, b = _pointee_of_argument(call[1][0]), _pointee_of_argument(call[1][1])
    if a is None or b is None or "VOID" in (a.kind.name, b.kind.name):
        return
    if _unqualified(a) != _unqualified(b):
        yield _hit(ctx, cursor)


@detector("memcmp_operand_types", "CALL_EXPR")
def memcmp_operand_types(ctx, cursor, params):
    call = _call(cursor, {"memcmp"})
    if not call:
        return
    for arg in call[1][:2]:
        t = _pointee_of_argument(arg)
        if t is not None and t.kind.name in ("RECORD", "FLOAT", "DOUBLE", "LONGDOUBLE", "CHAR_S", "CHAR_U"):
            yield _hit(ctx, cursor)
            return


def _array_bytes(arg) -> int | None:
    t = canon(peel(arg).type)
    if t.kind.name == "CONSTANTARRAY":
        return t.get_size()
    return None


@detector("string_function_bounds", "CALL_EXPR")
def string_function_bounds(ctx, cursor, params):
    call = _call(cursor, _STRING_FUNCTIONS)
    if not call or len(call[1]) < 2:
        return
    name, args = call
    room = _array_bytes(args[0])
    if room is None:
        return
    mode = params.get("mode")
    if mode == "copy" and name not in ("strcpy", "strcat"):
        return
    if mode == "size" and name in ("strcpy", "strcat"):
        return
    if name in ("strcpy", "strcat"):
        source = peel(args[1])
        if kind_name(source) == "STRING_LITERAL" and canon(source.type).get_size() > room:
            yield _hit(ctx, cursor)
    elif len(args) >= 3:
        size = const_int(args[2])
        if size is not None and size > room:
            yield _hit(ctx, cursor)


@detector("const_return_used_as_mutable", "VAR_DECL", "BINARY_OPERATOR")
def const_return_used_as_mutable(ctx, cursor, params):
    for dest, expr in value_flows(cursor):
        inner = peel(expr)
        if kind_name(inner) != "CALL_EXPR" or callee_name(inner) not in _CONST_RETURNING:
            continue
        t = canon(dest)
        if t.kind.name == "POINTER" and not canon(t.get_pointee()).is_const_qualified():
            yield _hit(ctx, cursor)


@detector("free_of_non_heap", "CALL_EXPR")
def free_of_non_heap(ctx, cursor, params):
    call = _call(cursor, {"free"})
    if not call or not call[1]:
        return
    arg = peel(call[1][0])
    name = kind_name(arg)
    if name == "UNARY_OPERATOR" and unary_operator(arg) == "&":
        yield _hit(ctx, cursor)
    elif name == "STRING_LITERAL" or (name == "DECL_REF_EXPR" and canon(arg.type).kind.name == "CONSTANTARRAY"):
        yield _hit(ctx, cursor)


def _is_file(t) -> bool:
    ct = canon(t)
    if ct.kind.name != "POINTER":
        return False
    target = canon(ct.get_pointee())
    return target.kind.name == "RECORD" and "FILE" in target.spelling


@detector("file_pointer_dereferenced", "UNARY_OPERATOR", "MEMBER_REF_EXPR")
def file_pointer_dereferenced(ctx, cursor, params):
    parts = kids(cursor)
    if not parts:
        return
    if kind_name(cursor) == "UNARY_OPERATOR":
        if unary_operator(cursor) == "*" and _is_file(peel(parts[0]).type):
            yield _hit(ctx, cursor)
    elif _is_file(peel(parts[0]).type):
        yield _hit(ctx, cursor)


_ALLOCATORS = {"malloc", "calloc", "realloc", "aligned_alloc"}


@detector("allocation_sizeof_pointer", "VAR_DECL", "BINARY_OPERATOR")
def allocation_sizeof_pointer(ctx, cursor, params):
    """p = malloc(sizeof(p)): the size of the pointer, not of what it points to."""
    for _, expr in value_flows(cursor):
        call = peel(expr)
        if kind_name(call) != "CALL_EXPR" or callee_name(call) not in _ALLOCATORS:
            continue
        target = cursor if kind_name(cursor) == "VAR_DECL" else (
            peel(kids(cursor)[0]).referenced if kind_name(peel(kids(cursor)[0])) == "DECL_REF_EXPR" else None)
        if target is None:
            continue
        for node in call.walk_preorder():
            toks = tokens(node) if kind_name(node) == "UNARY_EXPR" else []
            if toks[:1] != ["sizeof"]:
                continue
            for k in kids(node):
                ref = peel(k)
                if kind_name(ref) == "DECL_REF_EXPR" and ref.referenced == target \
                        and canon(ref.type).kind.name == "POINTER":
                    yield _hit(ctx, cursor)
                    return


@detector("file_object_declared", "VAR_DECL", "PARM_DECL", "FIELD_DECL")
def file_object_declared(ctx, cursor, params):
    t = canon(cursor.type)
    if t.kind.name == "RECORD" and "FILE" in t.spelling:
        yield _hit(ctx, cursor)


@detector("stream_argument_side_effects", "CALL_EXPR")
def stream_argument_side_effects(ctx, cursor, params):
    call = _call(cursor, {"getc", "putc", "getwc", "putwc"})
    if call and call[1] and side_effects(call[1][-1] if call[0].startswith("get") else call[1][-1]):
        yield _hit(ctx, cursor)


_THREAD_TYPES = ("thrd_t", "mtx_t", "cnd_t", "tss_t", "once_flag", "pthread_t", "pthread_mutex_t", "pthread_cond_t")


@detector("thread_object_automatic", "VAR_DECL")
def thread_object_automatic(ctx, cursor, params):
    spelled = cursor.type.spelling.replace("const ", "").replace("volatile ", "").strip()
    parent = cursor.semantic_parent
    local = parent is not None and kind_name(parent) == "FUNCTION_DECL"
    if local and spelled in _THREAD_TYPES and cursor.storage_class.name not in ("STATIC", "EXTERN"):
        yield _hit(ctx, cursor)
