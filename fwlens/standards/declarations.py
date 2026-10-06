"""
Declaration detectors: bit-fields, linkage and storage, enumerations, initialisers, identifier
visibility and use, basic types (MISRA C:2012 2.x, 4.5, 4.6, 5.2, 5.3, 6.x, 8.x, 9.x, 21.2).
"""

from __future__ import annotations

import ctypes

from fwlens.standards.astutil import (
    canon,
    kids,
    kind_name,
    tokens,
)
from fwlens.standards.engines import detector, finisher

_BASIC_WORDS = {"short", "int", "long", "float", "double", "signed", "unsigned"}


def _hit(ctx, cursor):
    line = cursor.location.line
    return line, ctx.line_text(line)


def _linkage(cursor) -> str:
    try:
        return cursor.linkage.name
    except Exception:
        return ""


def _storage(cursor) -> str:
    try:
        return cursor.storage_class.name
    except Exception:
        return ""


def _is_file_scope(cursor) -> bool:
    parent = cursor.semantic_parent
    return parent is not None and kind_name(parent) == "TRANSLATION_UNIT"


_inline_ready = False


def is_inline(cursor) -> bool:
    global _inline_ready
    from clang import cindex as ci
    lib = ci.conf.lib
    if not _inline_ready:
        lib.clang_Cursor_isFunctionInlined.argtypes = [ci.Cursor]
        lib.clang_Cursor_isFunctionInlined.restype = ctypes.c_uint
        _inline_ready = True
    return bool(lib.clang_Cursor_isFunctionInlined(cursor))


def _key(cursor) -> tuple:
    loc = cursor.location
    return (loc.file.name if loc.file else "", loc.line, loc.column)


# --- MISRA 6.x: bit-fields -----------------------------------------------------------------------------------

@detector("bit_field_type", "FIELD_DECL")
def bit_field_type(ctx, cursor, params):
    if cursor.is_bitfield() and canon(cursor.type).kind.name not in ("BOOL", "INT", "UINT"):
        yield _hit(ctx, cursor)


@detector("signed_single_bit_field", "FIELD_DECL")
def signed_single_bit_field(ctx, cursor, params):
    if cursor.is_bitfield() and cursor.spelling and cursor.get_bitfield_width() == 1 \
            and canon(cursor.type).kind.name in ("SCHAR", "SHORT", "INT", "LONG", "LONGLONG", "CHAR_S"):
        yield _hit(ctx, cursor)


@detector("bit_field_in_union", "FIELD_DECL")
def bit_field_in_union(ctx, cursor, params):
    parent = cursor.semantic_parent
    if cursor.is_bitfield() and parent is not None and kind_name(parent) == "UNION_DECL":
        yield _hit(ctx, cursor)


# --- MISRA 8.x: declarations and linkage ------------------------------------------------------------------------

@detector("function_prototype_form", "FUNCTION_DECL")
def function_prototype_form(ctx, cursor, params):
    if cursor.type.kind.name == "FUNCTIONNOPROTO":
        yield _hit(ctx, cursor)
        return
    if any(kind_name(k) == "PARM_DECL" and not k.spelling for k in kids(cursor)):
        yield _hit(ctx, cursor)


@detector("definition_without_declaration", "FUNCTION_DECL", "VAR_DECL")
def definition_without_declaration(ctx, cursor, params):
    if not _is_file_scope(cursor) or not cursor.is_definition() or _linkage(cursor) != "EXTERNAL":
        return
    if cursor.spelling == "main":
        return
    if cursor.canonical == cursor:
        yield _hit(ctx, cursor)


@detector("static_in_all_declarations", "FUNCTION_DECL", "VAR_DECL")
def static_in_all_declarations(ctx, cursor, params):
    if _is_file_scope(cursor) and _linkage(cursor) == "INTERNAL" and _storage(cursor) != "STATIC":
        yield _hit(ctx, cursor)


@detector("inline_not_static", "FUNCTION_DECL")
def inline_not_static(ctx, cursor, params):
    if cursor.is_definition() and is_inline(cursor) and _storage(cursor) != "STATIC":
        yield _hit(ctx, cursor)


@detector("extern_array_without_size", "VAR_DECL")
def extern_array_without_size(ctx, cursor, params):
    if _is_file_scope(cursor) and cursor.type.kind.name == "INCOMPLETEARRAY" and _linkage(cursor) == "EXTERNAL":
        yield _hit(ctx, cursor)


@detector("enum_implicit_duplicate", "ENUM_DECL")
def enum_implicit_duplicate(ctx, cursor, params):
    constants = [k for k in kids(cursor) if kind_name(k) == "ENUM_CONSTANT_DECL"]
    values = [c.enum_value for c in constants]
    for c in constants:
        if kids(c):
            continue                          # an explicit value
        if values.count(c.enum_value) > 1:
            yield _hit(ctx, c)


# --- MISRA 9.x: initialisation --------------------------------------------------------------------------------------

def _is_zero_only(cursor) -> bool:
    parts = kids(cursor)
    return len(parts) == 1 and tokens(parts[0]) in (["0"], ["0U"], ["0u"], ["0L"], ["0UL"])


@detector("partial_array_initialiser", "INIT_LIST_EXPR")
def partial_array_initialiser(ctx, cursor, params):
    t = canon(cursor.type)
    if t.kind.name != "CONSTANTARRAY":
        return
    toks = tokens(cursor)
    if any(tok == "=" for tok in toks) or any(tok == "." for tok in toks):
        return                                # designated initialisers are judged by 9.4 and 9.5
    if len(kids(cursor)) < t.get_array_size() and not _is_zero_only(cursor):
        yield _hit(ctx, cursor)


@detector("designated_array_without_size", "VAR_DECL")
def designated_array_without_size(ctx, cursor, params):
    toks = tokens(cursor)
    if "=" not in toks:
        return
    split = toks.index("=")
    head, tail = toks[:split], toks[split + 1:]
    if not any(a == "[" and b == "]" for a, b in zip(head, head[1:], strict=False)):
        return
    depth = 0
    for i, tok in enumerate(tail):
        if tok == "{":
            depth += 1
        elif tok == "}":
            depth -= 1
        elif tok == "[" and depth >= 1:
            close = tail.index("]", i) if "]" in tail[i:] else -1
            if close > 0 and close + 1 < len(tail) and tail[close + 1] == "=":
                yield _hit(ctx, cursor)
                return


# --- MISRA 2.7, 2.8, 8.9: unused parameters and objects -----------------------------------------------------

@detector("unused_parameter", "FUNCTION_DECL")
def unused_parameter(ctx, cursor, params):
    if not cursor.is_definition():
        return
    declared = [k for k in kids(cursor) if kind_name(k) == "PARM_DECL" and k.spelling]
    if not declared:
        return
    used = {_key(n.referenced) for n in cursor.walk_preorder()
            if kind_name(n) == "DECL_REF_EXPR" and n.referenced is not None}
    for p in declared:
        if _key(p) not in used:
            yield _hit(ctx, p)


@detector("unused_object", "VAR_DECL", "DECL_REF_EXPR")
def unused_object_visit(ctx, cursor, params):
    state = ctx.state.setdefault("objects", {"defs": {}, "refs": {}})
    if kind_name(cursor) == "DECL_REF_EXPR":
        ref = cursor.referenced
        if ref is not None and kind_name(ref) == "VAR_DECL":
            state["refs"].setdefault(_key(ref), set()).add(ctx.function)
        return ()
    if _storage(cursor) == "EXTERN" and not cursor.is_definition():
        return ()
    if _is_file_scope(cursor) and _linkage(cursor) == "EXTERNAL":
        return ()                             # visible to other files, judged across the project instead
    state["defs"][_key(cursor)] = (cursor.spelling, cursor.location.line, _is_file_scope(cursor), ctx.function)
    return ()


@finisher("unused_object")
def unused_object_finish(ctx, params):
    state = ctx.state.get("objects")
    if not state:
        return
    for key, (name, line, _, function) in sorted(state["defs"].items(), key=lambda kv: kv[1][1]):
        if key not in state["refs"] and name:
            yield line, ctx.line_text(line), function


@detector("object_used_by_one_function", "VAR_DECL", "DECL_REF_EXPR")
def object_used_by_one_function_visit(ctx, cursor, params):
    return unused_object_visit(ctx, cursor, params)


@finisher("object_used_by_one_function")
def object_used_by_one_function_finish(ctx, params):
    state = ctx.state.get("objects")
    if not state:
        return
    for key, (name, line, file_scope, _) in sorted(state["defs"].items(), key=lambda kv: kv[1][1]):
        users = state["refs"].get(key, set())
        if file_scope and len(users) == 1 and None not in users:
            yield line, ctx.line_text(line)


# --- MISRA 5.2, 5.3, D4.5: identifier visibility --------------------------------------------------------------------

def _first_party_top_names(ctx) -> dict[str, tuple]:
    cache = ctx.state.get("top_names")
    if cache is None:
        cache = {}
        for c in ctx.top_level:
            f = c.location.file
            if f is None or f.name not in ctx.first_party:
                continue
            name = kind_name(c)
            if name in ("FUNCTION_DECL", "VAR_DECL", "TYPEDEF_DECL") and c.spelling:
                cache.setdefault(c.spelling, _key(c))
            elif name == "ENUM_DECL":
                for k in kids(c):
                    if kind_name(k) == "ENUM_CONSTANT_DECL":
                        cache.setdefault(k.spelling, _key(k))
        ctx.state["top_names"] = cache
    return cache


def _scope_declarations(scope) -> list:
    """Variables declared directly in a scope: parameters of a function, or the declarations of a block."""
    name = kind_name(scope)
    if name == "FUNCTION_DECL":
        return [k for k in kids(scope) if kind_name(k) == "PARM_DECL"]
    out: list = []
    for k in kids(scope):
        if kind_name(k) == "DECL_STMT":
            out.extend(v for v in kids(k) if kind_name(v) == "VAR_DECL")
    return out


@detector("identifier_hiding", "VAR_DECL", "PARM_DECL")
def identifier_hiding(ctx, cursor, params):
    name = cursor.spelling
    if not name or _is_file_scope(cursor):
        return
    if name in _first_party_top_names(ctx):
        yield _hit(ctx, cursor)
        return
    scopes = [p for p in ctx.parents if kind_name(p) in ("FUNCTION_DECL", "COMPOUND_STMT", "FOR_STMT")]
    if not scopes:
        return
    own, outer = scopes[-1], scopes[:-1]
    start = cursor.extent.start.offset
    for scope in outer:
        if kind_name(scope) == "FUNCTION_DECL" and own in kids(scope):
            continue                           # the function body shares its scope with the parameters
        if any(d.spelling == name and d.extent.start.offset < start for d in _scope_declarations(scope)):
            yield _hit(ctx, cursor)
            return


def _prefix_clashes(declared, limit: int) -> list:
    seen: dict[str, str] = {}
    out = []
    for d in declared:
        n = d.spelling
        if len(n) <= limit:
            continue
        head = n[:limit]
        if head in seen and seen[head] != n:
            out.append(d)
        seen.setdefault(head, n)
    return out


@detector("identifier_significant_chars", "COMPOUND_STMT", "FUNCTION_DECL")
def identifier_significant_chars(ctx, cursor, params):
    limit = int(params.get("limit", 31))
    for d in _prefix_clashes(_scope_declarations(cursor), limit):
        yield _hit(ctx, d)


@finisher("identifier_significant_chars")
def identifier_significant_chars_finish(ctx, params):
    limit = int(params.get("limit", 31))
    seen: dict[str, str] = {}
    for c in ctx.top_level:
        f = c.location.file
        if f is None or f.name not in ctx.first_party or kind_name(c) not in ("FUNCTION_DECL", "VAR_DECL", "TYPEDEF_DECL"):
            continue
        n = c.spelling
        if len(n) > limit:
            head = n[:limit]
            if head in seen and seen[head] != n and f.name == ctx.main:
                yield c.location.line, ctx.line_text(c.location.line)
            seen.setdefault(head, n)


_CONFUSABLE = str.maketrans({"l": "1", "i": "1", "I": "1", "L": "1", "o": "0", "O": "0", "s": "5", "S": "5",
                             "z": "2", "Z": "2", "B": "8", "b": "8", "h": "n", "H": "n"})


def _normalise(name: str) -> str:
    return name.replace("rn", "m").translate(_CONFUSABLE).replace("_", "").lower()


@detector("typographic_ambiguity", "COMPOUND_STMT", "FUNCTION_DECL")
def typographic_ambiguity(ctx, cursor, params):
    seen: dict[str, str] = {}
    for d in _scope_declarations(cursor):
        n = d.spelling
        if not n:
            continue
        norm = _normalise(n)
        if norm in seen and seen[norm] != n:
            yield _hit(ctx, d)
        seen.setdefault(norm, n)


# --- D4.6: basic numerical types -------------------------------------------------------------------------------------

def _uses_basic_type(t) -> bool:
    text = t.spelling
    for ch in "*[](),":
        text = text.replace(ch, " ")
    words = set(text.split())
    if words & {"unsigned", "signed"} and not (words & _BASIC_WORDS - {"signed", "unsigned"}) and "char" not in words:
        return True                          # bare `unsigned` or `signed`
    return bool(words & (_BASIC_WORDS - {"signed", "unsigned"}))


@detector("basic_numerical_type", "VAR_DECL", "PARM_DECL", "FIELD_DECL", "FUNCTION_DECL")
def basic_numerical_type(ctx, cursor, params):
    if cursor.spelling == "main":
        return
    parts = [cursor.result_type] if kind_name(cursor) == "FUNCTION_DECL" else [cursor.type]
    if any(_uses_basic_type(t) for t in parts):
        yield _hit(ctx, cursor)


# --- MISRA 21.2: reserved identifiers ----------------------------------------------------------------------------------

_LIBRARY_NAMES = frozenset("""
abort abs acos asin atan atan2 atexit atof atoi atol bsearch calloc ceil clearerr clock cos cosh ctime difftime div
exit exp fabs fclose feof ferror fflush fgetc fgets floor fmod fopen fprintf fputc fputs fread free freopen frexp
fscanf fseek ftell fwrite getc getchar getenv gets gmtime isalnum isalpha iscntrl isdigit isgraph islower isprint
ispunct isspace isupper isxdigit labs ldexp ldiv localtime log log10 longjmp malloc memchr memcmp memcpy memmove
memset mktime modf perror pow printf putc putchar puts qsort raise rand realloc remove rename rewind scanf setbuf
setjmp setvbuf signal sin sinh snprintf sprintf sqrt srand sscanf strcat strchr strcmp strcpy strcspn strerror
strftime strlen strncat strncmp strncpy strpbrk strrchr strspn strstr strtod strtok strtol strtoul system tan tanh
time tmpfile tmpnam tolower toupper ungetc vfprintf vprintf vsprintf
""".split())


@detector("reserved_identifier", "VAR_DECL", "FUNCTION_DECL", "TYPEDEF_DECL", "STRUCT_DECL", "UNION_DECL", "ENUM_DECL",
          "ENUM_CONSTANT_DECL", "PARM_DECL", "FIELD_DECL")
def reserved_identifier(ctx, cursor, params):
    name = cursor.spelling
    if not name or name.startswith(("struct ", "union ", "enum ", "(")):
        return                                # anonymous aggregates
    reserved = name.startswith("__") or (name.startswith("_") and len(name) > 1 and name[1].isupper())
    file_scope = _is_file_scope(cursor)
    if not reserved and file_scope and name.startswith("_"):
        reserved = True
    if not reserved and file_scope and name in _LIBRARY_NAMES and kind_name(cursor) in ("FUNCTION_DECL", "VAR_DECL"):
        reserved = True
    if reserved:
        yield _hit(ctx, cursor)


@detector("multiple_declarators", "DECL_STMT")
def multiple_declarators(ctx, cursor, params):
    if sum(1 for k in kids(cursor) if kind_name(k) == "VAR_DECL") > 1:
        yield _hit(ctx, cursor)
