"""
Detectors for the FWLens rule set: unused code the MISRA checks do not cover, and interrupt
safety. Interrupt handlers are found by name or by an attribute on the declaration. Only the
handler's own body is read, so a hazard reached through a call is not seen and those rules are
partial.
"""

from __future__ import annotations

import re

from fwlens.standards.astutil import binary_operator, callee_name, kids, kind_name, unary_operator
from fwlens.standards.engines import detector, finisher

_ISR_NAME = (r"(?:_IRQHandler|_Handler|_ISR|_isr|_irq_handler|_IRQ_Handler)$|^(?:ISR|isr|Isr)_|^(?:ISR|isr)$"
             r"|^(?:vector|Vector)_\w+")
_ISR_ATTRIBUTE = re.compile(r"__interrupt\b|__irq\b|__fiq\b|__attribute__\s*\(\(.*interrupt|\bISR\s*\(|#\s*pragma\s+vector")


def _hit(ctx, cursor):
    line = cursor.location.line
    return line, ctx.line_text(line)


# --- unused code ------------------------------------------------------------------------------------------------

def _is_static_function(cursor) -> bool:
    return cursor.storage_class.name == "STATIC"


@detector("unused_static_function", "FUNCTION_DECL", "DECL_REF_EXPR")
def unused_static_function_visit(ctx, cursor, params):
    state = ctx.state.setdefault("static_functions", {"defs": {}, "refs": set()})
    if kind_name(cursor) == "DECL_REF_EXPR":
        ref = cursor.referenced
        if ref is not None and kind_name(ref) == "FUNCTION_DECL":
            state["refs"].add(ref.spelling)
        return ()
    if cursor.is_definition() and _is_static_function(cursor):
        state["defs"][cursor.spelling] = cursor.location.line
    return ()


@finisher("unused_static_function")
def unused_static_function_finish(ctx, params):
    state = ctx.state.get("static_functions")
    if not state:
        return
    for name, line in sorted(state["defs"].items(), key=lambda kv: kv[1]):
        if name not in state["refs"]:
            yield line, ctx.line_text(line), name


_ASSIGN_OPS = {"="}


def _is_write(parent, cursor) -> bool:
    """True when the reference is the plain left-hand side of an assignment."""
    if parent is None or kind_name(parent) != "BINARY_OPERATOR" or binary_operator(parent) not in _ASSIGN_OPS:
        return False
    children = kids(parent)
    return bool(children) and children[0] == cursor


@detector("write_only_local", "FUNCTION_DECL")
def write_only_local(ctx, cursor, params):
    """A local variable that is assigned but whose value is never read."""
    if not cursor.is_definition():
        return
    declared: dict = {}
    reads: set = set()
    writes: set = set()

    def walk(node, parent):
        name = kind_name(node)
        if name == "VAR_DECL" and node.storage_class.name in ("NONE", "AUTO", "REGISTER") and node.spelling:
            declared[node.get_usr() or (node.spelling, node.location.line)] = node
        elif name == "DECL_REF_EXPR" and node.referenced is not None and kind_name(node.referenced) == "VAR_DECL":
            ref = node.referenced
            key = ref.get_usr() or (ref.spelling, ref.location.line)
            (writes if _is_write(parent, node) else reads).add(key)
        for child in kids(node):
            walk(child, node)

    for child in kids(cursor):
        walk(child, cursor)
    for key, node in sorted(declared.items(), key=lambda kv: kv[1].location.line):
        if key in writes and key not in reads and not node.type.is_volatile_qualified():
            yield _hit(ctx, node)


# --- interrupt safety -----------------------------------------------------------------------------------------

def _is_isr(ctx, cursor, params) -> bool:
    if not cursor.is_definition():
        return False
    if re.search(params.get("isr_pattern", _ISR_NAME), cursor.spelling):
        return True
    start = cursor.extent.start.line
    ctx.line_text(start)                                       # fills the file cache
    lines = ctx.file_cache.get(ctx.main, [])
    head = "\n".join(lines[max(0, start - 3):start])
    return bool(_ISR_ATTRIBUTE.search(head))


def _calls(cursor):
    for node in cursor.walk_preorder():
        if kind_name(node) == "CALL_EXPR":
            yield node, callee_name(node)


@detector("isr_calls", "FUNCTION_DECL")
def isr_calls(ctx, cursor, params):
    """A call from an interrupt handler to one of the listed functions (``callee_in``)."""
    if not _is_isr(ctx, cursor, params):
        return
    wanted = set(params.get("callee_in", ()))
    prefix = tuple(params.get("callee_prefix", ()))
    for node, name in _calls(cursor):
        if name in wanted or (prefix and name.startswith(prefix)):
            yield _hit(ctx, node)


@detector("isr_length", "FUNCTION_DECL")
def isr_length(ctx, cursor, params):
    """An interrupt handler longer than ``limit`` lines."""
    if _is_isr(ctx, cursor, params):
        ext = cursor.extent
        if ext.end.line - ext.start.line + 1 > int(params.get("limit", 40)):
            yield _hit(ctx, cursor)


def _writes_in(node):
    """(reference, node) for each variable assigned, incremented or decremented inside ``node``."""
    def walk(n, parent):
        name = kind_name(n)
        if name == "DECL_REF_EXPR" and n.referenced is not None and kind_name(n.referenced) == "VAR_DECL":
            if parent is not None:
                pk = kind_name(parent)
                if pk == "BINARY_OPERATOR" and binary_operator(parent) == "=" and kids(parent)[0] == n:
                    yield n
                elif pk == "COMPOUND_ASSIGNMENT_OPERATOR" and kids(parent)[0] == n:
                    yield n
                elif pk == "UNARY_OPERATOR" and unary_operator(parent) in ("++", "--"):
                    yield n
        for c in kids(n):
            yield from walk(c, n)
    yield from walk(node, None)


def _shared_state(ctx) -> dict:
    return ctx.state.setdefault("isr_shared", {"isr_writes": {}, "users": {}})


@detector("isr_shared_not_volatile", "FUNCTION_DECL")
def isr_shared_not_volatile_visit(ctx, cursor, params):
    if not cursor.is_definition():
        return ()
    state = _shared_state(ctx)
    isr = _is_isr(ctx, cursor, params)
    for node in cursor.walk_preorder():
        if kind_name(node) != "DECL_REF_EXPR" or node.referenced is None:
            continue
        ref = node.referenced
        if kind_name(ref) != "VAR_DECL" or ref.semantic_parent is None \
                or kind_name(ref.semantic_parent) != "TRANSLATION_UNIT":
            continue
        key = ref.get_usr() or ref.spelling
        if not isr:
            state["users"].setdefault(key, set()).add(cursor.spelling)
    if isr:
        for node in _writes_in(cursor):
            ref = node.referenced
            if ref.type.is_volatile_qualified() or ref.type.is_const_qualified():
                continue
            if ref.semantic_parent is None or kind_name(ref.semantic_parent) != "TRANSLATION_UNIT":
                continue
            key = ref.get_usr() or ref.spelling
            state["isr_writes"].setdefault(key, (node.location.line, cursor.spelling))
    return ()


@finisher("isr_shared_not_volatile")
def isr_shared_not_volatile_finish(ctx, params):
    state = ctx.state.get("isr_shared")
    if not state:
        return
    for key, (line, function) in sorted(state["isr_writes"].items(), key=lambda kv: kv[1][0]):
        if state["users"].get(key):
            yield line, ctx.line_text(line), function
