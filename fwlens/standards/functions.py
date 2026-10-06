"""
Function detectors: results, parameters and function identifiers (MISRA C:2012 17.5 to 17.8 and
17.12).
"""

from __future__ import annotations

import re

from fwlens.standards.astutil import (
    binary_operator,
    canon,
    is_assignment_op,
    kids,
    kind_name,
    peel,
    tokens,
    unary_operator,
    value_unused,
)
from fwlens.standards.engines import detector


def _hit(ctx, cursor):
    line = cursor.location.line
    return line, ctx.line_text(line)


@detector("unused_call_result", "CALL_EXPR")
def unused_call_result(ctx, cursor, params):
    if cursor.type.kind.name != "VOID" and value_unused(ctx, cursor):
        yield _hit(ctx, cursor)


def _parameter_writes(body, parameters: set) -> list:
    """Nodes in ``body`` that assign to, step or take the address of one of the parameters."""
    out = []
    for n in body.walk_preorder():
        name = kind_name(n)
        target = None
        if (name == "BINARY_OPERATOR" and is_assignment_op(binary_operator(n))) or name == "COMPOUND_ASSIGNMENT_OPERATOR":
            target = kids(n)[0]
        elif name == "UNARY_OPERATOR" and unary_operator(n) in ("++", "--", "&"):
            target = kids(n)[0]
        if target is None:
            continue
        ref = peel(target)
        if kind_name(ref) == "DECL_REF_EXPR" and ref.referenced is not None and ref.referenced in parameters:
            out.append(n)
    return out


@detector("parameter_modified", "FUNCTION_DECL")
def parameter_modified(ctx, cursor, params):
    if not cursor.is_definition():
        return
    parameters = {k for k in kids(cursor) if kind_name(k) == "PARM_DECL"}
    if not parameters:
        return
    for node in _parameter_writes(cursor, parameters):
        yield _hit(ctx, node)


@detector("array_argument_size", "CALL_EXPR")
def array_argument_size(ctx, cursor, params):
    callee = cursor.referenced
    if callee is None or kind_name(callee) != "FUNCTION_DECL":
        return
    arguments = kids(cursor)[1:]
    for p, arg in zip(callee.get_arguments(), arguments, strict=False):
        pt = p.type
        if pt.kind.name != "CONSTANTARRAY":
            continue
        at = canon(peel(arg).type)
        if at.kind.name == "CONSTANTARRAY" and at.get_array_size() < pt.get_array_size():
            yield _hit(ctx, arg)


@detector("static_in_array_parameter", "PARM_DECL")
def static_in_array_parameter(ctx, cursor, params):
    toks = tokens(cursor)
    depth = 0
    for tok in toks:
        if tok == "[":
            depth += 1
        elif tok == "]":
            depth -= 1
        elif tok == "static" and depth > 0:
            yield _hit(ctx, cursor)
            return


@detector("bare_function_identifier", "DECL_REF_EXPR")
def bare_function_identifier(ctx, cursor, params):
    ref = cursor.referenced
    if ref is None or kind_name(ref) != "FUNCTION_DECL" or not ctx.parents:
        return
    parent = ctx.parents[-1]
    if kind_name(parent) == "UNARY_OPERATOR" and unary_operator(parent) == "&":
        return
    if kind_name(parent) == "UNEXPOSED_EXPR" and len(ctx.parents) > 1:
        grand = ctx.parents[-2]
        if kind_name(grand) == "CALL_EXPR" and kids(grand) and kids(grand)[0] == parent:
            return                             # f(...): the name followed by a parameter list
    if kind_name(parent) == "CALL_EXPR" and kids(parent) and kids(parent)[0] == cursor:
        return
    yield _hit(ctx, cursor)


@detector("function_length", "FUNCTION_DECL")
def function_length(ctx, cursor, params):
    if not cursor.is_definition():
        return
    limit = int(params.get("limit", 60))
    ext = cursor.extent
    if ext.end.line - ext.start.line + 1 > limit:
        yield _hit(ctx, cursor)


_ASSERT = re.compile(r"\b(?:assert|ASSERT|configASSERT|assert_param|static_assert)\s*\(")


@detector("assertion_density", "FUNCTION_DECL")
def assertion_density(ctx, cursor, params):
    if not cursor.is_definition():
        return
    ext = cursor.extent
    ctx.line_text(ext.start.line)                      # makes sure the file's lines are cached
    lines = ctx.file_cache.get(ctx.main, [])
    body = "\n".join(lines[ext.start.line - 1:ext.end.line])
    if len(_ASSERT.findall(body)) < int(params.get("minimum", 2)):
        yield _hit(ctx, cursor)
