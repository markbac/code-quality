"""
Control-flow detectors: unreachable code, goto and label rules, loop and switch rules, controlling
expressions (MISRA C:2012 rules 2.1, 2.2, 2.6, 14.x, 15.x and 16.x).
"""

from __future__ import annotations

from fwlens.standards.astutil import (
    JUMPS,
    LABELS,
    LOOPS,
    binary_operator,
    condition_of,
    const_int,
    for_parts,
    has_side_effect,
    is_assignment_op,
    kids,
    kind_name,
    peel,
    terminal,
    unary_operator,
)
from fwlens.standards.engines import detector, finisher
from fwlens.standards.essential import essential


def _hit(ctx, cursor):
    line = cursor.location.line
    return line, ctx.line_text(line)


def _nested_in_loop_or_switch(kind: str) -> bool:
    return kind in LOOPS or kind == "SWITCH_STMT"


def _breaks_out(loop) -> bool:
    """True if a break in the loop's body ends this loop, or a goto may leave it."""
    stack = [(k, False) for k in kids(loop)]
    start, end = loop.extent.start.offset, loop.extent.end.offset
    while stack:
        node, nested = stack.pop()
        name = kind_name(node)
        if name == "BREAK_STMT" and not nested:
            return True
        if name == "GOTO_STMT":
            label = next(iter(kids(node)), None)
            target = label.referenced if label is not None else None
            if target is None or not (start <= target.extent.start.offset <= end):
                return True
        inside = nested or _nested_in_loop_or_switch(name)
        stack.extend((k, inside) for k in kids(node))
    return False


def _is_infinite(loop) -> bool:
    name = kind_name(loop)
    if name == "FOR_STMT":
        cond = for_parts(loop)[1]
        return cond is None or const_int(cond) not in (None, 0)
    cond = condition_of(loop)
    value = const_int(cond) if cond is not None else None
    return name in ("WHILE_STMT",) and value not in (None, 0)


# --- MISRA 2.1, 2.2: unreachable and dead code -------------------------------------------------------

@detector("unreachable_code", "COMPOUND_STMT")
def unreachable_code(ctx, cursor, params):
    statements = kids(cursor)
    for i, stmt in enumerate(statements[:-1]):
        last = terminal(stmt)
        name = kind_name(last)
        ends = name in JUMPS or (name in LOOPS and _is_infinite(last) and not _breaks_out(last))
        if not ends:
            continue
        for follower in statements[i + 1:]:
            fname = kind_name(follower)
            if fname in LABELS:
                break                       # a label makes what follows reachable
            if fname in ("NULL_STMT", "DECL_STMT"):
                continue
            yield _hit(ctx, follower)
            break
        else:
            continue
        break


@detector("no_effect_statement", "COMPOUND_STMT")
def no_effect_statement(ctx, cursor, params):
    for stmt in kids(cursor):
        name = kind_name(stmt)
        if not (name.endswith(("_EXPR", "_OPERATOR", "_LITERAL")) or name == "UNEXPOSED_EXPR"):
            continue
        if name == "CSTYLE_CAST_EXPR" and stmt.type.spelling == "void":
            continue                        # (void)x; is the accepted way to say "unused"
        if name == "CALL_EXPR" or has_side_effect(None, stmt):
            continue
        if any(node.type.is_volatile_qualified() for node in stmt.walk_preorder()
               if kind_name(node) in ("DECL_REF_EXPR", "MEMBER_REF_EXPR")):
            continue                        # reading a volatile object is an effect
        yield _hit(ctx, stmt)


@detector("unused_label", "LABEL_STMT", "GOTO_STMT", "ADDR_LABEL_EXPR")
def unused_label_visit(ctx, cursor, params):
    state = ctx.state.setdefault("labels", {"defs": [], "refs": set()})
    name = kind_name(cursor)
    if name == "LABEL_STMT":
        state["defs"].append((ctx.function, cursor.spelling, cursor.location.line))
    else:
        for k in kids(cursor):
            if kind_name(k) == "LABEL_REF":
                state["refs"].add((ctx.function, k.spelling))
        if name == "ADDR_LABEL_EXPR":
            state["refs"].add((ctx.function, cursor.spelling))
    return ()


@finisher("unused_label")
def unused_label_finish(ctx, params):
    state = ctx.state.get("labels")
    if not state:
        return
    for function, label, line in state["defs"]:
        if (function, label) not in state["refs"]:
            yield line, ctx.line_text(line), function


# --- MISRA 15.x: goto, break, single exit, else-if ---------------------------------------------------------

def _goto_target(cursor):
    label = next((k for k in kids(cursor) if kind_name(k) == "LABEL_REF"), None)
    return label.referenced if label is not None else None


@detector("goto_backward", "GOTO_STMT")
def goto_backward(ctx, cursor, params):
    target = _goto_target(cursor)
    if target is not None and target.extent.start.offset < cursor.extent.start.offset:
        yield _hit(ctx, cursor)


@detector("goto_label_block", "GOTO_STMT")
def goto_label_block(ctx, cursor, params):
    target = _goto_target(cursor)
    function = ctx.enclosing("FUNCTION_DECL")
    if target is None or function is None:
        return
    blocks = ctx.state.setdefault("label_blocks", {})
    key = hash(function)
    if key not in blocks:
        mapping: dict[str, object] = {}

        def walk(node, block):
            if kind_name(node) == "LABEL_STMT":
                mapping[node.spelling] = block
            nxt = node if kind_name(node) == "COMPOUND_STMT" else block
            for k in kids(node):
                walk(k, nxt)
        walk(function, None)
        blocks[key] = mapping
    block = blocks[key].get(target.spelling)
    if block is not None and not any(p == block for p in ctx.parents):
        yield _hit(ctx, cursor)


@detector("loop_exit_count", *LOOPS)
def loop_exit_count(ctx, cursor, params):
    start, end = cursor.extent.start.offset, cursor.extent.end.offset
    count = 0
    stack = [(k, False) for k in kids(cursor)]
    while stack:
        node, nested = stack.pop()
        name = kind_name(node)
        if name == "BREAK_STMT" and not nested:
            count += 1
        elif name == "GOTO_STMT":
            target = _goto_target(node)
            if target is None or not (start <= target.extent.start.offset <= end):
                count += 1
        inside = nested or _nested_in_loop_or_switch(name)
        stack.extend((k, inside) for k in kids(node))
    if count > 1:
        yield _hit(ctx, cursor)


@detector("single_exit", "FUNCTION_DECL")
def single_exit(ctx, cursor, params):
    if not cursor.is_definition():
        return
    body = next((k for k in kids(cursor) if kind_name(k) == "COMPOUND_STMT"), None)
    if body is None:
        return
    returns = [n for n in body.walk_preorder() if kind_name(n) == "RETURN_STMT"]
    statements = kids(body)
    last_is_return = bool(statements) and kind_name(statements[-1]) == "RETURN_STMT"
    if len(returns) > 1 or (len(returns) == 1 and not last_is_return):
        yield _hit(ctx, cursor)


@detector("else_if_without_else", "IF_STMT")
def else_if_without_else(ctx, cursor, params):
    parent = ctx.parents[-1] if ctx.parents else None
    if parent is not None and kind_name(parent) == "IF_STMT":
        siblings = kids(parent)
        if len(siblings) > 2 and siblings[2] == cursor:
            return                          # an inner link of a chain, the chain's head reports it
    node, is_chain = cursor, False
    while True:
        parts = kids(node)
        if len(parts) > 2 and kind_name(parts[2]) == "IF_STMT":
            node, is_chain = parts[2], True
            continue
        break
    if is_chain and len(kids(node)) <= 2:
        yield _hit(ctx, node)


# --- MISRA 16.x: switch statements --------------------------------------------------------------------------

def switch_clauses(switch) -> list[dict] | None:
    """Split a switch body into clauses: {'labels': [...], 'stmts': [...]}. None if the body has no braces."""
    parts = kids(switch)
    body = parts[-1] if len(parts) > 1 else None
    if body is None or kind_name(body) != "COMPOUND_STMT":
        return None
    clauses: list[dict] = []
    for stmt in kids(body):
        if kind_name(stmt) in ("CASE_STMT", "DEFAULT_STMT"):
            labels, node = [stmt], stmt
            while True:
                inner = kids(node)
                nxt = inner[-1] if inner else None
                if nxt is not None and kind_name(nxt) in ("CASE_STMT", "DEFAULT_STMT"):
                    labels.append(nxt)
                    node = nxt
                    continue
                break
            first = kids(node)[-1] if kids(node) else None
            if first is not None and kind_name(node) == "CASE_STMT" and len(kids(node)) < 2:
                first = None
            clauses.append({"labels": labels, "stmts": [first] if first is not None else []})
        elif clauses:
            clauses[-1]["stmts"].append(stmt)
    return clauses


def _ends_with_break(stmts: list) -> bool:
    return bool(stmts) and kind_name(terminal(stmts[-1])) == "BREAK_STMT"


@detector("switch_break_terminated", "SWITCH_STMT")
def switch_break_terminated(ctx, cursor, params):
    for clause in switch_clauses(cursor) or ():
        if clause["stmts"] and not _ends_with_break(clause["stmts"]):
            yield _hit(ctx, clause["labels"][-1])
        elif not clause["stmts"]:
            yield _hit(ctx, clause["labels"][-1])


def _direct_labels(switch) -> list:
    parts = kids(switch)
    body = parts[-1] if len(parts) > 1 else None
    out: list = []

    def walk(node):
        for k in kids(node):
            name = kind_name(k)
            if name == "SWITCH_STMT":
                continue                    # labels of a nested switch belong to it
            if name in ("CASE_STMT", "DEFAULT_STMT"):
                out.append(k)
            walk(k)
    if body is not None:
        walk(body)
    return out


@detector("switch_default", "SWITCH_STMT")
def switch_default(ctx, cursor, params):
    if not any(kind_name(label) == "DEFAULT_STMT" for label in _direct_labels(cursor)):
        yield _hit(ctx, cursor)


@detector("switch_default_position", "SWITCH_STMT")
def switch_default_position(ctx, cursor, params):
    labels = _direct_labels(cursor)
    names = [kind_name(label) for label in labels]
    if "DEFAULT_STMT" in names and len(labels) > 2:
        index = names.index("DEFAULT_STMT")
        if index not in (0, len(labels) - 1):
            yield _hit(ctx, labels[index])


@detector("switch_min_clauses", "SWITCH_STMT")
def switch_min_clauses(ctx, cursor, params):
    clauses = switch_clauses(cursor)
    if clauses is not None and len(clauses) < 2:
        yield _hit(ctx, cursor)


@detector("switch_boolean", "SWITCH_STMT")
def switch_boolean(ctx, cursor, params):
    cond = condition_of(cursor)
    ess = essential(cond) if cond is not None else None
    if ess is not None and ess.cat == "boolean":
        yield _hit(ctx, cursor)


@detector("switch_label_placement", "CASE_STMT", "DEFAULT_STMT")
def switch_label_placement(ctx, cursor, params):
    for p in reversed(ctx.parents):
        name = kind_name(p)
        if name == "COMPOUND_STMT":
            idx = ctx.parents.index(p)
            owner = ctx.parents[idx - 1] if idx > 0 else None
            if owner is None or kind_name(owner) != "SWITCH_STMT":
                yield _hit(ctx, cursor)
            return
        if name not in LABELS:
            return


@detector("switch_well_formed", "SWITCH_STMT")
def switch_well_formed(ctx, cursor, params):
    """Rule 16.1 as the union of its parts: braces, default, clause count, break-terminated clauses."""
    problems = []
    clauses = switch_clauses(cursor)
    if clauses is None:
        problems.append(cursor)
    else:
        if len(clauses) < 2 or not any(kind_name(label) == "DEFAULT_STMT" for label in _direct_labels(cursor)):
            problems.append(cursor)
        problems.extend(clause["labels"][-1] for clause in clauses
                        if not clause["stmts"] or not _ends_with_break(clause["stmts"]))
    for c in problems[:1]:
        yield _hit(ctx, c)


# --- MISRA 14.x: loops and controlling expressions --------------------------------------------------------

def _is_idiomatic_infinite(cursor, cond) -> bool:
    name = kind_name(cursor)
    if cond is None:
        return True                          # for (;;)
    value = const_int(cond)
    if name == "WHILE_STMT" or name == "FOR_STMT":
        return value is not None and value != 0
    if name == "DO_STMT":
        return value == 0                    # the do { } while (0) macro idiom
    return False


@detector("invariant_condition", "IF_STMT", "WHILE_STMT", "DO_STMT", "FOR_STMT", "CONDITIONAL_OPERATOR")
def invariant_condition(ctx, cursor, params):
    cond = condition_of(cursor)
    if cond is None or const_int(cond) is None:
        return
    if _is_idiomatic_infinite(cursor, cond):
        return
    yield _hit(ctx, cond)


@detector("non_boolean_condition", "IF_STMT", "WHILE_STMT", "DO_STMT", "FOR_STMT", "CONDITIONAL_OPERATOR")
def non_boolean_condition(ctx, cursor, params):
    cond = condition_of(cursor)
    if cond is None:
        return
    ess = essential(cond)
    if ess is not None and ess.cat != "boolean":
        yield _hit(ctx, cond)
    elif ess is None and peel(cond).type.get_canonical().kind.name in ("POINTER", "ENUM"):
        yield _hit(ctx, cond)


def _referenced_vars(node):
    return [n.referenced for n in node.walk_preorder() if kind_name(n) == "DECL_REF_EXPR" and n.referenced is not None
            and kind_name(n.referenced) in ("VAR_DECL", "PARM_DECL")]


def _modified_vars(node) -> list:
    out = []
    for n in node.walk_preorder():
        name = kind_name(n)
        target = None
        if name == "BINARY_OPERATOR" and is_assignment_op(binary_operator(n)):
            target = kids(n)[0]
        elif name == "COMPOUND_ASSIGNMENT_OPERATOR":
            target = kids(n)[0]
        elif name == "UNARY_OPERATOR" and unary_operator(n) in ("++", "--"):
            target = kids(n)[0]
        if target is not None:
            ref = peel(target)
            if kind_name(ref) == "DECL_REF_EXPR" and ref.referenced is not None:
                out.append(ref.referenced)
    return out


@detector("float_loop_counter", "FOR_STMT")
def float_loop_counter(ctx, cursor, params):
    _, cond, inc, _ = for_parts(cursor)
    if cond is None or inc is None:
        return
    counters = _modified_vars(inc)
    for var in _referenced_vars(cond):
        if var in counters and var.type.get_canonical().kind.name in ("FLOAT", "DOUBLE", "LONGDOUBLE", "HALF"):
            yield _hit(ctx, cursor)
            return


@detector("for_loop_well_formed", "FOR_STMT")
def for_loop_well_formed(ctx, cursor, params):
    init, cond, inc, body = for_parts(cursor)
    if cond is None or inc is None:
        yield _hit(ctx, cursor)
        return
    counters = _modified_vars(inc)
    if len(set(counters)) != 1 or counters[0] not in _referenced_vars(cond):
        yield _hit(ctx, cursor)
        return
    counter = counters[0]
    if body is not None and (counter in _modified_vars(body) or any(
            kind_name(n) == "UNARY_OPERATOR" and unary_operator(n) == "&" and
            counter in _referenced_vars(n) for n in body.walk_preorder())):
        yield _hit(ctx, cursor)


# --- declarations before the first case, assignments in conditions, empty bodies ------------------------

@detector("declaration_before_case", "SWITCH_STMT")
def declaration_before_case(ctx, cursor, params):
    parts = kids(cursor)
    body = parts[-1] if len(parts) > 1 else None
    if body is None or kind_name(body) != "COMPOUND_STMT":
        return
    for stmt in kids(body):
        name = kind_name(stmt)
        if name in ("CASE_STMT", "DEFAULT_STMT"):
            return
        if name == "DECL_STMT":
            yield _hit(ctx, stmt)


@detector("assignment_in_condition", "IF_STMT", "WHILE_STMT", "DO_STMT", "FOR_STMT", "CONDITIONAL_OPERATOR")
def assignment_in_condition(ctx, cursor, params):
    cond = condition_of(cursor)
    if cond is None:
        return
    inner = peel(cond)
    name = kind_name(inner)
    if name == "COMPOUND_ASSIGNMENT_OPERATOR" or (name == "BINARY_OPERATOR" and is_assignment_op(binary_operator(inner))):
        yield _hit(ctx, inner)


@detector("empty_control_body", "IF_STMT", "WHILE_STMT", "FOR_STMT")
def empty_control_body(ctx, cursor, params):
    parts = kids(cursor)
    if kind_name(cursor) == "IF_STMT":
        body = parts[1] if len(parts) > 1 else None
    else:
        body = parts[-1] if parts else None
    if body is not None and kind_name(body) == "NULL_STMT":
        yield _hit(ctx, cursor)
