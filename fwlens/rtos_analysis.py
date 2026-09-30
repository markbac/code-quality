"""
RTOS task/synchronisation analysis for fwlens. Currently implements embOS; the
config schema (fwlens.config.RTOSConfig) is written generically enough that another
RTOS could plug in by supplying its own function-name lists, but only embOS has
been tested and only embOS gets default function-name/argument-position values.

Interprets the raw RTOS API call sites already captured during the AST walk
(FunctionMetrics.rtos_calls, populated only for callee names in config.rtos's
configured lists) into RTOSTask / RTOSSyncObject / RTOSObjectUsage records, then
derives three analyses:

- Priority collisions: two tasks created at the same resolved priority.
- Priority inversion candidates: a counting semaphore (no priority inheritance in
  embOS -- OS_CSEMA) waited on by tasks of different priority. embOS's resource
  semaphore (OS_RSEMA, "mutex" here) has built-in priority inheritance/ownership
  tracking and is not flagged. See Sha, Rajkumar, Lehoczky (1990) for the general
  priority-inversion problem this is checking for.
- Unused objects: created but never touched by any configured usage function.

Task->object usage is attributed via the existing call graph (fwlens.graph.engines):
a usage call site belongs to every task whose entry function can reach it.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

import networkx as nx

from fwlens.config import FwLensConfig
from fwlens.model.project import (
    ProjectModel, RTOSInversionRisk, RTOSObjectUsage, RTOSPriorityCollision,
    RTOSSyncObject, RTOSTask,
)


def _normalise_var(text: str) -> str:
    """Strip a leading address-of operator and surrounding whitespace/parens."""
    t = text.strip()
    while t.startswith("(") and t.endswith(")"):
        t = t[1:-1].strip()
    if t.startswith("&"):
        t = t[1:].strip()
    return t


def _try_int(text: str) -> Optional[int]:
    """
    Parse a call argument as an integer literal, tolerant of a leading C-style cast.
    libclang expands macros before fwlens ever sees the AST, so a literal passed through
    an older convenience macro (e.g. embOS's OS_TASK_CREATE) often arrives wrapped in a
    cast inserted by the macro body, like "(OS_PRIO)(5)" for a plain "5" at the call site --
    strip that off before giving up on parsing it as a number.
    """
    if not text:
        return None
    t = text.strip()
    # Strip one or more leading "(SomeType)" casts, and surrounding redundant parens.
    cast_re = re.compile(r'^\(\s*[A-Za-z_][A-Za-z0-9_ ]*\)\s*')
    while True:
        new_t = cast_re.sub('', t)
        if new_t == t:
            break
        t = new_t.strip()
    while t.startswith("(") and t.endswith(")"):
        t = t[1:-1].strip()
    t = t.rstrip("uUlL")
    try:
        return int(t, 0)
    except ValueError:
        return None


def _arg(args: list[str], positions: dict, key: str) -> str:
    idx = positions.get(key)
    if idx is None or idx >= len(args):
        return ""
    return args[idx]


def _build_task(call: dict, config: FwLensConfig, file: Path) -> RTOSTask:
    args = call["args"]
    positions = config.rtos.task_functions.get(call["callee"], {})

    tcb_var = _normalise_var(_arg(args, positions, "tcb"))
    name_raw = _arg(args, positions, "name").strip()
    name = name_raw[1:-1] if name_raw.startswith('"') and name_raw.endswith('"') else name_raw
    priority_expr = _arg(args, positions, "priority")
    routine = _normalise_var(_arg(args, positions, "routine"))
    stack_expr = _normalise_var(_arg(args, positions, "stack"))
    stack_size_expr = _arg(args, positions, "stack_size")

    return RTOSTask(
        name=name or tcb_var or f"<task@{call['line']}>",
        tcb_var=tcb_var,
        priority_expr=priority_expr,
        priority_value=_try_int(priority_expr),
        entry_function=routine,
        stack_expr=stack_expr,
        stack_size_expr=stack_size_expr,
        stack_size_value=_try_int(stack_size_expr),
        creation_function=call["callee"],
        file=file,
        line=call["line"],
    )


def _build_sync_object(kind: str, call: dict, file: Path, config: FwLensConfig) -> RTOSSyncObject:
    if call["callee"] in config.rtos.return_value_functions:
        # FreeRTOS-style: handle comes back via return value (`q = xQueueCreate(...)`),
        # not an output-pointer argument -- the AST walker captured the assignment
        # target separately since it isn't one of the call's own arguments.
        var = call.get("assigned_var") or f"<unassigned@{call['line']}>"
    else:
        args = call["args"]
        var = _normalise_var(args[0]) if args else f"<unnamed@{call['line']}>"
    return RTOSSyncObject(
        kind=kind, var_name=var, creation_function=call["callee"], file=file, line=call["line"],
    )


def _classify_access(callee: str, config: FwLensConfig) -> str:
    """
    Signal keywords are checked before wait keywords: some signal-side names (e.g.
    OS_MUTEX_Unlock) contain a substring ("Lock") that would otherwise also match a
    wait keyword, so checking signal first and returning immediately avoids that.
    """
    lower = callee.lower()
    if any(kw.lower() in lower for kw in config.rtos.signal_keywords):
        return "signal"
    if any(kw.lower() in lower for kw in config.rtos.wait_keywords):
        return "wait"
    return "other"


def _compute_priority_collisions(tasks: list[RTOSTask]) -> list[RTOSPriorityCollision]:
    by_prio: dict[int, list[str]] = {}
    for t in tasks:
        if t.priority_value is not None:
            by_prio.setdefault(t.priority_value, []).append(t.name)
    return [
        RTOSPriorityCollision(priority_value=p, task_names=names)
        for p, names in sorted(by_prio.items()) if len(names) > 1
    ]


def _compute_inversion_risks(
    sync_objects: list[RTOSSyncObject], usages: list[RTOSObjectUsage], tasks: list[RTOSTask],
) -> list[RTOSInversionRisk]:
    task_priority = {t.name: t.priority_value for t in tasks}
    # Only plain counting semaphores lack priority inheritance in embOS -- mutexes
    # (OS_MUTEX_Create, priority-inheriting) and reader/writer locks are not flagged.
    semaphore_vars = {o.var_name for o in sync_objects if o.kind == "semaphore"}

    by_object: dict[str, set[str]] = {}
    for u in usages:
        if u.object_var in semaphore_vars and u.access_kind == "wait" and u.task_name != "(unassigned)":
            by_object.setdefault(u.object_var, set()).add(u.task_name)

    risks = []
    for obj_var, task_names in by_object.items():
        priorities = [task_priority.get(t) for t in sorted(task_names)]
        distinct = {p for p in priorities if p is not None}
        if len(distinct) > 1:
            risks.append(RTOSInversionRisk(
                object_var=obj_var, task_names=sorted(task_names), priorities=priorities,
            ))
    return risks


def _compute_unused(
    sync_objects: list[RTOSSyncObject], usages: list[RTOSObjectUsage],
) -> list[RTOSSyncObject]:
    used_vars = {u.object_var for u in usages}
    return [o for o in sync_objects if o.var_name not in used_vars]


def _build_task_from_table_entry(entry: dict, field_map: dict) -> Optional[RTOSTask]:
    """
    Turn one recovered task-table entry ({fields: {member_name: value_text}, ...})
    into an RTOSTask using the configured struct-member-name mapping
    (config.rtos.task_table_types[type_name]).
    """
    fields = entry.get("fields", {})

    def _get(key: str) -> str:
        member_name = field_map.get(key)
        if not member_name:
            return ""
        return fields.get(member_name, "")

    tcb_var = _normalise_var(_get("tcb"))
    name_raw = _get("name").strip()
    name = name_raw[1:-1] if name_raw.startswith('"') and name_raw.endswith('"') else name_raw
    priority_expr = _get("priority")
    routine = _normalise_var(_get("routine"))
    stack_expr = _normalise_var(_get("stack"))
    stack_size_expr = _get("stack_size")

    if not tcb_var and not name and not routine:
        return None

    return RTOSTask(
        name=name or tcb_var or f"<task@{entry.get('line', '?')}>",
        tcb_var=tcb_var,
        priority_expr=priority_expr,
        priority_value=_try_int(priority_expr),
        entry_function=routine,
        stack_expr=stack_expr,
        stack_size_expr=stack_size_expr,
        stack_size_value=_try_int(stack_size_expr),
        creation_function=f"<table:{entry.get('type_name', '?')}>",
        file=entry.get("file"),
        line=entry.get("line", 0),
    )


def _looks_like_unresolved_table_loop(task: RTOSTask) -> bool:
    """
    True if a call-site-derived task is clearly a generic "create everything in this
    table" loop rather than a real, distinct task -- i.e. its tcb/routine are runtime
    struct-member accesses (contain "->" or ".") rather than concrete identifiers. A
    genuinely resolvable direct call (even one with an unresolved priority/stack
    literal) still has a plain named tcb/routine; only the generic-loop pattern
    leaves member-access syntax in both. Reported once by the task-table detection
    instead (when config.rtos.task_table_types is set) or not at all otherwise --
    either way, a single misleading "task" named after a struct field is noise.
    """
    indirect = lambda s: ("->" in s) or ("." in s and not s.startswith('"'))
    return bool(task.tcb_var) and bool(task.entry_function) and \
        indirect(task.tcb_var) and indirect(task.entry_function)


def run_rtos_analysis(model: ProjectModel, config: FwLensConfig) -> None:
    """Populate model.rtos_* from FunctionMetrics.rtos_calls. No-op if rtos.kind == 'none'."""
    model.rtos_kind = config.rtos.kind
    if config.rtos.kind == "none":
        return

    task_fns = set(config.rtos.task_functions.keys())
    sem_fns = set(config.rtos.semaphore_functions)
    mutex_fns = set(config.rtos.mutex_functions)
    mb_fns = set(config.rtos.mailbox_functions)
    q_fns = set(config.rtos.queue_functions)
    ev_fns = set(config.rtos.event_functions)
    rwlock_fns = set(config.rtos.rwlock_functions)
    usage_fns = set(config.rtos.usage_functions)

    tasks: list[RTOSTask] = []
    sync_objects: list[RTOSSyncObject] = []
    raw_usages: list[tuple] = []  # (object_var, used_by_function, callee, file, line)

    for f in model.all_functions():
        for call in f.rtos_calls:
            callee = call["callee"]
            if callee in task_fns:
                t = _build_task(call, config, f.file)
                if not _looks_like_unresolved_table_loop(t):
                    tasks.append(t)
            elif callee in sem_fns:
                sync_objects.append(_build_sync_object("semaphore", call, f.file, config))
            elif callee in mutex_fns:
                sync_objects.append(_build_sync_object("mutex", call, f.file, config))
            elif callee in mb_fns:
                sync_objects.append(_build_sync_object("mailbox", call, f.file, config))
            elif callee in q_fns:
                sync_objects.append(_build_sync_object("queue", call, f.file, config))
            elif callee in ev_fns:
                sync_objects.append(_build_sync_object("event", call, f.file, config))
            elif callee in rwlock_fns:
                sync_objects.append(_build_sync_object("rwlock", call, f.file, config))
            elif callee in usage_fns:
                var = _normalise_var(call["args"][0]) if call["args"] else ""
                raw_usages.append((var, f.name, callee, f.file, call["line"]))

    model.rtos_tasks = tasks
    model.rtos_sync_objects = sync_objects

    # Task descriptor tables (static const array-of-struct, generic creation loop) --
    # a separate detection path from call-site-based task_functions above, since the
    # real per-task data lives in the array's initializer, not at OS_TASK_Create's
    # (runtime-indirect, pTask->field) call site in this pattern.
    task_table_types = config.rtos.task_table_types
    if task_table_types:
        for entry in model.task_table_entries:
            type_name = entry.get("type_name")
            field_map = task_table_types.get(type_name)
            if not field_map:
                continue
            t = _build_task_from_table_entry(entry, field_map)
            if t is not None:
                tasks.append(t)

    # Attribute each usage call site to every task whose entry function can reach it,
    # via the call graph the graph engine already built.
    call_graph: Optional[nx.DiGraph] = getattr(model, "_call_graph", None)
    func_to_tasks: dict[str, list[str]] = {}
    if call_graph is not None:
        for t in tasks:
            if not t.entry_function:
                continue
            reachable = {t.entry_function}
            if t.entry_function in call_graph:
                reachable |= nx.descendants(call_graph, t.entry_function)
            for fn in reachable:
                func_to_tasks.setdefault(fn, []).append(t.name)

    usages: list[RTOSObjectUsage] = []
    for var, used_by, callee, file, line in raw_usages:
        access_kind = _classify_access(callee, config)
        owning_tasks = func_to_tasks.get(used_by) or ["(unassigned)"]
        for task_name in owning_tasks:
            usages.append(RTOSObjectUsage(
                object_var=var, task_name=task_name, used_by_function=used_by,
                access_kind=access_kind, file=file, line=line,
            ))
    model.rtos_object_usages = usages

    model.rtos_priority_collisions = _compute_priority_collisions(tasks)
    model.rtos_inversion_risks = _compute_inversion_risks(sync_objects, usages, tasks)
    model.rtos_unused_objects = _compute_unused(sync_objects, usages)
