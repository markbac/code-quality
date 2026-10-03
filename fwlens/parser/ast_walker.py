"""
libclang AST walker for fwlens.

For each translation unit, walks the AST and extracts:
- Functions with their metrics (CC, Halstead, LOC, block depth, parameters, etc.)
- Global variable declarations and accesses
- Include relationships
- Call relationships
- Magic numbers, assert calls, return paths

IAR compat defines are injected as clang args to prevent parse failures.
"""

from __future__ import annotations

import math
import os
from pathlib import Path
from typing import Optional

_MODULE_VERSION = "ast_walker-0.5.1"  # fixed: defensive CursorKind access via getattr

from fwlens.config import FwLensConfig, macro_name
from fwlens.model.project import FunctionMetrics, GlobalAccess, GlobalVarInfo, ParameterInfo
from fwlens.parser.ewp import TranslationUnit
from fwlens.sysinc import detect_system_includes, target_args

# Lazy import -- clang may not be available until venv is set up
_clang_available = False
_clang = None

def _ensure_clang(config: FwLensConfig):
    global _clang_available, _clang
    if _clang_available:
        return
    from fwlens.libclang_locate import locate_libclang, LibclangError
    try:
        location = locate_libclang(config.tool.libclang_path)
    except LibclangError as e:
        raise RuntimeError(str(e))
    try:
        import clang.cindex as ci
        if location.path is not None:
            ci.Config.set_library_file(str(location.path))
        _clang = ci
        _clang_available = True
    except Exception as e:
        raise RuntimeError(
            "libclang not available. Install FWLens with its dependencies, or set "
            "tool.libclang_path / LIBCLANG_PATH.\n"
            f"Original error: {e}"
        )


_ASSERT_NAMES = frozenset([
    "assert", "ASSERT", "PSP_ASSERT", "STATIC_ASSERT",
    "_Static_assert", "static_assert",
])

_MAGIC_EXEMPT = frozenset(["0", "1", "-1", "0u", "1u", "0U", "1U",
                            "0x0", "0x1", "0x00", "0xFF", "true", "false",
                            "NULL", "nullptr"])

_ISR_ATTRS = frozenset([
    "__interrupt", "__irq", "__fiq", "__swi",
    "IRQHandler",  # suffix convention on Cortex-M
])

# Standard ARM Cortex-M exception/fault handler names -- fixed by the CMSIS/ARM
# architecture itself (not a project-specific naming convention like _IRQHandler
# is), so these are safe to match by exact name across any Cortex-M codebase.
# None of these end in "_IRQHandler", so the suffix check alone misses them --
# HardFault_Handler etc. are genuinely interrupt/exception context just as much
# as a peripheral IRQ handler is.
_ISR_EXACT_NAMES = frozenset([
    "NMI_Handler", "HardFault_Handler", "MemManage_Handler", "BusFault_Handler",
    "UsageFault_Handler", "SVC_Handler", "DebugMon_Handler", "PendSV_Handler",
    "SysTick_Handler", "Reset_Handler",
])


def _is_isr(cursor) -> bool:
    """Heuristic ISR detection: IAR attributes, _IRQHandler suffix, or a standard
    ARM Cortex-M exception/fault handler name."""
    name = cursor.spelling or ""
    if name.endswith("IRQHandler") or name.endswith("_IRQHandler"):
        return True
    if name in _ISR_EXACT_NAMES:
        return True
    # Check tokens for IAR attributes
    try:
        for tok in cursor.get_tokens():
            if tok.spelling in _ISR_ATTRS:
                return True
    except Exception:
        pass
    return False


def _token_text_toplevel(ci_module, arg_cursor) -> str:
    """
    Module-level twin of _FunctionVisitor._arg_text -- same DFS-with-tokens
    fallback (see that method's docstring for why the fallback is needed), used
    for top-level (file-scope) initializer walking where there's no
    _FunctionVisitor instance to call the method on. Deliberately duplicated
    rather than shared to avoid touching the already-working per-function path.
    """
    try:
        direct = "".join(t.spelling for t in arg_cursor.get_tokens())
    except Exception:
        direct = ""
    if direct:
        return direct

    best = [""]

    def visit(c):
        if best[0]:
            return
        try:
            ref = c.referenced
        except ValueError:
            ref = None
        decl_ref = getattr(ci_module.CursorKind, 'DECL_REF_EXPR', None)
        if decl_ref and c.kind == decl_ref and ref and ref.spelling:
            best[0] = ref.spelling
            return
        try:
            toks = "".join(t.spelling for t in c.get_tokens())
        except Exception:
            toks = ""
        if toks:
            best[0] = toks
            return
        for child in c.get_children():
            visit(child)
            if best[0]:
                return

    visit(arg_cursor)
    return best[0]


def _extract_task_table_entries(cursor, type_name: str, ci_module) -> list[dict]:
    """
    Given a VAR_DECL cursor for a `static const SomeStruct SomeList[] = {...}`
    array and the resolved element struct type name, walk the array's initializer
    and return one dict of {member_name: value_text} per array element (one dict
    per task descriptor). Relies on C99 designated-initializer structure: each
    element is an INIT_LIST_EXPR whose children are UNEXPOSED_EXPR nodes wrapping
    exactly [MEMBER_REF (the field name), value expression].
    """
    member_ref_kind = getattr(ci_module.CursorKind, 'MEMBER_REF', None)
    init_list_kind = getattr(ci_module.CursorKind, 'INIT_LIST_EXPR', None)
    if member_ref_kind is None or init_list_kind is None:
        return []

    outer_init = None
    for child in cursor.get_children():
        if child.kind == init_list_kind:
            outer_init = child
            break
    if outer_init is None:
        return []

    entries: list[dict] = []
    for element in outer_init.get_children():
        if element.kind != init_list_kind:
            continue
        fields: dict[str, str] = {}
        for pair in element.get_children():
            kids = list(pair.get_children())
            member_cursor = None
            value_cursor = None
            for k in kids:
                if k.kind == member_ref_kind and member_cursor is None:
                    member_cursor = k
                else:
                    value_cursor = k
            if member_cursor is None or value_cursor is None:
                continue
            field_name = member_cursor.spelling
            if field_name:
                value_text = _token_text_toplevel(ci_module, value_cursor)
                if not value_text:
                    # Defensive fallback: per-child extraction can come back empty for
                    # AST shapes this wasn't specifically tested against (e.g. under a
                    # degraded/error-recovery parse from an unresolved header elsewhere
                    # in the TU). Try the raw tokens of the whole ".field = value" pair
                    # and strip the leading "field=" textually as a last resort, rather
                    # than silently losing the value.
                    try:
                        pair_text = "".join(t.spelling for t in pair.get_tokens())
                    except Exception:
                        pair_text = ""
                    prefix = f".{field_name}="
                    if pair_text.startswith(prefix):
                        value_text = pair_text[len(prefix):]
                    elif pair_text.startswith(f"{field_name}="):
                        value_text = pair_text[len(field_name) + 1:]
                fields[field_name] = value_text
        if fields:
            entries.append(fields)
    return entries


class _FunctionVisitor:
    """
    Walks a single function cursor and collects all metrics.
    """

    def __init__(self, cursor, tu_path: Path, config: FwLensConfig):
        self.cursor = cursor
        self.tu_path = tu_path
        self.config = config
        self.ci = _clang
        # Configurable assert-macro names (config.assert_names) with the module
        # default as a fallback -- lets a project-specific assert macro (e.g.
        # embOS's OS_ASSERT) be recognised without a code change.
        self._assert_names = set(getattr(config, "assert_names", None) or _ASSERT_NAMES)

        self.cc = 1  # base
        self.cognitive = 0
        self.max_depth = 0
        self.current_depth = 0
        self.return_count = 0
        self.magic_numbers: list[str] = []
        self.assert_count = 0
        self.loc = 0
        self.callees: set[str] = set()
        self.indirect_call_count: int = 0   # calls through function pointers
        self.global_reads: list[str] = []
        self.global_writes: list[str] = []
        # RTOS API calls (e.g. embOS OS_CreateTask/OS_CreateCSema/...) made by this
        # function -- only populated for callee names in config.rtos's function lists
        self.rtos_calls: list[dict] = []
        # Switch-based state-machine candidates found in this function
        self.state_machines: list[dict] = []

        # Halstead raw counts
        self._operators: list[str] = []
        self._operands: list[str] = []

        self.parameters: list[ParameterInfo] = []
        self._param_names: set[str] = set()
        self._mutated_params: set[str] = set()

        # Build CursorKind sets once, guarding against names missing in older bindings.
        # Some names vary between clang Python binding versions.
        ci = _clang
        def _ck(*names):
            """Return a frozenset of CursorKind values for the given names, skipping any missing."""
            result = set()
            for name in names:
                kind = getattr(ci.CursorKind, name, None)
                if kind is not None:
                    result.add(kind)
            return frozenset(result)

        self._branch_kinds = _ck(
            'IF_STMT', 'WHILE_STMT', 'FOR_STMT', 'DO_STMT',
            'CASE_STMT', 'CONDITIONAL_OPERATOR',
        )
        self._compound_stmt = _ck('COMPOUND_STMT')
        self._return_stmt   = _ck('RETURN_STMT')
        self._call_expr     = _ck('CALL_EXPR')
        self._decl_ref      = _ck('DECL_REF_EXPR')
        self._int_lit       = _ck('INTEGER_LITERAL')
        self._binary_op     = _ck('BINARY_OPERATOR')
        self._unary_op      = _ck('UNARY_OPERATOR')
        self._switch_stmt   = _ck('SWITCH_STMT')
        self._case_stmt     = _ck('CASE_STMT')
        self._default_stmt  = _ck('DEFAULT_STMT')
        self._assign_kinds  = _ck(
            'COMPOUND_ASSIGN_OPERATOR',   # clang >= 14
            'COMPOUND_ASSIGNMENT_OPERATOR',  # older bindings
        )
        self._op_kinds = _ck(
            'BINARY_OPERATOR', 'UNARY_OPERATOR',
            'COMPOUND_ASSIGN_OPERATOR', 'COMPOUND_ASSIGNMENT_OPERATOR',
            'CONDITIONAL_OPERATOR', 'IF_STMT', 'WHILE_STMT', 'FOR_STMT',
            'DO_STMT', 'SWITCH_STMT', 'CALL_EXPR',
            'ARRAY_SUBSCRIPT_EXPR', 'MEMBER_REF_EXPR',
        )
        self._operand_kinds = _ck(
            'DECL_REF_EXPR', 'INTEGER_LITERAL', 'FLOATING_LITERAL',
            'STRING_LITERAL', 'CHARACTER_LITERAL',
        )
        self._type_decl_kinds = _ck(  # for visit_top -- not used here but consistent
            'STRUCT_DECL', 'ENUM_DECL', 'TYPEDEF_DECL', 'UNION_DECL',
        )

    def _record_write_target(self, target_cursor) -> None:
        """If target_cursor is a direct DECL_REF_EXPR to a VAR_DECL, record it as a write."""
        try:
            if target_cursor.kind in self._decl_ref:
                ref = target_cursor.referenced
                var_decl = getattr(self.ci.CursorKind, 'VAR_DECL', None)
                if ref and var_decl and ref.kind == var_decl:
                    name = ref.spelling
                    if name and name not in self.global_writes:
                        self.global_writes.append(name)
        except (ValueError, Exception):
            pass

    def _arg_text(self, arg_cursor) -> str:
        """
        Best-effort raw text of a call argument -- joined token spellings, no semantic
        resolution. For a plain call this is just cursor.get_tokens() on the argument
        itself. For a call reached via macro expansion (e.g. an embOS convenience macro
        like OS_TASK_CREATE), libclang's tokenizer frequently can't retrieve tokens for
        the outer wrapper cursors (cast/paren/unexposed nodes) macro expansion
        introduces -- but a leaf further down the same subtree (the literal or
        identifier actually written at the call site) usually still has tokens, so this
        recurses down to find it. Not constant-folding or macro resolution -- still
        just what's directly visible in the AST.
        """
        try:
            direct = "".join(t.spelling for t in arg_cursor.get_tokens())
        except Exception:
            direct = ""
        if direct:
            return direct

        best = [""]

        def visit(c):
            if best[0]:
                return
            try:
                ref = c.referenced
            except ValueError:
                ref = None
            decl_ref = getattr(self.ci.CursorKind, 'DECL_REF_EXPR', None)
            if decl_ref and c.kind == decl_ref and ref and ref.spelling:
                best[0] = ref.spelling
                return
            try:
                toks = "".join(t.spelling for t in c.get_tokens())
            except Exception:
                toks = ""
            if toks:
                best[0] = toks
                return
            for child in c.get_children():
                visit(child)
                if best[0]:
                    return

        visit(arg_cursor)
        return best[0]

    def _assignment_target(self, cursor, parent) -> str:
        """
        If this call is a direct initializer (`Type x = call(...)`) or the RHS of a
        plain assignment (`x = call(...)`), return the target variable name --
        needed for RTOS APIs like FreeRTOS's xQueueCreate/xSemaphoreCreateBinary
        that return the created handle via return value rather than writing to an
        output-pointer argument the way embOS's in-place-init style does. Empty
        string if this call isn't directly in either position.
        """
        if parent is None:
            return ""
        var_decl_kind = getattr(self.ci.CursorKind, 'VAR_DECL', None)
        binop_kind = getattr(self.ci.CursorKind, 'BINARY_OPERATOR', None)
        try:
            if var_decl_kind and parent.kind == var_decl_kind:
                return parent.spelling or ""
            if binop_kind and parent.kind == binop_kind:
                kids = list(parent.get_children())
                if len(kids) == 2 and kids[1] == cursor:
                    try:
                        toks = [t.spelling for t in parent.get_tokens()]
                    except Exception:
                        toks = []
                    if "=" in toks:
                        return self._arg_text(kids[0]).strip()
        except Exception:
            pass
        return ""

    def _extract_switch_transitions(self, switch_cursor):
        """
        Best-effort detection of a switch-based state machine: the switch's controlling
        expression is treated as the "state variable" (by raw text, not semantic
        resolution), and any assignment to that same text within a case's body is
        treated as a transition from that case's label to the assigned value. A switch
        needs at least 2 cases and at least one detected transition to count -- most
        switches aren't state machines, and this stays a heuristic either way: it
        doesn't track control flow (an assignment inside an `if` inside a case is still
        attributed to that case, correctly for most real state-machine code but not
        guaranteed), and it doesn't resolve enum/macro values to compare across cases.
        """
        children = list(switch_cursor.get_children())
        if len(children) < 2:
            return None
        state_var_text = self._arg_text(children[0]).strip()
        if not state_var_text:
            return None
        body_cursor = children[1]

        transitions: list = []
        case_count = 0
        state = {"current_case": None}

        def scan_stmt(cursor):
            k = cursor.kind
            if k in self._binary_op:
                try:
                    toks = [t.spelling for t in cursor.get_tokens()]
                except Exception:
                    toks = []
                if "=" in toks:
                    kids = list(cursor.get_children())
                    if len(kids) >= 2:
                        lhs_text = self._arg_text(kids[0]).strip()
                        if lhs_text == state_var_text:
                            rhs_text = self._arg_text(kids[1]).strip()
                            if rhs_text:
                                transitions.append((state["current_case"], rhs_text))
            if k not in self._switch_stmt:  # don't descend into a nested switch's own cases
                for sub in cursor.get_children():
                    scan_stmt(sub)

        def walk_body(cursor):
            nonlocal case_count
            for child in cursor.get_children():
                k = child.kind
                if k in self._case_stmt:
                    case_count += 1
                    case_children = list(child.get_children())
                    if case_children:
                        state["current_case"] = self._arg_text(case_children[0]).strip()
                    for sub in case_children[1:]:
                        scan_stmt(sub)
                elif k in self._default_stmt:
                    state["current_case"] = "default"
                    for sub in child.get_children():
                        scan_stmt(sub)
                else:
                    scan_stmt(child)

        walk_body(body_cursor)
        if case_count < 2 or not transitions:
            return None
        return {
            "state_var": state_var_text,
            "case_count": case_count,
            "transitions": transitions,
            "line": switch_cursor.location.line,
        }

    @staticmethod
    def _own_operator(cursor) -> str:
        """Spelling of a BinaryOperator's own operator token, or "" if unknown.

        The operator is the first token after the left operand's extent. Only
        this node's operator is returned (not those of nested operands), and
        an operator that comes from a macro expansion yields "" because the
        cursor's tokens are then the macro call, not the expanded operator.
        """
        try:
            kids = list(cursor.get_children())
            if len(kids) != 2:
                return ""
            lhs_end = kids[0].extent.end.offset
            for t in cursor.get_tokens():
                if t.location.offset >= lhs_end and t.spelling != ")":
                    return t.spelling
        except Exception:
            pass
        return ""

    def _visit(self, cursor, nesting: int = 0, parent=None):
        try:
            ck = cursor.kind
        except ValueError:
            # libclang Python bindings don't know this cursor kind (e.g. LLVM 22
            # added new kinds not yet in the Python enum). Skip but still recurse
            # so we don't lose the subtree.
            for child in cursor.get_children():
                try:
                    if child.location.file and Path(child.location.file.name) == self.tu_path:
                        self._visit(child, nesting, parent=cursor)
                except Exception:
                    pass
            return
        ci = self.ci

        # Nesting / CC / cognitive
        if ck in self._branch_kinds:
            self.cc += 1
            self.cognitive += 1 + nesting
            nesting += 1

        if ck in self._binary_op:
            # Detect && and || for CC -- token scan for this narrow case only
            try:
                tokens = [t.spelling for t in cursor.get_tokens()]
                # Count only THIS node's own operator. A BinaryOperator's
                # location is its operator token, so look the token up there.
                # Scanning the whole subtree double-counted chained operands,
                # and for operators written inside a macro the extent covers
                # the macro call, which inflated CC (issue #46).
                if self._own_operator(cursor) in ("&&", "||"):
                    self.cc += 1
                    self.cognitive += 1
                # A plain assignment (=) always tokenises as a standalone '='
                # token -- comparisons tokenise as '==', '<=', '>=', '!=', so
                # this doesn't false-positive on those.
                if "=" in tokens:
                    children = list(cursor.get_children())
                    if children:
                        self._record_write_target(children[0])
            except Exception:
                pass

        # Compound assignment (+=, -=, etc.) and increment/decrement both write
        # through their target -- record it as a global write, independent of
        # whether the function has parameters (param-mutation tracking below
        # only fires when it does).
        if ck in self._assign_kinds:
            try:
                children = list(cursor.get_children())
                if children:
                    self._record_write_target(children[0])
            except Exception:
                pass

        if ck in self._unary_op:
            try:
                tokens = [t.spelling for t in cursor.get_tokens()]
                if "++" in tokens or "--" in tokens:
                    children = list(cursor.get_children())
                    if children:
                        self._record_write_target(children[0])
            except Exception:
                pass

        # Param mutation: detect compound assignments through pointer parameters
        if ck in self._assign_kinds and self._param_names:
            try:
                children = list(cursor.get_children())
                if children:
                    lhs = children[0]
                    if lhs.spelling in self._param_names:
                        self._mutated_params.add(lhs.spelling)
                    for lhs_child in lhs.get_children():
                        if lhs_child.spelling in self._param_names:
                            self._mutated_params.add(lhs_child.spelling)
            except Exception:
                pass

        # Block depth tracking
        if ck in self._compound_stmt:
            self.current_depth += 1
            if self.current_depth > self.max_depth:
                self.max_depth = self.current_depth

        # Return statements
        if ck in self._return_stmt:
            self.return_count += 1

        if ck in self._switch_stmt:
            sm = self._extract_switch_transitions(cursor)
            if sm:
                self.state_machines.append(sm)

        # Calls
        if ck in self._call_expr:
            callee_name = cursor.spelling
            if callee_name:
                if callee_name in self._assert_names:
                    self.assert_count += 1
                else:
                    self.callees.add(callee_name)
                rtos_names = getattr(self.config, "rtos", None)
                if rtos_names is not None and callee_name in rtos_names.all_function_names:
                    try:
                        args = [self._arg_text(a) for a in cursor.get_arguments()]
                    except Exception:
                        args = []
                    self.rtos_calls.append({
                        "callee": callee_name, "args": args, "line": cursor.location.line,
                        "assigned_var": self._assignment_target(cursor, parent),
                    })
            else:
                # No spelling means the callee is indirect -- a function pointer
                # call via member access, array subscript, or bare pointer.
                self.indirect_call_count += 1

        # Global variable references and function-pointer references
        if ck in self._decl_ref:
            try:
                ref = cursor.referenced
                if ref:
                    var_decl  = getattr(ci.CursorKind, 'VAR_DECL', None)
                    func_decl = getattr(ci.CursorKind, 'FUNCTION_DECL', None)
                    if var_decl and ref.kind == var_decl:
                        # Record all VAR_DECL references regardless of linkage.
                        # The dispatcher detection filters by known table names so
                        # including local variables is harmless noise.
                        name = ref.spelling
                        if name and name not in self.global_reads:
                            self.global_reads.append(name)
                    # Function referenced by address (e.g. stored in a struct/array
                    # initialiser as a function pointer).  Treat it the same as a
                    # direct call so it is never wrongly flagged as dead code.
                    elif func_decl and ref.kind == func_decl:
                        name = ref.spelling
                        if name:
                            self.callees.add(name)
            except ValueError:
                pass  # unknown cursor kind on ref or parent

        # Magic numbers
        if ck in self._int_lit:
            try:
                tokens = list(cursor.get_tokens())
                if tokens:
                    val = tokens[0].spelling
                    if val not in _MAGIC_EXEMPT:
                        self.magic_numbers.append(val)
            except Exception:
                pass

        # Halstead operator/operand collection
        if ck in self._op_kinds:
            self._operators.append(ck.name)
        elif ck in self._operand_kinds:
            spelling = cursor.spelling
            if spelling:
                self._operands.append(spelling)
            elif ck not in self._decl_ref:
                # Literal with no spelling -- use kind name as placeholder
                self._operands.append(ck.name)

        # Recurse
        for child in cursor.get_children():
            if child.location.file and Path(child.location.file.name) == self.tu_path:
                self._visit(child, nesting, parent=cursor)

        if ck in self._compound_stmt:
            self.current_depth -= 1

    def _extract_parameters(self):
        for child in self.cursor.get_children():
            if child.kind == getattr(self.ci.CursorKind, 'PARM_DECL', None):
                name = child.spelling or f"_p{len(self.parameters)}"
                type_spell = child.type.spelling if child.type else ""
                is_ptr = "*" in type_spell or "[" in type_spell
                is_const = "const" in type_spell
                self.parameters.append(ParameterInfo(
                    name=name,
                    type_spelling=type_spell,
                    is_pointer=is_ptr,
                    is_const=is_const,
                ))
                self._param_names.add(name)

    def _compute_loc(self) -> int:
        ext = self.cursor.extent
        if ext:
            return max(1, ext.end.line - ext.start.line + 1)
        return 0

    def _compute_halstead(self) -> dict:
        from collections import Counter
        op_counts = Counter(self._operators)
        opd_counts = Counter(self._operands)

        n1 = len(op_counts)   # distinct operators
        n2 = len(opd_counts)  # distinct operands
        N1 = sum(op_counts.values())
        N2 = sum(opd_counts.values())

        n = n1 + n2
        N = N1 + N2

        if n < 2 or N == 0:
            return dict(n1=n1, n2=n2, N1=N1, N2=N2,
                        vocabulary=n, length=N,
                        volume=0.0, difficulty=0.0, effort=0.0, bugs=0.0)

        V = N * math.log2(n)
        D = (n1 / 2.0) * (N2 / max(n2, 1))
        E = D * V
        B = V / 3000.0

        return dict(n1=n1, n2=n2, N1=N1, N2=N2,
                    vocabulary=n, length=N,
                    volume=V, difficulty=D, effort=E, bugs=B)

    def collect(self) -> FunctionMetrics:
        self._extract_parameters()
        for child in self.cursor.get_children():
            if child.kind in self._compound_stmt:
                self._visit(child, nesting=0, parent=self.cursor)

        loc = self._compute_loc()
        halstead = self._compute_halstead()
        magic_count = len(self.magic_numbers)
        magic_density = magic_count / max(loc, 1)
        assert_density = self.assert_count / max(loc, 1)

        # Maintainability Index (MIwoc -- without comments)
        V = halstead["volume"]
        cc = self.cc
        if V > 0 and loc > 1:
            mi_woc = max(0.0, (171 - 5.2 * math.log(V) - 0.23 * cc - 16.2 * math.log(loc)) * 100 / 171)
        else:
            mi_woc = 100.0

        # Param mutation rate: fraction of pointer params that are mutated
        ptr_params = [p for p in self.parameters if p.is_pointer and not p.is_const]
        param_mutation_rate = 0.0
        if ptr_params:
            mutated = sum(1 for p in ptr_params if p.name in self._mutated_params)
            param_mutation_rate = mutated / len(ptr_params)
            # Back-annotate
            for p in self.parameters:
                if p.name in self._mutated_params:
                    p.is_mutated = True

        # Complexity efficiency
        complexity_efficiency = cc / max(V, 1.0)

        # Vocabulary concentration
        vocab_conc = halstead["vocabulary"] / max(2 * loc, 1)

        fm = FunctionMetrics(
            name=self.cursor.spelling or "<unnamed>",
            file=self.tu_path,
            line=self.cursor.location.line if self.cursor.location else 0,
            loc=loc,
            cyclomatic_complexity=self.cc,
            cognitive_complexity=self.cognitive,
            block_depth=self.max_depth,
            parameter_count=len(self.parameters),
            parameters=self.parameters,
            return_path_count=self.return_count,
            magic_number_count=magic_count,
            magic_number_density=magic_density,
            magic_numbers=list(self.magic_numbers),
            assert_count=self.assert_count,
            assert_density=assert_density,
            fan_out=len(self.callees),
            callees=list(self.callees),
            indirect_call_count=self.indirect_call_count,
            global_reads=self.global_reads,
            global_writes=self.global_writes,
            rtos_calls=self.rtos_calls,
            state_machines=self.state_machines,
            halstead_n1=halstead["n1"],
            halstead_n2=halstead["n2"],
            halstead_N1=halstead["N1"],
            halstead_N2=halstead["N2"],
            halstead_vocabulary=halstead["vocabulary"],
            halstead_length=halstead["length"],
            halstead_volume=halstead["volume"],
            halstead_difficulty=halstead["difficulty"],
            halstead_effort=halstead["effort"],
            halstead_bugs=halstead["bugs"],
            mi_woc=mi_woc,
            mi_cw=mi_woc,  # cw requires comment LOC; set equal until comment scanning added
            mi_comment_dependency=1.0,
            complexity_efficiency=complexity_efficiency,
            vocabulary_concentration=vocab_conc,
            param_mutation_rate=param_mutation_rate,
            is_isr=_is_isr(self.cursor),
        )
        return fm


def walk_translation_unit(
    tu_info: TranslationUnit,
    config: FwLensConfig,
) -> tuple[list[FunctionMetrics], list[GlobalVarInfo], list[Path], list[tuple[str, str]]]:
    """
    Parse a single translation unit and return:
    - list of FunctionMetrics (one per function defined in this file)
    - list of GlobalVarInfo (globals declared in this file)
    - list of included paths (direct #includes)
    - list of (including_file, included_file) edges across the FULL transitive
      include chain (any depth) -- for building the header-to-header include graph
    """
    _ensure_clang(config)
    ci = _clang

    if not tu_info.path.exists():
        return [], [], [], [], 0, [], {}, {}, {}, [], [{"severity": "fatal", "message": "file not found", "line": 0}]

    # Build clang args
    # -fno-builtin: without this, clang treats well-known library function names
    # (memcpy, strlen, snprintf, ...) as builtins with its own hardcoded signature,
    # completely independent of any prototype we provide via a stub header -- if our
    # stub's signature doesn't match clang's internal one exactly (down to the precise
    # spelling of the size/type parameter for this specific target), it's reported as an
    # "incompatible redeclaration", regardless of how textbook-correct our signature
    # looks. This disables that recognition entirely so our own stub declarations are
    # authoritative, which is what we want anyway since we don't have real headers.
    clang_args = [
        "-x", "c", *target_args(config.tool.target), "-fno-builtin",
        # Matches IAR's default enum packing (--enum_is_int is OFF by default in IAR --
        # an enum takes the smallest type that fits its value range, not always a
        # 4-byte int). Without this, any struct/static_assert relying on IAR's real
        # enum size (e.g. `static_assert(sizeof(SomeEnumType) == 2, ...)`) fails under
        # clang's default int-sized enums even though the real IAR build is correct.
        "-fshort-enums",
        # --target=arm-none-eabi predefines its own __ARM_ARCH (and related) macros
        # from the target triple, before any of our -D flags below are even applied.
        # iar_compat_defines then deliberately overrides several of them (__ARM_ARCH,
        # __CORE__, the __ARMxxM__/__ARMxxEM__ family) to match the specific IAR
        # target rather than clang's generic default -- that redefinition is the
        # whole point, not a mistake. Each -D below is preceded by a matching -U for
        # the same macro name (see the loop below) so there's no redefinition event
        # for clang to warn about in the first place -- more surgical than disabling
        # a whole warning class, which would also hide a genuine conflict between two
        # of the project's own headers. (An earlier attempt at this used
        # -Wno-builtin-macro-redefined, which doesn't apply here: that flag only
        # covers clang's small set of dynamic compiler builtins like __LINE__/
        # __FILE__/__has_feature -- target-predefined macros like __ARM_ARCH are
        # ordinary #defines in the predefines buffer and fall under the general
        # -Wmacro-redefined group instead, which -Wno-builtin-macro-redefined leaves
        # untouched.)
    ]

    # IAR compat defines -- entries starting with -U are undefines, rest are -D.
    # Each -D is preceded by a -U for the same macro name so overriding a macro the
    # target already predefines (__ARM_ARCH etc.) never triggers a redefinition
    # warning -- see the clang_args comment above. -U on a macro that was never
    # defined is a silent no-op, so this is always safe even for compat defines that
    # don't collide with anything.
    for d in config.iar_compat_defines:
        if d.startswith("-U"):
            clang_args.append(d)
        else:
            clang_args.append(f"-U{macro_name(d)}")
            clang_args.append(f"-D{d}")

    # Project defines
    for d in tu_info.defines:
        clang_args.append(f"-D{d}")

    # Include paths -- prepend iar_stubs/ (sits next to config.yaml) first so
    # stub headers shadow any missing IAR toolchain headers like intrinsics.h.
    stubs_dir = config.config_path.parent / "iar_stubs"
    if stubs_dir.exists():
        clang_args.append(f"-I{stubs_dir}")

    # System headers: explicit config wins, otherwise ask the matching compiler.
    # The libclang wheel ships no resource headers, so without this stddef.h and
    # friends are "not found" (issue #48).
    if config.tool.sysroot:
        clang_args.append(f"--sysroot={config.tool.sysroot}")
    if config.tool.system_include_dirs:
        for d in config.tool.system_include_dirs:
            clang_args.append(f"-isystem{d}")
    elif config.tool.auto_detect_includes:
        detected, _compiler = detect_system_includes(config.tool.target, str(config.tool.sysroot or ""))
        for d in detected:
            clang_args.append(f"-isystem{d}")

    # Inject LLVM bundled system headers so standard headers like string.h are found.
    if config.tool.libclang_path:
        llvm_root = config.tool.libclang_path.parent.parent
        clang_lib = llvm_root / "lib" / "clang"
        if clang_lib.exists():
            for v in sorted(clang_lib.iterdir(), reverse=True):
                candidate = v / "include"
                if candidate.exists():
                    clang_args.append(f"-I{candidate}")
                    break

    for inc in tu_info.include_paths:
        if inc.exists():
            clang_args.append(f"-I{inc}")

    # Per-file flags from a compile database (-std, -m*, -include, -target ...)
    # then project-wide extra args, so the build's own flags win over defaults.
    extra = list(getattr(tu_info, "extra_args", []) or [])
    if any(a.startswith(("--target=", "-target")) for a in extra):
        clang_args = [a for a in clang_args if not a.startswith("--target=")]
    clang_args.extend(extra)
    clang_args.extend(config.tool.clang_args)

    index = ci.Index.create()
    try:
        translation_unit = index.parse(
            str(tu_info.path),
            args=clang_args,
            options=ci.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD,
        )
    except Exception as e:
        return [], [], [], 0, [], {}, {}, {}, [], [{"severity": "fatal", "message": str(e), "line": 0}]

    # Capture parse diagnostics -- errors/warnings from libclang itself. A file can
    # report a plausible function count while one specific construct silently failed
    # to parse (a missing header, an unresolved macro) with no visible sign anywhere
    # else in the pipeline; this makes that visible instead of hiding it behind a
    # deceptively normal-looking "parsed OK" status.
    diagnostics_raw: list[dict] = []
    for d in translation_unit.diagnostics:
        if d.severity >= 3:
            sev = "fatal" if d.severity == 4 else "error"
        elif d.severity == 2:
            sev = "warning"
        else:
            continue  # skip notes/pedantic-level noise
        try:
            line = d.location.line if d.location else 0
        except Exception:
            line = 0
        # The physical file this diagnostic actually occurred in -- NOT necessarily the
        # translation unit itself. libclang tracks the true location precisely, including
        # inside an #included header; a diagnostic on a widely-shared header will show up
        # for every TU that includes it, each carrying that header's own line number
        # rather than anything in the TU's own source. Recording only the TU-relative
        # line number here (as earlier versions did) makes it look like the problem is at
        # that line *in the .c file*, which is misleading whenever it's really a header --
        # exactly the ambiguity that made the arch-define #error hard to pin down over
        # several rounds of debugging: without this, there was no way to tell whether line
        # 158 meant batteryLife.c line 158 or some IAR header's own line 158.
        in_file = ""
        try:
            loc_file = d.location.file if d.location else None
            if loc_file is not None:
                in_file = str(loc_file.name)
        except Exception:
            pass
        diagnostics_raw.append({
            "severity": sev, "message": str(d.spelling), "line": line, "in_file": in_file,
        })
        if len(diagnostics_raw) >= 50:  # cap -- cascading errors can produce hundreds
            break

    functions: list[FunctionMetrics] = []
    globals_: list[GlobalVarInfo] = []
    includes: list[Path] = []
    # Every inclusion edge in the TU's full preprocessed chain (any depth), not just
    # this file's own direct #includes -- needed to build a genuine header-to-header
    # include graph. get_includes() already walks the whole chain; depth==1 above only
    # keeps the direct-include subset for call sites that specifically want that (e.g.
    # the unused-includes heuristic, which must stay scoped to what a file's own text
    # could plausibly need). Discarding depth>=2 there is correct for that use case,
    # but doing it project-wide meant no header->header edge ever existed anywhere --
    # every file's transitive include depth silently capped at 1, and circular/self
    # includes going through an intermediate header could never be detected, since the
    # graph had nothing to detect them with.
    all_include_edges: list[tuple[str, str]] = []
    for inc in translation_unit.get_includes():
        if inc.depth == 1:  # direct includes only
            try:
                includes.append(Path(inc.include.name))
            except Exception:
                pass
        try:
            src_name = str(inc.source.name) if inc.source is not None else str(tu_info.path)
            all_include_edges.append((src_name, str(inc.include.name)))
        except Exception:
            pass

    tu_path = tu_info.path

    type_decl_count = 0

    file_scope_fn_refs: set[str] = set()
    # Maps global var name -> list of function names stored in its initialiser
    dispatch_tables_raw: dict[str, list[str]] = {}
    dispatch_table_lines: dict[str, int] = {}
    # Maps global var name -> list of other global var names referenced in its initialiser
    # e.g. emBatteryChange -> [UIBatteryChange], DailyLog -> [DailyLogVft]
    var_registrations_raw: dict[str, list[str]] = {}
    # Task descriptor table entries recovered from static const array-of-struct
    # declarations matching config.rtos.task_table_types (see _extract_task_table_entries)
    task_table_entries_raw: list[dict] = []

    def _collect_fn_refs(var_name: str, cursor) -> None:
        """Recursively collect FUNCTION_DECL and VAR_DECL references under a cursor.

        Populates:
          - file_scope_fn_refs / dispatch_tables_raw: function pointers stored in initialisers
          - var_registrations_raw: global variables embedded in other global initialisers
            (e.g. a vtable or state block stored inside a larger struct)
        """
        _decl_ref  = getattr(ci.CursorKind, 'DECL_REF_EXPR', None)
        _func_decl = getattr(ci.CursorKind, 'FUNCTION_DECL', None)
        _var_decl  = getattr(ci.CursorKind, 'VAR_DECL',      None)

        def _walk(c):
            try:
                ck = c.kind
            except ValueError:
                pass
            else:
                if _decl_ref and ck == _decl_ref:
                    try:
                        ref = c.referenced
                        if ref:
                            if _func_decl and ref.kind == _func_decl and ref.spelling:
                                name = ref.spelling
                                file_scope_fn_refs.add(name)
                                dispatch_tables_raw.setdefault(var_name, [])
                                if name not in dispatch_tables_raw[var_name]:
                                    dispatch_tables_raw[var_name].append(name)
                            elif _var_decl and ref.kind == _var_decl and ref.spelling:
                                # Another global variable is referenced in this initialiser --
                                # record it as "var_name embeds ref.spelling"
                                ref_name = ref.spelling
                                if ref_name != var_name:
                                    var_registrations_raw.setdefault(ref_name, [])
                                    if var_name not in var_registrations_raw[ref_name]:
                                        var_registrations_raw[ref_name].append(var_name)
                    except ValueError:
                        pass
            for child in c.get_children():
                _walk(child)

        _walk(cursor)

    def visit_top(cursor):
        nonlocal type_decl_count
        if not cursor.location.file:
            return
        cursor_file = Path(cursor.location.file.name)
        if cursor_file != tu_path:
            return

        try:
            ck = cursor.kind
        except ValueError:
            for child in cursor.get_children():
                visit_top(child)
            return

        # Function definitions (not declarations)
        _func_decl = getattr(ci.CursorKind, 'FUNCTION_DECL', None)
        if _func_decl and ck == _func_decl and cursor.is_definition():
            visitor = _FunctionVisitor(cursor, tu_path, config)
            fm = visitor.collect()
            fm.is_isr = _is_isr(cursor)
            functions.append(fm)
            return

        # Type declarations (struct, enum, typedef, union) -- count as abstract tokens
        _type_kinds = {
            getattr(ci.CursorKind, n, None)
            for n in ('STRUCT_DECL', 'ENUM_DECL', 'TYPEDEF_DECL', 'UNION_DECL')
        } - {None}
        if ck in _type_kinds and cursor.is_definition():
            type_decl_count += 1

        # Global variable declarations.
        # Use storage_class rather than is_definition(): a tentative definition
        # (e.g. `int g_foo;` relying on .bss zero-init, no initialiser) is a real
        # global, but libclang's is_definition() is False for it -- only an
        # `extern` forward declaration (no storage allocated here) should be
        # excluded, and that's exactly what StorageClass.EXTERN identifies.
        _var_decl = getattr(ci.CursorKind, 'VAR_DECL', None)
        if _var_decl and ck == _var_decl:
            try:
                is_extern_decl = cursor.storage_class == ci.StorageClass.EXTERN
            except Exception:
                is_extern_decl = not cursor.is_definition()
            if cursor.is_definition() or not is_extern_decl:
                type_spell = cursor.type.spelling if cursor.type else ""
                is_vol = "volatile" in type_spell
                gv = GlobalVarInfo(
                    name=cursor.spelling,
                    file=tu_path,
                    is_volatile=is_vol,
                )
                globals_.append(gv)
                # Collect any function pointer references in the initialiser
                # (e.g. dispatch tables, command tables, callback structs).
                var_name = cursor.spelling
                _collect_fn_refs(var_name, cursor)
                if var_name in dispatch_tables_raw:
                    dispatch_table_lines[var_name] = cursor.location.line

                # Task descriptor table: a static const array whose element type
                # matches one of config.rtos.task_table_types -- e.g.
                # `static const TaskEntry_t CommonTaskList[] = { {.tcb=..., ...}, ... }`
                task_table_types = getattr(getattr(config, "rtos", None), "task_table_types", None)
                if task_table_types:
                    try:
                        elem_type = cursor.type.get_array_element_type()
                        type_name = elem_type.spelling.replace("const ", "").strip() if elem_type else ""
                    except Exception:
                        type_name = ""
                    if type_name in task_table_types:
                        entries = _extract_task_table_entries(cursor, type_name, ci)
                        for fields in entries:
                            task_table_entries_raw.append({
                                "type_name": type_name,
                                "fields": fields,
                                "line": cursor.location.line,
                            })

        for child in cursor.get_children():
            visit_top(child)

    for cursor in translation_unit.cursor.get_children():
        if cursor.location.file and Path(cursor.location.file.name) == tu_path:
            visit_top(cursor)

    # Attach type_decl_count to the first function as a module-level annotation,
    # or stash it as a side-channel via a sentinel GlobalVarInfo with a special name.
    # Simpler: return it as a 4th value.
    return functions, globals_, includes, all_include_edges, type_decl_count, list(file_scope_fn_refs), dispatch_tables_raw, dispatch_table_lines, var_registrations_raw, task_table_entries_raw, diagnostics_raw