"""
Core data model for fwlens.

All analysis results are stored in these dataclasses and passed between pipeline stages.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional


class BoundaryClass(str, Enum):
    FIRST_PARTY = "first_party"
    THIRD_PARTY_LIB = "third_party_lib"
    SDK = "sdk"
    UNKNOWN = "unknown"


class AnalysisScope(str, Enum):
    """Which boundary classes to run full analysis on."""
    FIRST_PARTY = "first_party"
    THIRD_PARTY_LIB = "third_party_lib"
    SDK = "sdk"


@dataclass
class IARGroup:
    name: str
    parent: Optional[str] = None
    children: list[str] = field(default_factory=list)
    files: list[Path] = field(default_factory=list)
    inferred_layer: Optional[str] = None


@dataclass
class ParameterInfo:
    name: str
    type_spelling: str
    is_pointer: bool
    is_const: bool
    is_mutated: bool = False  # written through inside function body


@dataclass
class GlobalAccess:
    name: str
    file: Path
    is_read: bool
    is_write: bool
    is_volatile: bool


@dataclass
class FunctionMetrics:
    name: str
    file: Path
    line: int
    loc: int = 0
    cyclomatic_complexity: int = 0
    cognitive_complexity: int = 0
    block_depth: int = 0
    parameter_count: int = 0
    parameters: list[ParameterInfo] = field(default_factory=list)
    return_path_count: int = 0
    magic_number_count: int = 0
    magic_number_density: float = 0.0
    magic_numbers: list[str] = field(default_factory=list)
    assert_count: int = 0
    assert_density: float = 0.0
    fan_out: int = 0          # distinct callees
    fan_in: int = 0           # populated by graph engine
    callees: list[str] = field(default_factory=list)
    callers: list[str] = field(default_factory=list)
    global_reads: list[str] = field(default_factory=list)
    global_writes: list[str] = field(default_factory=list)
    is_isr: bool = False
    is_entry_point: bool = False
    # Halstead
    halstead_n1: int = 0
    halstead_n2: int = 0
    halstead_N1: int = 0
    halstead_N2: int = 0
    halstead_vocabulary: int = 0
    halstead_length: int = 0
    halstead_volume: float = 0.0
    halstead_difficulty: float = 0.0
    halstead_effort: float = 0.0
    halstead_bugs: float = 0.0
    # Maintainability
    mi_woc: float = 0.0
    mi_cw: float = 0.0
    mi_comment_dependency: float = 0.0
    # Derived
    complexity_efficiency: float = 0.0
    vocabulary_concentration: float = 0.0
    param_mutation_rate: float = 0.0
    structural_debt_index: float = 0.0
    # Stack
    stack_depth_estimate: Optional[int] = None
    stack_estimable: bool = True
    # Dead code
    is_dead_candidate: bool = False
    # Hotspot
    hotspot_score: float = 0.0
    # Bug-fix-weighted hotspot score: same churn x structural-debt formula as
    # hotspot_score, but churn is restricted to fix-flavoured commits (fwlens.config
    # GitConfig.fix_keywords) rather than all commits -- a sharper defect-focused
    # signal (see fwlens.reliability.compute_bugfix_hotspots)
    bugfix_hotspot_score: float = 0.0
    # Non-empty if this function's (or its file's) name is a generic/vague token
    # ("utils", "handler", "misc", ...) that reveals little about responsibility --
    # a name that can't be judged is a weaker signal that a hotspot score is trustworthy
    # (fwlens.hotspot_names, "judge hotspots by the power of names")
    vague_name_flag: str = ""
    # Indirect calls (calls through function pointers, not direct CALL_EXPR to a FUNCTION_DECL)
    indirect_call_count: int = 0
    # Dispatch tables read by this function (global var names whose initialisers hold fn ptrs)
    dispatch_table_reads: list[str] = field(default_factory=list)
    # Composite risk score: weighted fusion of SDI, hotspot, module pain, ISR, and stack
    # risk (fwlens.risk) -- 0-1, percentile-based, comparable across the whole codebase
    composite_risk_score: float = 0.0
    # Henry & Kafura information flow complexity: length x (fan_in x fan_out)^2 --
    # penalises functions that are both internally long AND heavily coupled through
    # the call graph, a different signal from cyclomatic complexity
    information_flow_complexity: float = 0.0
    # Raw RTOS API calls made by this function (e.g. embOS OS_CreateTask/OS_CreateCSema),
    # only populated for callee names in config.rtos's configured function lists --
    # interpreted into RTOSTask/RTOSSyncObject/RTOSObjectUsage by fwlens.rtos_analysis
    rtos_calls: list = field(default_factory=list)
    # Raw switch-based state-machine candidates found in this function -- interpreted
    # into StateMachine objects by fwlens.state_machines
    state_machines: list = field(default_factory=list)


@dataclass
class ModuleMetrics:
    path: Path
    boundary_class: BoundaryClass = BoundaryClass.UNKNOWN
    iar_groups: list[str] = field(default_factory=list)
    layer: Optional[str] = None
    file_scope_fn_refs: list[str] = field(default_factory=list)  # functions referenced in global initialisers
    loc: int = 0
    function_count: int = 0
    functions: list[FunctionMetrics] = field(default_factory=list)
    includes: list[Path] = field(default_factory=list)
    # Every (including_file, included_file) edge across this TU's FULL transitive
    # include chain (any depth) -- `includes` above is deliberately just the direct
    # (depth==1) subset for callers that need that narrower scope (e.g. the unused-
    # includes heuristic). This field is what build_include_graph() uses to construct
    # a genuine header-to-header graph; using `includes` there instead would silently
    # cap every file's graph reach at depth 1, which is exactly the bug this field
    # exists to avoid -- see fwlens.graph.engines.build_include_graph.
    all_include_edges: list[tuple[Path, Path]] = field(default_factory=list)
    # Longest actual include chain from this file (itself first, deepest header
    # last), not just its length -- populated by compute_include_depth() alongside
    # include_depth. Lets the report show the real path, not just a number.
    include_chain: list[Path] = field(default_factory=list)
    # Coupling
    fan_in: int = 0
    fan_out: int = 0
    instability: float = 0.0
    abstractness: float = 0.0
    main_sequence_distance: float = 0.0
    # Cohesion (0-1, higher is more cohesive)
    internal_call_cohesion: float = 0.0
    # Per-module aggregates
    avg_cc: float = 0.0
    max_cc: int = 0
    avg_halstead_effort: float = 0.0
    avg_mi_woc: float = 0.0
    avg_magic_density: float = 0.0
    pragma_density: float = 0.0
    header_source_coherence: float = 1.0
    include_depth: int = 0
    # SCC
    scc_id: Optional[int] = None
    in_cycle: bool = False
    # Type declaration count (struct/enum/typedef/union defined in this file)
    type_decl_count: int = 0
    # Stable abstractions zone classification
    zone: str = "unknown"   # pain | uselessness | main_sequence | warning | unknown
    pain_score: float = 0.0  # composite defect-risk score; higher = more painful to modify
    # Dispatch tables defined in this module (var_name -> [fn_names])
    dispatch_tables: dict = field(default_factory=dict)
    # Line numbers of dispatch table variable definitions (var_name -> line)
    dispatch_table_lines: dict = field(default_factory=dict)
    # Global vars that embed other global vars in their initialisers (embedded_var -> [container_vars])
    var_registrations: dict = field(default_factory=dict)
    # Total indirect call sites across all functions in this module
    indirect_call_sites: int = 0
    # Parse diagnostics from libclang itself (errors/warnings), capped at 50 per
    # file -- makes silent parse degradation visible instead of hiding behind a
    # deceptively normal-looking function count. Each dict: {severity, message, line}
    parse_diagnostics: list = field(default_factory=list)
    # File-level line metrics (whole physical file, not just inside functions) --
    # populated by fwlens.metrics.file_metrics, no external tool used
    file_total_lines: int = 0
    file_sloc: int = 0
    file_comment_lines: int = 0
    file_blank_lines: int = 0
    file_comment_ratio: float = 0.0
    # Git commit count touching this file (churn) -- populated by fwlens.git_history,
    # 0 if the project isn't a git repo or git is unavailable
    commit_count: int = 0
    # Fix-flavoured commit count touching this file (subset of commit_count) --
    # populated by fwlens.reliability.compute_bugfix_hotspots
    bugfix_commit_count: int = 0
    # Code ownership (fwlens.ownership) -- who wrote most of this file, and how
    # fragmented is the remaining authorship. main_author is "" if the file has
    # no commit history (0 commits) or isn't in a git repo.
    main_author: str = ""
    main_author_share: float = 0.0       # main_author's commits / commit_count, 0-1
    distinct_author_count: int = 0
    ownership_fragmentation: float = 0.0  # 1 - main_author_share; 0 = single owner, ->1 = diffuse
    # Percentile-rank(commit_count) x ownership_fragmentation -- a file that's both
    # frequently changed and diffusely owned, the "bystander effect" risk signal from
    # Tornhill Ch.11-13. 0 if commit_count is 0.
    ownership_risk_score: float = 0.0
    # Preprocessor complexity -- populated by fwlens.tech_debt, text-based, no external tool
    max_ifdef_depth: int = 0
    ifdef_directive_count: int = 0
    distinct_feature_flags: int = 0


@dataclass
class DispatchTable:
    """Project-level record of a function-pointer table and its dispatch chain."""
    var_name: str           # e.g. cmdReadRegisterData
    file: Path              # file where the table is defined
    line: int               # line number of the definition
    stored_fns: list[str]   # functions stored as pointers in the table
    dispatchers: list[str]  # functions that read this table variable (effective callers)
    registered_into: list[str] = field(default_factory=list)  # global vars that embed this table
    # Fingerprint (populated by stats engine)
    fingerprint: dict = field(default_factory=dict)


@dataclass
class GlobalVarInfo:
    name: str
    file: Path
    is_volatile: bool
    readers: list[str] = field(default_factory=list)
    writers: list[str] = field(default_factory=list)
    isr_readers: list[str] = field(default_factory=list)
    isr_writers: list[str] = field(default_factory=list)
    volatile_risk: bool = False  # accessed from ISR and non-ISR, not volatile


@dataclass
class ISRRisk:
    isr_name: str
    file: Path
    line: int
    own_cc: int
    transitive_cc_sum: int
    call_depth: int
    risk_score: float
    non_estimable: bool = False


@dataclass
class StackRisk:
    """Worst-case stack depth for a single entry point (task/main entry or ISR)."""
    function_name: str
    file: Path
    line: int
    is_isr: bool
    stack_depth_estimate: Optional[int]
    stack_estimable: bool


@dataclass
class GroupDirMismatch:
    """A source file whose IAR group name does not match its parent directory name."""
    file: Path           # absolute path to the .c file
    iar_group: str       # group name in the IAR project tree
    actual_dir: str      # name of the file's immediate parent directory on disk
    layer: str           # assigned architecture layer (or "Unknown")
    suggested_dir: Path  # where the file would live if dirs mirrored IAR groups


@dataclass
class TodoMarker:
    file: Path
    line: int
    tag: str    # TODO | FIXME | HACK | XXX
    text: str   # rest of the comment line, trimmed


@dataclass
class CommentedCodeBlock:
    """A run of consecutive comment-only lines that looks like disabled code, not prose."""
    file: Path
    start_line: int
    end_line: int
    line_count: int


@dataclass
class ClonePair:
    """Two functions whose normalised token streams are near-duplicates (type-2 clone)."""
    function_a: str
    file_a: Path
    line_a: int
    function_b: str
    file_b: Path
    line_b: int
    similarity: float  # Jaccard over normalised token shingles, 0-1
    token_count_a: int
    token_count_b: int
    # Whether each side is also flagged as dead code (fwlens.graph.engines dead-code
    # detection, which runs before clone detection). A clone pair where one or both
    # sides are dead is a stronger removal candidate than either signal alone --
    # duplication that's also unreachable is safe to delete outright, not just merge.
    is_dead_a: bool = False
    is_dead_b: bool = False


@dataclass
class CouplingPair:
    """Two files that change together in the same commit more often than chance."""
    file_a: Path
    file_b: Path
    co_changes: int
    changes_a: int
    changes_b: int
    coupling: float  # Jaccard: co_changes / (changes_a + changes_b - co_changes)
    # Populated by fwlens.git_history.compute_architecture_coupling (both default False
    # until that stage runs, e.g. if either file's layer is "Unknown"/unassigned)
    layer_a: str = ""
    layer_b: str = ""
    cross_layer: bool = False    # file_a and file_b are assigned to different layers
    # cross_layer AND neither file directly #includes the other -- co-change with no
    # static dependency to explain it (best-effort: direct-include check only, not
    # transitive/call-graph -- treat as a worklist signal, not a definitive verdict)
    surprising: bool = False


@dataclass
class LayerCouplingPair:
    """Aggregated change coupling between two architecture layers (fwlens.git_history)."""
    layer_a: str
    layer_b: str
    file_pair_count: int       # distinct file pairs contributing to this layer pair
    total_co_changes: int
    avg_coupling: float
    surprising_pair_count: int  # of file_pair_count, how many had no static #include either way


@dataclass
class ComplexityTrendPoint:
    date: datetime
    complexity_proxy: int   # regex decision-keyword count, summed over the file at this commit


@dataclass
class ComplexityTrend:
    """
    Complexity-over-time trend for one hotspot file (fwlens.complexity_trend), sampled
    from historical git blobs -- distinguishes a hotspot whose complexity spiked once and
    has been stable since from one that's still climbing every commit.
    """
    file: Path
    points: list[ComplexityTrendPoint] = field(default_factory=list)
    slope: float = 0.0             # complexity_proxy units per day, from a linear fit
    trend: str = "insufficient_data"  # "worsening" | "improving" | "stable" | "insufficient_data"
    r_squared: float = 0.0


@dataclass
class ChurnHeatmapCell:
    """Commit count for one first-party file within one time bin (e.g. one month)."""
    file: Path
    bin_label: str   # e.g. "2026-03" for month bins, "2026-W12" for week bins
    commit_count: int


@dataclass
class CommitActivityCell:
    """
    Total commit count for one calendar day, across the whole first-party codebase
    (not per file) -- the classic GitHub-style "when did work happen" calendar heatmap,
    distinct from ChurnHeatmapCell's per-file/per-month breakdown. A commit touching
    several first-party files counts once here, not once per file.
    """
    date: str   # ISO "YYYY-MM-DD"
    commit_count: int


@dataclass
class EffortEstimate:
    """Basic COCOMO 81 effort/schedule estimate derived from first-party SLOC."""
    mode: str  # organic | semidetached | embedded
    kloc: float
    effort_person_months: float
    schedule_months: float
    average_staffing: float


@dataclass
class ReliabilityGrowth:
    """Goel-Okumoto NHPP fit over fix-commit discovery dates."""
    fix_commit_count: int
    fitted_total_defects: float   # 'a' -- asymptotic expected total defects
    fitted_discovery_rate: float  # 'b'
    cumulative_to_date: int
    estimated_remaining: float
    trend: str        # "climbing" | "flattening" | "plateaued" | "insufficient_data"
    r_squared: float
    days_span: int


@dataclass
class DefectCorrelation:
    """Spearman rank correlation between a module-level metric and its fix-commit count."""
    metric: str
    label: str
    spearman_r: float
    p_value: float
    n: int


@dataclass
class CostBenefitEstimate:
    """Cost of catching the estimated remaining defects statically vs. in the field."""
    estimated_remaining_defects: float
    cost_per_defect_static_usd: float
    cost_per_defect_field_usd: float
    cost_if_static_usd: float
    cost_if_field_usd: float
    potential_savings_usd: float


@dataclass
class RTOSTask:
    """A task created by an RTOS task-creation call (e.g. embOS OS_CreateTask)."""
    name: str                          # resolved string literal if available, else the TCB var name
    tcb_var: str
    priority_expr: str                 # raw text of the priority argument
    priority_value: Optional[int]      # resolved only if priority_expr was a plain integer literal
    entry_function: str
    stack_expr: str                    # raw text of the stack pointer/array argument
    stack_size_expr: str
    stack_size_value: Optional[int]    # resolved only if stack_size_expr was a plain integer literal
    creation_function: str
    file: Path
    line: int


@dataclass
class RTOSSyncObject:
    """A semaphore/mutex/mailbox/queue/event created by an RTOS creation call."""
    kind: str            # "semaphore" | "mutex" | "mailbox" | "queue" | "event"
    var_name: str
    creation_function: str
    file: Path
    line: int


@dataclass
class RTOSObjectUsage:
    """One call site where a task (transitively) touches a known sync object."""
    object_var: str
    task_name: str
    used_by_function: str    # the actual function containing the call, may differ from task_name
    access_kind: str         # "wait" | "signal" | "other"
    file: Path
    line: int


@dataclass
class RTOSPriorityCollision:
    """Two or more tasks created at the same resolved priority."""
    priority_value: int
    task_names: list[str] = field(default_factory=list)


@dataclass
class RTOSInversionRisk:
    """A non-priority-inheriting semaphore shared by tasks of different priority."""
    object_var: str
    task_names: list[str] = field(default_factory=list)
    priorities: list = field(default_factory=list)  # parallel to task_names, entries may be None


@dataclass
class StateMachine:
    """A switch-based state machine detected in a single function."""
    function_name: str
    file: Path
    line: int
    state_var: str
    states: list[str] = field(default_factory=list)
    transitions: list = field(default_factory=list)  # list of (from_state, to_state) tuples
    case_count: int = 0


@dataclass
class ArchitectureViolation:
    source_module: Path
    target_module: Path
    source_layer: str
    target_layer: str
    violation_type: str   # "upward", "skipped", "forbidden"
    dependency_kind: str  # "include", "call", "global"


@dataclass
class IncludeCycle:
    """A strongly-connected component (size > 1) in the file-level #include graph."""
    files: list[Path]
    length: int


@dataclass
class SelfInclude:
    """A file that (directly or via a resolved macro path) includes itself."""
    file: Path


@dataclass
class MissingIncludeGuard:
    file: Path
    reason: str  # "no #ifndef or #pragma once found" / "#ifndef NAME not followed by matching #define"


@dataclass
class DeepIncludeChain:
    """Top-N first-party files by transitive include depth (fwlens.graph.engines.compute_include_depth)."""
    file: Path
    depth: int
    # Ordered list of files from `file` itself down to the deepest header reached --
    # the actual longest path, not just its length. Populated alongside `depth` by
    # compute_include_depth(); may be empty for chains computed before this field
    # existed (older cached model data), so callers should treat it as optional.
    chain: list[Path] = field(default_factory=list)


@dataclass
class UnusedInclude:
    """
    Heuristic: none of a header's declared names (functions, macros, typedefs,
    extern globals) appear to be referenced in the including file's text.
    First-party-to-first-party edges only -- see fwlens.header_checks for caveats.
    """
    file: Path       # the including file
    included: Path    # the header that appears unused
    declared_name_count: int  # how many candidate names were checked


@dataclass
class ProjectModel:
    ewp_path: Path
    configuration: str
    iar_groups: dict[str, IARGroup] = field(default_factory=dict)
    modules: list[ModuleMetrics] = field(default_factory=list)
    globals: list[GlobalVarInfo] = field(default_factory=list)
    isr_risks: list[ISRRisk] = field(default_factory=list)
    arch_violations: list[ArchitectureViolation] = field(default_factory=list)
    dead_candidates: list[FunctionMetrics] = field(default_factory=list)
    group_dir_mismatches: list[GroupDirMismatch] = field(default_factory=list)
    dispatch_tables: list[DispatchTable] = field(default_factory=list)
    # Worst-case stack per entry point (tasks/main entry + ISRs), sorted by depth descending
    entry_point_stack_risks: list[StackRisk] = field(default_factory=list)
    # Hotspots: first-party functions ranked by churn x structural debt (fwlens.git_history)
    hotspots: list[FunctionMetrics] = field(default_factory=list)
    git_available: bool = False
    # Parse health from the pipeline: in_scope, parsed_ok, failed, files_with_errors, fatal_diagnostics
    parse_stats: dict = field(default_factory=dict)
    # Tech debt / smells (fwlens.tech_debt)
    todo_markers: list[TodoMarker] = field(default_factory=list)
    commented_code_blocks: list[CommentedCodeBlock] = field(default_factory=list)
    # Near-duplicate functions (fwlens.clones)
    clone_pairs: list[ClonePair] = field(default_factory=list)
    # Files that change together in the same commit (fwlens.git_history)
    change_coupling: list[CouplingPair] = field(default_factory=list)
    # Per-file, per-time-bin commit counts for the churn heatmap (fwlens.git_history)
    churn_heatmap: list[ChurnHeatmapCell] = field(default_factory=list)
    # Total commit count per calendar day, whole first-party codebase (fwlens.git_history)
    commit_activity: list[CommitActivityCell] = field(default_factory=list)
    # Change coupling rolled up to the architecture-layer level (fwlens.git_history)
    layer_coupling: list[LayerCouplingPair] = field(default_factory=list)
    # First-party modules with commit history, sorted by ownership_risk_score descending
    # (fwlens.ownership)
    ownership_risks: list[ModuleMetrics] = field(default_factory=list)
    # Complexity-over-time trend for the top-N hotspot files (fwlens.complexity_trend)
    complexity_trends: list[ComplexityTrend] = field(default_factory=list)
    # First-party functions ranked by bugfix_hotspot_score descending (fwlens.reliability)
    bugfix_hotspots: list[FunctionMetrics] = field(default_factory=list)
    # Parse diagnostics sharing a message shape + line number across many files --
    # usually one shared root cause, not N independent problems (fwlens.diagnostic_clusters)
    diagnostic_clusters: list = field(default_factory=list)
    # COCOMO effort/schedule estimate (fwlens.effort_estimate)
    effort_estimate: Optional[EffortEstimate] = None
    # Goel-Okumoto reliability growth fit over fix-commit history (fwlens.reliability)
    reliability_growth: Optional[ReliabilityGrowth] = None
    # Complexity-vs-defect correlation and root-cause categorisation (fwlens.defect_analysis)
    defect_correlations: list[DefectCorrelation] = field(default_factory=list)
    # Static-vs-field cost/benefit estimate (fwlens.cost_benefit)
    cost_benefit: Optional[CostBenefitEstimate] = None
    # RTOS task/synchronisation analysis (fwlens.rtos_analysis)
    rtos_kind: str = "none"
    rtos_tasks: list[RTOSTask] = field(default_factory=list)
    rtos_sync_objects: list[RTOSSyncObject] = field(default_factory=list)
    rtos_object_usages: list[RTOSObjectUsage] = field(default_factory=list)
    rtos_priority_collisions: list[RTOSPriorityCollision] = field(default_factory=list)
    rtos_inversion_risks: list[RTOSInversionRisk] = field(default_factory=list)
    rtos_unused_objects: list[RTOSSyncObject] = field(default_factory=list)
    # State machines detected via switch statements (fwlens.state_machines)
    state_machines: list[StateMachine] = field(default_factory=list)
    # Raw task-descriptor-table entries recovered from static const array-of-struct
    # declarations (see fwlens.parser.ast_walker._extract_task_table_entries),
    # interpreted into RTOSTask objects by fwlens.rtos_analysis alongside the
    # call-site-based task_functions detection
    task_table_entries: list[dict] = field(default_factory=list)
    # All first-party functions sorted by composite_risk_score descending (fwlens.risk)
    composite_risk: list[FunctionMetrics] = field(default_factory=list)
    # Codebase-level stats (populated by stats engine)
    codebase_fingerprint: dict = field(default_factory=dict)
    exceedance_probabilities: dict = field(default_factory=dict)
    # Header include hygiene (fwlens.header_checks)
    include_cycles: list[IncludeCycle] = field(default_factory=list)
    self_includes: list[SelfInclude] = field(default_factory=list)
    missing_include_guards: list[MissingIncludeGuard] = field(default_factory=list)
    deep_include_chains: list[DeepIncludeChain] = field(default_factory=list)
    unused_includes: list[UnusedInclude] = field(default_factory=list)

    def first_party_modules(self) -> list[ModuleMetrics]:
        return [m for m in self.modules if m.boundary_class == BoundaryClass.FIRST_PARTY]

    def all_functions(self) -> list[FunctionMetrics]:
        return [f for m in self.modules for f in m.functions]

    def first_party_functions(self) -> list[FunctionMetrics]:
        return [f for m in self.first_party_modules() for f in m.functions]