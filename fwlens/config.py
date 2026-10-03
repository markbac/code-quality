"""
Configuration loader for fwlens.

Loads and validates config.yaml, resolves all paths relative to the config file location.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml


@dataclass
class ToolConfig:
    libclang_path: Optional[Path]
    # clang --target. "native" (or "host") passes no --target and uses the host compiler's headers.
    target: str = "arm-none-eabi"
    sysroot: Optional[Path] = None
    # Extra system include directories. When set, auto-detection is skipped.
    system_include_dirs: list[Path] = field(default_factory=list)
    # Extra arguments appended to every clang invocation (e.g. ["-std=c11"]).
    clang_args: list[str] = field(default_factory=list)
    # Ask the compiler for system include dirs when none are configured.
    auto_detect_includes: bool = True
    # Fraction of in-scope files allowed to have fatal/error diagnostics before
    # --fail-on-parse-error fails the run (0.0 = none allowed).
    parse_error_threshold: float = 0.0


@dataclass
class ProjectConfig:
    ewp: Optional[Path]
    configuration: str
    proj_dir: Path
    toolkit_dir: Optional[Path]
    mode: str = "ewp"                    # "ewp" | "directory" | "compile_commands" | "cmake" | "make"
    source_dir: Optional[Path] = None    # directory-mode root, glob'd for *.c
    compile_commands: Optional[Path] = None  # path to compile_commands.json (CMake/Make)


@dataclass
class ScopeConfig:
    first_party: list[str]
    sdk: list[str]
    third_party_lib: list[str]
    analyse: list[str]


@dataclass
class LayerRule:
    name: str
    paths: list[str] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)


@dataclass
class ThresholdConfig:
    cyclomatic_complexity: int = 15
    cognitive_complexity: int = 20
    halstead_effort: float = 1_000_000
    halstead_volume: float = 8_000
    block_depth: int = 5
    function_loc: int = 100
    parameter_count: int = 6
    return_path_count: int = 5
    magic_number_density: float = 0.15
    fan_out: int = 10
    cohesion_min: float = 0.3  # internal_call_cohesion below this = low cohesion
    instability_zone_of_pain: float = 0.3
    instability_zone_of_uselessness: float = 0.7
    main_sequence_distance: float = 0.5


@dataclass
class OutputConfig:
    reports_dir: Path
    exports_dir: Path
    cache_dir: Path
    db_path: Path
    formats: list[str]
    top_n: int = 20
    # Files longer than this (in lines) are skipped from the HTML report's embedded
    # source viewer entirely -- shown as "Source not available" rather than jumping to
    # source. A single enormous generated/vendored file isn't worth the size cost.
    source_embed_loc_limit: int = 10000


@dataclass
class GitConfig:
    # How far back to count commits for churn/hotspot analysis, e.g. "180 days ago".
    # None (default) counts the full history. Ignored if the project isn't a git repo.
    since: Optional[str] = None
    # Time bin size for the churn heatmap: "month" or "week".
    heatmap_bin: str = "month"
    # Commit-message keywords (case-insensitive) that classify a commit as a "fix" --
    # shared by fwlens.reliability (Goel-Okumoto discovery curve), fwlens.defect_analysis
    # (correlation + root-cause categorisation), and fwlens.reliability.compute_bugfix_hotspots
    # (bug-fix-weighted hotspots). Override if your project's commit conventions differ
    # from the English fix/bug/defect/... default (e.g. a Jira-ticket-only convention, or
    # a non-English team).
    fix_keywords: list[str] = field(default_factory=lambda: [
        "fix", "bug", "defect", "issue", "resolve", "patch", "hotfix",
    ])


@dataclass
class EstimationConfig:
    # COCOMO 81 project mode: "organic" (small, familiar), "semidetached" (mixed
    # experience/constraints), or "embedded" (tight constraints, hardware/timing/interface
    # dependent -- the closest built-in COCOMO category to firmware, though the constants
    # were calibrated on 1970s-80s business/systems software, not this codebase).
    cocomo_mode: str = "embedded"


@dataclass
class CostBenefitConfig:
    # Placeholder order-of-magnitude figures (a conservative 10x found-early-vs-found-late
    # ratio) -- fwlens has no way to know your organisation's actual costs. Replace with
    # real numbers for the estimate to mean anything.
    cost_per_defect_static_usd: float = 100.0
    cost_per_defect_field_usd: float = 1000.0


@dataclass
class RTOSConfig:
    # "none" (default, disables RTOS analysis) or "embos" -- only embOS is implemented.
    kind: str = "none"
    # Task-creation function name -> 0-based argument index of each field of interest,
    # per function (not a single shared mapping) -- embOS's OS_TASK_Create and
    # OS_TASK_CreateEx share an argument order, but older convenience macros
    # (OS_CREATETASK, OS_TASK_CREATE) swap the priority/routine positions relative to
    # them. Since libclang expands macros before fwlens ever sees the AST, a call
    # through any of those macros is recorded under the *expanded* function name
    # (OS_TASK_Create) with the *expanded* argument list, so the defaults below only
    # need entries for the real functions, not the macros themselves.
    task_functions: dict = field(default_factory=dict)
    semaphore_functions: list = field(default_factory=list)   # counting semaphores (no priority inheritance)
    mutex_functions: list = field(default_factory=list)       # priority-inheriting resource lock
    mailbox_functions: list = field(default_factory=list)
    queue_functions: list = field(default_factory=list)
    event_functions: list = field(default_factory=list)
    rwlock_functions: list = field(default_factory=list)      # reader/writer lock
    # Task descriptor TABLES: struct type name -> {tcb/name/priority/routine/stack/
    # stack_size: actual struct member name}. For the common embedded pattern where
    # tasks are defined as a static const array of descriptor structs (designated
    # initializers) and created generically in a loop -- OS_TASK_Create(pTask->tcb,
    # pTask->name, ...) -- rather than via one literal call site per task. Complements
    # task_functions (call-site based); both are merged into the same task list.
    task_table_types: dict = field(default_factory=dict)
    # Creation function names whose object handle comes back via RETURN VALUE
    # (e.g. FreeRTOS's `q = xQueueCreate(...)`) rather than an output-pointer
    # argument (embOS's `OS_MUTEX_Create(&mutex, ...)` style, the default
    # assumption for every other creation-function list above). For a function
    # listed here, the object's variable name is read from the assignment target
    # captured by the AST walker (FunctionMetrics._assignment_target) instead of
    # args[0] -- only meaningful for functions also listed in one of
    # semaphore_functions/mutex_functions/mailbox_functions/queue_functions/
    # event_functions/rwlock_functions.
    return_value_functions: list = field(default_factory=list)
    # Functions that *use* an already-created object (wait/signal/put/get/...) rather
    # than create one -- object pointer expected as the first argument, an embOS-wide
    # convention. Classified as wait/signal via the keyword lists below (signal is
    # checked first, so e.g. "Unlock" is never mis-caught by a generic "Lock" wait match).
    usage_functions: list = field(default_factory=list)
    wait_keywords: list = field(default_factory=lambda: ["Wait", "Get", "Receive", "Take", "Lock", "Blocked"])
    signal_keywords: list = field(default_factory=lambda: ["Give", "Put", "Send", "Unlock", "Set", "Pulse"])

    @property
    def all_function_names(self) -> set:
        return (set(self.task_functions.keys()) | set(self.semaphore_functions) | set(self.mutex_functions)
                | set(self.mailbox_functions) | set(self.queue_functions) | set(self.event_functions)
                | set(self.rwlock_functions) | set(self.usage_functions))


# embOS defaults, used when rtos.kind == "embos" and a list isn't explicitly overridden in
# config.yaml. Verified against the real embOS V5.18.3.0 RTOS.h (SEGGER), current (non-
# deprecated) function names only -- the many OS_CreateCSema/OS_WaitCSema/OS_Use/...-style
# aliases in that header are plain object-like #defines with no argument reordering, so
# they resolve to these same canonical names by the time libclang builds the AST; they
# don't need separate entries here.
_EMBOS_DEFAULTS = {
    "task_functions": {
        "OS_TASK_Create":   {"tcb": 0, "name": 1, "priority": 2, "routine": 3, "stack": 4, "stack_size": 5},
        "OS_TASK_CreateEx": {"tcb": 0, "name": 1, "priority": 2, "routine": 3, "stack": 4, "stack_size": 5},
    },
    "semaphore_functions": ["OS_SEMAPHORE_Create"],
    "mutex_functions": ["OS_MUTEX_Create"],
    "mailbox_functions": ["OS_MAILBOX_Create"],
    "queue_functions": ["OS_QUEUE_Create"],
    "event_functions": ["OS_EVENT_Create", "OS_EVENT_CreateEx"],
    "rwlock_functions": ["OS_RWLOCK_Create"],
    "usage_functions": [
        # semaphore (no priority inheritance)
        "OS_SEMAPHORE_Give", "OS_SEMAPHORE_GiveMax",
        "OS_SEMAPHORE_Take", "OS_SEMAPHORE_TakeBlocked", "OS_SEMAPHORE_TakeTimed",
        # mutex (priority inheritance)
        "OS_MUTEX_Lock", "OS_MUTEX_LockBlocked", "OS_MUTEX_LockTimed", "OS_MUTEX_Unlock",
        # mailbox
        "OS_MAILBOX_Put", "OS_MAILBOX_PutBlocked", "OS_MAILBOX_PutTimed",
        "OS_MAILBOX_PutFront", "OS_MAILBOX_PutFrontBlocked",
        "OS_MAILBOX_Get", "OS_MAILBOX_GetBlocked", "OS_MAILBOX_GetTimed",
        "OS_MAILBOX_GetPtr", "OS_MAILBOX_GetPtrBlocked",
        "OS_MAILBOX_WaitBlocked", "OS_MAILBOX_WaitTimed",
        # queue
        "OS_QUEUE_Put", "OS_QUEUE_PutBlocked", "OS_QUEUE_PutTimed",
        "OS_QUEUE_GetPtr", "OS_QUEUE_GetPtrBlocked", "OS_QUEUE_GetPtrTimed",
        # event
        "OS_EVENT_Set", "OS_EVENT_SetMask", "OS_EVENT_Pulse",
        "OS_EVENT_Get", "OS_EVENT_GetBlocked", "OS_EVENT_GetTimed",
        "OS_EVENT_GetMask", "OS_EVENT_GetMaskBlocked", "OS_EVENT_GetMaskTimed",
        # reader/writer lock
        "OS_RWLOCK_RdLock", "OS_RWLOCK_RdLockBlocked", "OS_RWLOCK_RdLockTimed", "OS_RWLOCK_RdUnlock",
        "OS_RWLOCK_WrLock", "OS_RWLOCK_WrLockBlocked", "OS_RWLOCK_WrLockTimed", "OS_RWLOCK_WrUnlock",
    ],
}


@dataclass
class FwLensConfig:
    config_path: Path
    tool: ToolConfig
    project: ProjectConfig
    scope: ScopeConfig
    iar_compat_defines: list[str]
    layers: list[LayerRule]
    thresholds: ThresholdConfig
    output: OutputConfig
    entry_points: list[str]
    git: GitConfig = field(default_factory=GitConfig)
    estimation: EstimationConfig = field(default_factory=EstimationConfig)
    cost_benefit: CostBenefitConfig = field(default_factory=CostBenefitConfig)
    rtos: RTOSConfig = field(default_factory=RTOSConfig)
    # Function names treated as assertion calls for assert-coverage metrics. Extend
    # this with any project-specific assert macro or error-report function rather
    # than needing a code change. Note: a macro that expands to a conditional call
    # (e.g. embOS's OS_ASSERT -> `if (!cond) OS_Error(code)`) never appears as a
    # call node under its own macro name after preprocessing -- list the function
    # it actually expands into (OS_Error here) instead.
    assert_names: list = field(default_factory=lambda: [
        "assert", "ASSERT", "PSP_ASSERT", "STATIC_ASSERT",
        "_Static_assert", "static_assert",
    ])


def macro_name(define_line: str) -> str:
    """Extract the macro name a compat-define line sets, for override
    comparison -- handles '-Uname', 'name=value', 'name(x)=value', and bare
    'name'. Two lines defining the same macro to different values (e.g.
    '__ARM7EM__=7' vs '__ARM7EM__=1') must be recognised as the same macro,
    not two distinct entries, wherever compat-define lists get merged or
    deduplicated."""
    s = define_line.strip()
    if s.startswith("-U"):
        s = s[2:]
    for sep in ("(", "="):
        idx = s.find(sep)
        if idx != -1:
            s = s[:idx]
            break
    return s.strip()


def load_config(config_path: Path) -> FwLensConfig:
    config_path = config_path.resolve()
    if not config_path.exists():
        print(f"[fwlens] ERROR: Config file not found: {config_path}", file=sys.stderr)
        sys.exit(1)

    base = config_path.parent

    with open(config_path, encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    def resolve(p: str) -> Path:
        """Resolve path relative to config file location (for inputs like ewp, toolkit_dir)."""
        return (base / Path(p)).resolve()

    def resolve_output(p: str) -> Path:
        """Resolve output path relative to the working directory, not the config file."""
        return (Path.cwd() / Path(p)).resolve()

    # Tool
    tool_raw = raw.get("tool", {})
    libclang_raw = tool_raw.get("libclang_path")
    sysroot_raw = tool_raw.get("sysroot")
    tool = ToolConfig(
        libclang_path=Path(libclang_raw) if libclang_raw else None,
        target=str(tool_raw.get("target", "arm-none-eabi")),
        sysroot=Path(sysroot_raw) if sysroot_raw else None,
        system_include_dirs=[Path(p) for p in tool_raw.get("system_include_dirs", []) or []],
        clang_args=[str(a) for a in tool_raw.get("clang_args", []) or []],
        auto_detect_includes=bool(tool_raw.get("auto_detect_includes", True)),
        parse_error_threshold=float(tool_raw.get("parse_error_threshold", 0.0)),
    )

    # Project
    proj_raw = raw.get("project", {})
    ewp_raw = proj_raw.get("ewp")
    source_dir_raw = proj_raw.get("source_dir")
    compile_commands_raw = proj_raw.get("compile_commands")
    mode_raw = proj_raw.get("mode")

    if not ewp_raw and not source_dir_raw and not compile_commands_raw and not mode_raw:
        print("[fwlens] ERROR: project.ewp, project.source_dir, or project.compile_commands must be set in config.yaml",
              file=sys.stderr)
        sys.exit(1)

    if mode_raw:
        mode = mode_raw.lower()
    elif compile_commands_raw:
        mode = "compile_commands"
    elif source_dir_raw:
        mode = "directory"
    else:
        mode = "ewp"

    ewp_path = resolve(ewp_raw) if ewp_raw else None
    source_dir_path = resolve(source_dir_raw) if source_dir_raw else None
    compile_commands_path = resolve(compile_commands_raw) if compile_commands_raw else None

    proj_dir_raw = proj_raw.get("proj_dir")
    toolkit_dir_raw = proj_raw.get("toolkit_dir")
    
    if proj_dir_raw:
        default_proj_dir = Path(proj_dir_raw)
    elif source_dir_path:
        default_proj_dir = source_dir_path
    elif compile_commands_path:
        default_proj_dir = compile_commands_path.parent
    elif ewp_path:
        default_proj_dir = ewp_path.parent
    else:
        default_proj_dir = base

    project = ProjectConfig(
        ewp=ewp_path,
        mode=mode,
        source_dir=source_dir_path,
        compile_commands=compile_commands_path,
        configuration=proj_raw.get("configuration", "Debug"),
        proj_dir=default_proj_dir,
        toolkit_dir=Path(toolkit_dir_raw) if toolkit_dir_raw else None,
    )

    # Scope
    scope_raw = raw.get("scope", {})
    scope = ScopeConfig(
        first_party=scope_raw.get("first_party", ["Src", "Inc"]),
        sdk=scope_raw.get("sdk", ["sdk"]),
        third_party_lib=scope_raw.get("third_party_lib", ["Lib"]),
        analyse=scope_raw.get("analyse", ["first_party"]),
    )

    # IAR compat defines
    iar_compat = list(raw.get("iar_compat_defines", []))

    config_yaml_macro_names = {macro_name(d) for d in iar_compat}

    # Arch defines auto-detected by `--auto-stub` (fwlens.autostub) get written to a
    # side-channel file rather than config.yaml itself. This has to be read back here,
    # in load_config, rather than left as an in-memory mutation on the FwLensConfig
    # object returned by an earlier load_config call: parsing runs in subprocess workers
    # (fwlens.parser.pipeline._worker) that only receive a config *path*, not the live
    # Python object, and independently call load_config(that path) fresh in each
    # subprocess -- an in-memory-only mutation in the main process is invisible to them.
    # Reading a side-channel file here means every load_config call, in any process,
    # picks it up the same way.
    #
    # Dedup is by MACRO NAME, not exact line, and config.yaml always wins: if the
    # person has explicitly set a value for a macro in config.yaml (e.g. correcting
    # __ARM7EM__ from the auto-detected =1 to the =7 their header actually needs),
    # a stale matching-name-different-value line left over in the side-channel file
    # from an earlier --auto-stub run must never be appended after it -- clang takes
    # the LAST -D for a given macro on the command line, so appending an outdated
    # duplicate would silently override the person's explicit fix with no warning.
    autostub_defines_path = base / "iar_stubs" / "_auto_detected_defines.txt"
    if autostub_defines_path.exists():
        for line in autostub_defines_path.read_text().splitlines():
            line = line.strip()
            if line and line not in iar_compat and macro_name(line) not in config_yaml_macro_names:
                iar_compat.append(line)

    # Layers
    layers = []
    for lr in raw.get("layers", []):
        layers.append(LayerRule(
            name=lr["name"],
            paths=lr.get("paths", []),
            groups=lr.get("groups", []),
        ))

    # Thresholds
    thresh_raw = raw.get("thresholds", {})
    thresholds = ThresholdConfig(
        cyclomatic_complexity=thresh_raw.get("cyclomatic_complexity", 15),
        cognitive_complexity=thresh_raw.get("cognitive_complexity", 20),
        halstead_effort=thresh_raw.get("halstead_effort", 1_000_000),
        halstead_volume=thresh_raw.get("halstead_volume", 8_000),
        block_depth=thresh_raw.get("block_depth", 5),
        function_loc=thresh_raw.get("function_loc", 100),
        parameter_count=thresh_raw.get("parameter_count", 6),
        return_path_count=thresh_raw.get("return_path_count", 5),
        magic_number_density=thresh_raw.get("magic_number_density", 0.15),
        fan_out=thresh_raw.get("fan_out", 10),
        cohesion_min=thresh_raw.get("cohesion_min", 0.3),
        instability_zone_of_pain=thresh_raw.get("instability_zone_of_pain", 0.3),
        instability_zone_of_uselessness=thresh_raw.get("instability_zone_of_uselessness", 0.7),
        main_sequence_distance=thresh_raw.get("main_sequence_distance", 0.5),
    )

    # Output
    out_raw = raw.get("output", {})
    output = OutputConfig(
        reports_dir=resolve_output(out_raw.get("reports_dir", "output/reports")),
        exports_dir=resolve_output(out_raw.get("exports_dir", "output/exports")),
        cache_dir=resolve_output(out_raw.get("cache_dir", "output/.cache")),
        db_path=resolve_output(out_raw.get("db_path", "output/fwlens.db")),
        formats=out_raw.get("formats", ["html", "csv", "json"]),
        top_n=out_raw.get("top_n", 20),
    )

    entry_points = raw.get("entry_points", ["main"])

    git_raw = raw.get("git", {})
    git = GitConfig(
        since=git_raw.get("since"),
        heatmap_bin=git_raw.get("heatmap_bin", "month"),
        fix_keywords=git_raw.get("fix_keywords", GitConfig().fix_keywords),
    )

    est_raw = raw.get("estimation", {})
    estimation = EstimationConfig(cocomo_mode=est_raw.get("cocomo_mode", "embedded"))

    cb_raw = raw.get("cost_benefit", {})
    cost_benefit = CostBenefitConfig(
        cost_per_defect_static_usd=cb_raw.get("cost_per_defect_static_usd", 100.0),
        cost_per_defect_field_usd=cb_raw.get("cost_per_defect_field_usd", 1000.0),
    )

    rtos_raw = raw.get("rtos", {})
    rtos_kind = rtos_raw.get("kind", "none")
    rtos_defaults = _EMBOS_DEFAULTS if rtos_kind == "embos" else {}
    rtos = RTOSConfig(
        kind=rtos_kind,
        task_functions=rtos_raw.get("task_functions", rtos_defaults.get("task_functions", {})),
        semaphore_functions=rtos_raw.get("semaphore_functions", rtos_defaults.get("semaphore_functions", [])),
        mutex_functions=rtos_raw.get("mutex_functions", rtos_defaults.get("mutex_functions", [])),
        mailbox_functions=rtos_raw.get("mailbox_functions", rtos_defaults.get("mailbox_functions", [])),
        queue_functions=rtos_raw.get("queue_functions", rtos_defaults.get("queue_functions", [])),
        event_functions=rtos_raw.get("event_functions", rtos_defaults.get("event_functions", [])),
        rwlock_functions=rtos_raw.get("rwlock_functions", rtos_defaults.get("rwlock_functions", [])),
        task_table_types=rtos_raw.get("task_table_types", {}),
        return_value_functions=rtos_raw.get("return_value_functions", []),
        usage_functions=rtos_raw.get("usage_functions", rtos_defaults.get("usage_functions", [])),
        wait_keywords=rtos_raw.get("wait_keywords", ["Wait", "Get", "Receive", "Take", "Lock", "Blocked"]),
        signal_keywords=rtos_raw.get("signal_keywords", ["Give", "Put", "Send", "Unlock", "Set", "Pulse"]),
    )

    _default_assert_names = [
        "assert", "ASSERT", "PSP_ASSERT", "STATIC_ASSERT",
        "_Static_assert", "static_assert",
    ]
    # embOS's OS_ASSERT is a macro that expands to `if (!cond) { OS_Error(code); }`
    # -- by the time libclang builds the AST (after preprocessing), there is no
    # "OS_ASSERT" call node to match at all, only a call to OS_Error guarded by an
    # if. Detecting OS_ASSERT usage means detecting THAT call instead.
    if rtos_kind == "embos":
        _default_assert_names.append("OS_Error")
    assert_names = raw.get("assert_names", _default_assert_names)

    return FwLensConfig(
        config_path=config_path,
        tool=tool,
        project=project,
        scope=scope,
        iar_compat_defines=iar_compat,
        layers=layers,
        thresholds=thresholds,
        output=output,
        entry_points=entry_points,
        git=git,
        estimation=estimation,
        cost_benefit=cost_benefit,
        rtos=rtos,
        assert_names=assert_names,
    )