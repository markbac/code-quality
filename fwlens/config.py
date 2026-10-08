"""
Configuration loader for fwlens.

Loads and validates config.yaml.

Path rule: every input path (project.*, tool.libclang_path, tool.sysroot,
tool.system_include_dirs, standards.*) is resolved relative to the directory containing the
config file, so the same config behaves the same from any working directory. Absolute paths and
`~` are honoured as written. The one exception is output.* (reports_dir, exports_dir,
cache_dir, db_path), which is relative to the current working directory because outputs belong
where the tool is run, not next to the config.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


class ConfigError(ValueError):
    """Raised when config loading or validation fails."""


class ConfigWarning(UserWarning):
    """A config.yaml problem that does not stop the run, such as an unknown key."""


@dataclass
class ToolConfig:
    libclang_path: Path | None
    # clang --target. "native" (or "host") passes no --target and uses the host compiler's headers.
    target: str = "arm-none-eabi"
    sysroot: Path | None = None
    # Extra system include directories. When set, auto-detection is skipped.
    system_include_dirs: list[Path] = field(default_factory=list)
    # Extra arguments appended to every clang invocation (e.g. ["-std=c11"]).
    clang_args: list[str] = field(default_factory=list)
    # Ask the compiler for system include dirs when none are configured.
    auto_detect_includes: bool = True
    # Fraction of in-scope files allowed to have fatal/error diagnostics before
    # --fail-on-parse-error fails the run (0.0 = none allowed).
    parse_error_threshold: float = 0.0
    # Parallel parse workers (0 = number of CPUs minus one).
    jobs: int = 0
    # Seconds allowed per translation unit before its worker is killed (0 = no limit).
    parse_timeout: float = 120.0
    # Reuse per-file parse results from output.cache_dir when nothing relevant changed.
    parse_cache: bool = True


@dataclass
class ProjectConfig:
    ewp: Path | None
    configuration: str
    proj_dir: Path
    toolkit_dir: Path | None
    mode: str = "ewp"                    # "ewp" | "directory" | "compile_commands" | "cmake" | "make"
    source_dir: Path | None = None    # directory-mode root, glob'd for *.c
    compile_commands: Path | None = None  # path to compile_commands.json (CMake/Make)
    map_file: Path | None = None          # linker map file (IAR or GCC) for flash/RAM footprint
    uvprojx: Path | None = None           # Keil uVision project; project.configuration names the target
    cproject: Path | None = None          # Eclipse CDT / STM32CubeIDE .cproject; configuration names the build config
    include_dirs: list[Path] = field(default_factory=list)   # directory mode: explicit include path, in order
    include_mode: str = "all"            # directory mode: "all" header dirs | "used" (only dirs reached by #include)


@dataclass
class ScopeConfig:
    first_party: list[str]
    sdk: list[str]
    third_party_lib: list[str]
    analyse: list[str]
    exclude: list[str] = field(default_factory=list)


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
    show_timing: bool = True        # print where the run's time went when the command ends


@dataclass
class GitConfig:
    # How far back to count commits for churn/hotspot analysis, e.g. "180 days ago".
    # None (default) counts the full history. Ignored if the project isn't a git repo.
    since: str | None = None
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
class StandardSelection:
    standard: str
    include_categories: list[str] = field(default_factory=list)   # empty = all categories
    include_ids: list[str] = field(default_factory=list)          # empty = all rules
    exclude_rules: list[str] = field(default_factory=list)


@dataclass
class StandardsConfig:
    """Optional coding-standard compliance (MISRA C, CERT C ...). Disabled unless ``enabled`` is set."""
    enabled: list[StandardSelection] = field(default_factory=list)
    extra_rule_dirs: list[Path] = field(default_factory=list)
    deviations_file: Path | None = None
    imports: list[tuple[str, Path]] = field(default_factory=list)    # (tool, results file)


@dataclass
class PRCheckConfig:
    """Defaults for `compare` and `pr-comment`; the matching command-line options override them."""
    base: Path | None = None             # reference findings file or baseline.json (--base)
    base_ref: str | None = None          # git ref to analyse in a worktree (--base-ref)
    uncertain_gates: bool = False        # also fail on loosely matched findings
    fail_on_new: bool = False            # exit 1 on new or worsened findings or a footprint gate
    max_items: int = 20                  # rows per table in the comment
    base_label: str = "the target branch"
    report_url: str | None = None
    max_flash_growth_bytes: int | None = None   # fail when flash grows by more than this vs the reference
    max_ram_growth_bytes: int | None = None
    status: bool = False                 # also set a commit status (GitHub: statuses, GitLab: statuses API)


@dataclass
class MatchConfig:
    """How findings are matched to a baseline or reference when code moves or is edited."""
    similarity: float = 0.85         # body similarity (0-1] needed for a loose match
    report_uncertain: bool = True    # false: no loose matching, so edited code is new + resolved


@dataclass
class SbomComponent:
    """A component declared by hand, because versions and licences cannot always be read from source."""
    name: str
    path: Path
    version: str | None = None
    license: str | None = None       # an SPDX id or expression
    supplier: str | None = None
    purl: str | None = None
    description: str | None = None


@dataclass
class SbomConfig:
    components: list[SbomComponent] = field(default_factory=list)
    include_files: bool = False      # list every file with its hash, not just one hash per component
    application_version: str | None = None   # version of the firmware the SBOM describes
    components_file: Path | None = None      # a hand-kept components.yaml: bootloader, modem, toolchain and the like


@dataclass
class CbomConfig:
    extra_catalog_dirs: list[Path] = field(default_factory=list)   # more crypto catalogue YAML files
    scan_scopes: list[str] = field(default_factory=lambda: ["first_party"])   # boundary classes scanned for use
    autodetect: bool = True                  # name an identifier by its keywords (aes, sha256 ...) when the catalogue lacks it
    keywords: list[dict] = field(default_factory=list)       # more keyword phrases for autodetection
    ignore_identifiers: list[str] = field(default_factory=list)   # identifier patterns autodetection must skip
    apis: list[dict] = field(default_factory=list)           # function and macro names, as catalogue entries
    certificates: bool = True                # find certificates and keys in files and source
    certificate_expiry_days: int = 90        # warn when a certificate expires within this many days


@dataclass
class ArchitectureConfig:
    enabled: bool = True                     # recover the architecture model (docs/ARCHITECTURE_RECOVERY.md)
    weights: dict = field(default_factory=dict)   # weight per dependency kind: callback, state, type, call, include
    private_headers: list | None = None      # header patterns whose declarations are internal (default *_priv.h, */internal/* ...)
    components: list = field(default_factory=list)   # pinned components: [{name, units: [path patterns]}]
    resolution: float = 1.0                  # community detection resolution: higher gives smaller components
    max_component_units: int = 40            # an IDE group larger than this is split by community detection
    domains: list = field(default_factory=list)      # more subsystem domains: [{id, name, words, includes}]
    subsystems: list = field(default_factory=list)   # pin a domain to units: [{domain, units: [path patterns]}]
    patterns: list = field(default_factory=list)     # more pattern rules, or replacements: [{id, name, scope, signals, thresholds}]
    intended_layers: list = field(default_factory=list)   # the intended layers, top to bottom: names or {name, components, domains, units}
    rules: list = field(default_factory=list)        # dependency rules: [{id, from, to, allow, kinds}]
    strict_layers: bool = False              # also report a dependency that skips an intended layer
    forbid_cycles: bool = False              # report every upward dependency inside a cycle of components
    register_calls: list = field(default_factory=list)   # registration functions: [{function, id_arg, callback_arg}] (0-based)
    publish_calls: list = field(default_factory=list)    # publish functions: [{function, id_arg}]
    baseline: Path | None = None             # a saved architecture snapshot (architecture save) to compare each run with
    drift_threshold: float = 0.6             # report a unit when this share of its coupling is outside its directory's component


_EDGE_KINDS = ("callback", "state", "type", "call", "include")


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
    standards: StandardsConfig = field(default_factory=StandardsConfig)
    pr_check: PRCheckConfig = field(default_factory=PRCheckConfig)
    match: MatchConfig = field(default_factory=MatchConfig)
    sbom: SbomConfig = field(default_factory=SbomConfig)
    cbom: CbomConfig = field(default_factory=CbomConfig)
    architecture: ArchitectureConfig = field(default_factory=ArchitectureConfig)
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
    # Warnings raised while loading (unknown keys); also emitted through warnings.warn.
    warnings: list = field(default_factory=list)


_BOUNDARY_CLASSES = ("first_party", "sdk", "third_party_lib", "unknown")


def macro_name(define_line: str) -> str:
    """Extract the macro name a compat-define line sets, for override
    comparison -- handles '-Uname', 'name=value', 'name(x)=value', and bare
    'name'. Two lines defining the same macro to different values (e.g.
    '__ARM7EM__=7' vs '__ARM7EM__=1') must be recognised as the same macro,
    not two distinct entries, wherever compat-define lists get merged or
    deduplicated."""
    s = define_line.strip()
    s = s.removeprefix("-U")
    for sep in ("(", "="):
        idx = s.find(sep)
        if idx != -1:
            s = s[:idx]
            break
    return s.strip()


def load_config(config_path: Path) -> FwLensConfig:
    config_path = config_path.resolve()
    if not config_path.exists():
        raise ConfigError(f"Config file not found: {config_path}")

    base = config_path.parent

    with open(config_path, encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    if raw is None:
        raw = {}
    elif not isinstance(raw, dict):
        raise ConfigError(f"Invalid config format in {config_path}: expected dictionary root")

    import warnings

    from fwlens.config_schema import SUPPORTED_FORMATS, unknown_key_messages

    load_warnings = unknown_key_messages(raw)
    for message in load_warnings:
        warnings.warn(f"{config_path.name}: {message}", ConfigWarning, stacklevel=2)

    def resolve(p: str) -> Path:
        """Resolve an input path relative to the config file location."""
        return (base / Path(p).expanduser()).resolve()

    def resolve_output(p: str) -> Path:
        """Resolve output path relative to the working directory, not the config file."""
        return (Path.cwd() / Path(p)).resolve()

    # Tool
    tool_raw = raw.get("tool", {}) or {}
    libclang_raw = tool_raw.get("libclang_path")
    sysroot_raw = tool_raw.get("sysroot")
    tool = ToolConfig(
        libclang_path=resolve(libclang_raw) if libclang_raw else None,
        target=str(tool_raw.get("target", "arm-none-eabi")),
        sysroot=resolve(sysroot_raw) if sysroot_raw else None,
        system_include_dirs=[resolve(p) for p in tool_raw.get("system_include_dirs", []) or []],
        clang_args=[str(a) for a in tool_raw.get("clang_args", []) or []],
        auto_detect_includes=bool(tool_raw.get("auto_detect_includes", True)),
        parse_error_threshold=float(tool_raw.get("parse_error_threshold", 0.0)),
        jobs=int(tool_raw.get("jobs", 0)),
        parse_timeout=float(tool_raw.get("parse_timeout", 120.0)),
        parse_cache=bool(tool_raw.get("parse_cache", True)),
    )

    # Project
    proj_raw = raw.get("project", {}) or {}
    ewp_raw = proj_raw.get("ewp")
    source_dir_raw = proj_raw.get("source_dir")
    compile_commands_raw = proj_raw.get("compile_commands")
    map_file_raw = proj_raw.get("map_file")
    mode_raw = proj_raw.get("mode")

    uvprojx_raw = proj_raw.get("uvprojx")
    cproject_raw = proj_raw.get("cproject")

    if not (ewp_raw or source_dir_raw or compile_commands_raw or mode_raw or uvprojx_raw or cproject_raw):
        raise ConfigError("project.ewp, project.source_dir, or project.compile_commands must be set in "
                          "config.yaml (or project.uvprojx / project.cproject)")

    if mode_raw:
        mode = mode_raw.lower()
    elif compile_commands_raw:
        mode = "compile_commands"
    elif uvprojx_raw:
        mode = "keil"
    elif cproject_raw:
        mode = "cproject"
    elif source_dir_raw:
        mode = "directory"
    else:
        mode = "ewp"

    include_mode = str(proj_raw.get("include_mode", "all")).lower()
    if include_mode not in ("all", "used"):
        raise ConfigError(f"project.include_mode must be 'all' or 'used', not '{include_mode}'")
    include_dirs = [resolve(d) for d in proj_raw.get("include_dirs") or []]

    ewp_path = resolve(ewp_raw) if ewp_raw else None
    source_dir_path = resolve(source_dir_raw) if source_dir_raw else None
    compile_commands_path = resolve(compile_commands_raw) if compile_commands_raw else None
    uvprojx_path = resolve(uvprojx_raw) if uvprojx_raw else None
    cproject_path = resolve(cproject_raw) if cproject_raw else None

    proj_dir_raw = proj_raw.get("proj_dir")
    toolkit_dir_raw = proj_raw.get("toolkit_dir")
    
    if proj_dir_raw:
        default_proj_dir = resolve(proj_dir_raw)
    elif source_dir_path:
        default_proj_dir = source_dir_path
    elif compile_commands_path:
        default_proj_dir = compile_commands_path.parent
    elif uvprojx_path:
        default_proj_dir = uvprojx_path.parent
    elif cproject_path:
        default_proj_dir = cproject_path.parent
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
        toolkit_dir=resolve(toolkit_dir_raw) if toolkit_dir_raw else None,
        map_file=resolve(map_file_raw) if map_file_raw else None,
        include_dirs=include_dirs,
        include_mode=include_mode,
        uvprojx=uvprojx_path,
        cproject=cproject_path,
    )

    # Scope
    scope_raw = raw.get("scope") or {}
    bad_analyse = [a for a in scope_raw.get("analyse", ["first_party"]) if a not in _BOUNDARY_CLASSES]
    if bad_analyse:
        raise ConfigError(f"scope.analyse has unsupported value(s) {bad_analyse}; "
                          f"use any of {list(_BOUNDARY_CLASSES)}")
    scope = ScopeConfig(
        first_party=scope_raw.get("first_party", ["Src", "Inc"]),
        sdk=scope_raw.get("sdk", ["sdk"]),
        third_party_lib=scope_raw.get("third_party_lib", ["Lib"]),
        analyse=scope_raw.get("analyse", ["first_party"]),
        exclude=scope_raw.get("exclude", []),
    )

    # IAR compat defines
    iar_compat = list(raw.get("iar_compat_defines", []))

    config_yaml_macro_names = {macro_name(d) for d in iar_compat}

    # Arch defines auto-detected by `--auto-stub` (fwlens.autostub) are also written to a
    # side-channel file so they persist: later runs, and `debug-parse`, load them here
    # without --auto-stub. Within a run the parse workers receive the live config object,
    # so --auto-stub's in-memory additions are visible to them directly.
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
    out_raw = raw.get("output") or {}
    formats = out_raw.get("formats", ["html", "csv", "json"])
    bad_formats = [f for f in formats if f not in SUPPORTED_FORMATS]
    if bad_formats:
        raise ConfigError(f"output.formats has unsupported value(s) {bad_formats}; "
                          f"supported: {list(SUPPORTED_FORMATS)}")
    output = OutputConfig(
        reports_dir=resolve_output(out_raw.get("reports_dir", "output/reports")),
        exports_dir=resolve_output(out_raw.get("exports_dir", "output/exports")),
        cache_dir=resolve_output(out_raw.get("cache_dir", "output/.cache")),
        db_path=resolve_output(out_raw.get("db_path", "output/fwlens.db")),
        formats=formats,
        top_n=out_raw.get("top_n", 20),
        source_embed_loc_limit=out_raw.get("source_embed_loc_limit", 10000),
        show_timing=bool(out_raw.get("show_timing", True)),
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

    std_raw = raw.get("standards") or {}
    standards = StandardsConfig(
        enabled=[
            StandardSelection(
                standard=str(e["standard"]),
                include_categories=[str(c) for c in e.get("include_categories", []) or []],
                include_ids=[str(i) for i in e.get("include_ids", []) or []],
                exclude_rules=[str(i) for i in e.get("exclude_rules", []) or []],
            )
            for e in std_raw.get("enabled", []) or []
        ],
        extra_rule_dirs=[resolve(d) for d in std_raw.get("extra_rule_dirs", []) or []],
        deviations_file=resolve(std_raw["deviations_file"]) if std_raw.get("deviations_file") else None,
        imports=[(str(i["tool"]), resolve(i["path"])) for i in std_raw.get("imports", []) or []],
    )

    match_raw = raw.get("match") or {}
    similarity = match_raw.get("similarity", MatchConfig().similarity)
    if isinstance(similarity, bool) or not isinstance(similarity, (int, float)) or not 0 < similarity <= 1:
        raise ConfigError(f"match.similarity must be a number above 0 and at most 1, not {similarity!r}")
    match = MatchConfig(similarity=float(similarity),
                        report_uncertain=bool(match_raw.get("report_uncertain", True)))

    sbom_raw = raw.get("sbom") or {}
    sbom_components = []
    for i, c in enumerate(sbom_raw.get("components") or []):
        if not isinstance(c, dict) or not c.get("name") or not c.get("path"):
            raise ConfigError(f"sbom.components[{i}] needs at least 'name' and 'path'")
        sbom_components.append(SbomComponent(
            name=str(c["name"]), path=resolve(str(c["path"])),
            version=None if c.get("version") is None else str(c["version"]),
            license=c.get("license"), supplier=c.get("supplier"), purl=c.get("purl"),
            description=c.get("description")))
    sbom = SbomConfig(components=sbom_components, include_files=bool(sbom_raw.get("include_files", False)),
                      application_version=None if sbom_raw.get("application_version") is None
                      else str(sbom_raw["application_version"]),
                      components_file=resolve(str(sbom_raw["components_file"])) if sbom_raw.get("components_file") else None)

    arch_raw = raw.get("architecture") or {}
    weights = arch_raw.get("weights") or {}
    if not isinstance(weights, dict) or any(k not in _EDGE_KINDS for k in weights) or any(
            isinstance(v, bool) or not isinstance(v, (int, float)) or v < 0 for v in weights.values()):
        raise ConfigError(f"architecture.weights must map {list(_EDGE_KINDS)} to numbers of zero or more")
    pinned = []
    for i, c in enumerate(arch_raw.get("components") or []):
        patterns = c.get("units") if isinstance(c, dict) else None
        if not isinstance(c, dict) or not c.get("name") or not isinstance(patterns, list) or not patterns:
            raise ConfigError(f"architecture.components[{i}] needs 'name' and 'units' (a list of path patterns)")
        pinned.append({"name": str(c["name"]), "units": [str(p) for p in patterns]})
    domains = arch_raw.get("domains") or []
    if not isinstance(domains, list) or not all(isinstance(d, dict) and d.get("id") for d in domains):
        raise ConfigError("architecture.domains must be a list of mappings, each with an 'id' and 'words' or 'includes'")
    from fwlens.arch.rules import validate as validate_rules
    validate_rules(arch_raw.get("rules"), arch_raw.get("intended_layers"))
    from fwlens.arch.pubsub import validate as validate_events
    validate_events(arch_raw.get("register_calls"), arch_raw.get("publish_calls"))
    patterns = arch_raw.get("patterns") or []
    if not isinstance(patterns, list) or not all(isinstance(p, dict) and p.get("id") for p in patterns):
        raise ConfigError("architecture.patterns must be a list of mappings, each with an 'id' and 'signals'")
    pins = []
    for i, s in enumerate(arch_raw.get("subsystems") or []):
        patterns = s.get("units") if isinstance(s, dict) else None
        if not isinstance(s, dict) or not s.get("domain") or not isinstance(patterns, list) or not patterns:
            raise ConfigError(f"architecture.subsystems[{i}] needs 'domain' and 'units' (a list of path patterns)")
        pins.append({"domain": str(s["domain"]), "units": [str(p) for p in patterns]})
    resolution = arch_raw.get("resolution", 1.0)
    if isinstance(resolution, bool) or not isinstance(resolution, (int, float)) or resolution <= 0:
        raise ConfigError("architecture.resolution must be a number above 0")
    architecture = ArchitectureConfig(enabled=bool(arch_raw.get("enabled", True)),
                                      weights={k: float(v) for k, v in weights.items()},
                                      private_headers=None if arch_raw.get("private_headers") is None
                                      else [str(x) for x in arch_raw["private_headers"]],
                                      components=pinned, resolution=resolution,
                                      max_component_units=int(arch_raw.get("max_component_units", 40)),
                                      drift_threshold=float(arch_raw.get("drift_threshold", 0.6)),
                                      domains=domains, subsystems=pins, patterns=patterns,
                                      intended_layers=list(arch_raw.get("intended_layers") or []),
                                      rules=list(arch_raw.get("rules") or []),
                                      register_calls=list(arch_raw.get("register_calls") or []),
                                      publish_calls=list(arch_raw.get("publish_calls") or []),
                                      baseline=resolve(str(arch_raw["baseline"])) if arch_raw.get("baseline") else None,
                                      strict_layers=bool(arch_raw.get("strict_layers", False)),
                                      forbid_cycles=bool(arch_raw.get("forbid_cycles", False)))

    cbom_raw = raw.get("cbom") or {}
    scan_scopes = [str(x) for x in cbom_raw.get("scan_scopes", ["first_party"])]
    bad_scopes = [x for x in scan_scopes if x not in _BOUNDARY_CLASSES]
    if bad_scopes:
        raise ConfigError(f"cbom.scan_scopes has unsupported value(s) {bad_scopes}; use any of {list(_BOUNDARY_CLASSES)}")
    for key in ("keywords", "apis"):
        value = cbom_raw.get(key) or []
        if not isinstance(value, list) or not all(isinstance(x, dict) for x in value):
            raise ConfigError(f"cbom.{key} must be a list of mappings")
    cbom = CbomConfig(extra_catalog_dirs=[resolve(d) for d in cbom_raw.get("extra_catalog_dirs") or []],
                      scan_scopes=scan_scopes, autodetect=bool(cbom_raw.get("autodetect", True)),
                      keywords=list(cbom_raw.get("keywords") or []),
                      ignore_identifiers=[str(x) for x in cbom_raw.get("ignore_identifiers") or []],
                      apis=list(cbom_raw.get("apis") or []), certificates=bool(cbom_raw.get("certificates", True)),
                      certificate_expiry_days=int(cbom_raw.get("certificate_expiry_days", 90)))

    pc_raw = raw.get("pr_check") or {}
    defaults = PRCheckConfig()
    pr_check = PRCheckConfig(
        base=resolve(pc_raw["base"]) if pc_raw.get("base") else None,
        base_ref=pc_raw.get("base_ref"),
        uncertain_gates=bool(pc_raw.get("uncertain_gates", defaults.uncertain_gates)),
        fail_on_new=bool(pc_raw.get("fail_on_new", defaults.fail_on_new)),
        max_items=int(pc_raw.get("max_items", defaults.max_items)),
        base_label=str(pc_raw.get("base_label", defaults.base_label)),
        report_url=pc_raw.get("report_url"),
        max_flash_growth_bytes=pc_raw.get("max_flash_growth_bytes"),
        max_ram_growth_bytes=pc_raw.get("max_ram_growth_bytes"),
        status=bool(pc_raw.get("status", defaults.status)),
    )

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
        standards=standards,
        pr_check=pr_check,
        match=match,
        sbom=sbom,
        cbom=cbom,
        architecture=architecture,
        assert_names=assert_names,
        warnings=load_warnings,
    )