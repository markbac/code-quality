"""
Config preflight validation for fwlens.

Two passes:
- run_static_preflight(config): fast checks needing no parsing -- file paths that
  must exist, obviously-wrong config values. Run immediately after load_config(),
  before any libclang work starts, so a wrong path fails in milliseconds instead
  of after a multi-minute parse.
- run_post_scan_preflight(config, model): checks that need the parsed model --
  scope matched nothing, entry_points naming functions that don't exist, RTOS
  configured but nothing found. Run once after the full pipeline completes.

Each check returns PreflightIssue(level, message) -- "error" issues are printed in
red and, for the static pass, abort the run (nothing downstream can succeed);
"warning" issues are printed in yellow and don't abort, since they're often
legitimate (e.g. no RTOS objects in a codebase that genuinely doesn't use one).
"""

from __future__ import annotations

from dataclasses import dataclass

from fwlens.config import FwLensConfig
from fwlens.model.project import ProjectModel


@dataclass
class PreflightIssue:
    level: str  # "error" | "warning"
    message: str


def run_static_preflight(config: FwLensConfig) -> list[PreflightIssue]:
    issues: list[PreflightIssue] = []

    from fwlens.libclang_locate import locate_libclang, LibclangError
    try:
        locate_libclang(config.tool.libclang_path)
    except LibclangError as e:
        issues.append(PreflightIssue("error", str(e)))

    if config.project.mode == "ewp":
        if not config.project.ewp or not config.project.ewp.exists():
            issues.append(PreflightIssue(
                "error", f"project.ewp not found: {config.project.ewp}",
            ))
        if config.project.proj_dir and not config.project.proj_dir.exists():
            issues.append(PreflightIssue(
                "error", f"project.proj_dir not found: {config.project.proj_dir}",
            ))
        if config.project.toolkit_dir and not config.project.toolkit_dir.exists():
            issues.append(PreflightIssue(
                "warning",
                f"project.toolkit_dir not found: {config.project.toolkit_dir} -- "
                "$TOOLKIT_DIR$-relative includes (e.g. CMSIS headers) will fail to resolve.",
            ))
    else:
        if not config.project.source_dir or not config.project.source_dir.exists():
            issues.append(PreflightIssue(
                "error", f"project.source_dir not found: {config.project.source_dir}",
            ))

    if not config.scope.first_party:
        issues.append(PreflightIssue(
            "warning",
            "scope.first_party is empty -- boundary classification may not behave as expected. "
            "See config.example.yaml for the expected shape.",
        ))

    for name, value in [
        ("cyclomatic_complexity", config.thresholds.cyclomatic_complexity),
        ("function_loc", config.thresholds.function_loc),
        ("fan_out", config.thresholds.fan_out),
    ]:
        if value is not None and value <= 0:
            issues.append(PreflightIssue(
                "warning", f"thresholds.{name} is {value} -- expected a positive number.",
            ))

    if config.rtos.kind not in ("none", "embos", "freertos", "threadx"):
        issues.append(PreflightIssue(
            "warning",
            f"rtos.kind is '{config.rtos.kind}' -- only 'none' and 'embos' have built-in "
            "defaults; everything else needs explicit task_functions/semaphore_functions/etc.",
        ))

    # No `-std=` flag is ever passed to clang (see fwlens/parser/ast_walker.py), so it
    # defaults to gnu17 -- where lowercase `static_assert` only exists as a macro from
    # <assert.h>, not a keyword. Any header that uses static_assert without including
    # <assert.h> itself (relying on the real IAR compiler treating it as an
    # always-available keyword, which clang doesn't) breaks for every file that reaches
    # that header without <assert.h> in its own chain -- a very common shape for a
    # generated-constants header, and one that manifests as unrelated-looking "unknown
    # type name" / "expected ')'" cascades rather than anything mentioning static_assert
    # by name, so it's easy to spend a long time chasing the symptom instead of this.
    # --auto-stub can give assert.h itself real content, but that only helps translation
    # units that already include assert.h -- this compat define is the one fix that
    # covers every translation unit regardless of what it includes.
    if not any(d.strip() in ("static_assert=_Static_assert", "static_assert =_Static_assert")
               for d in config.iar_compat_defines):
        issues.append(PreflightIssue(
            "warning",
            "iar_compat_defines does not include \"static_assert=_Static_assert\" -- if any "
            "header in this codebase uses static_assert(...) without including <assert.h> "
            "itself, every file that reaches that header will fail to parse with "
            "unrelated-looking errors (typically \"unknown type name\", \"expected ')'\", "
            "\"type specifier missing\") rather than anything mentioning static_assert. "
            "Add this line to iar_compat_defines if you see that pattern -- see "
            "config.example.yaml and the guide's Project-wide auto-stub section.",
        ))

    return issues


def run_post_scan_preflight(config: FwLensConfig, model: ProjectModel) -> list[PreflightIssue]:
    issues: list[PreflightIssue] = []

    fp_modules = model.first_party_modules()
    fp_funcs = model.first_party_functions()

    if config.scope.first_party and not fp_modules:
        issues.append(PreflightIssue(
            "error",
            f"scope.first_party={config.scope.first_party} matched zero files. "
            "Run `debug` (EWP mode) to see how files are actually being classified.",
        ))

    if not fp_funcs:
        issues.append(PreflightIssue(
            "error",
            "Zero first-party functions were extracted -- check parse diagnostics "
            "(top of the HTML report, or parse_diagnostics.csv) before trusting any metric.",
        ))

    fp_func_names = {f.name for f in fp_funcs}
    missing_entry_points = [e for e in config.entry_points if e not in fp_func_names]
    if missing_entry_points:
        issues.append(PreflightIssue(
            "warning",
            f"entry_points not found among parsed first-party functions: {missing_entry_points}. "
            "Likely a typo, a function that's actually conditionally compiled out, or a "
            "third-party/SDK function -- dead-code exclusion for these names has no effect.",
        ))

    if config.rtos.kind != "none" and not model.rtos_tasks and not model.rtos_sync_objects:
        issues.append(PreflightIssue(
            "warning",
            f"rtos.kind is '{config.rtos.kind}' but zero tasks and zero sync objects were found. "
            "Check that task_functions/semaphore_functions/etc. actually match your codebase's "
            "real API names and argument order -- see the RTOS tab's 'About these metrics' panel.",
        ))

    # Sanity-check the include graph rather than silently trusting it: "0 circular
    # includes, 0 self-includes, every file's transitive include depth == 1" is what a
    # genuinely shallow codebase looks like, but it's ALSO exactly what a header->header
    # edge-building bug looks like -- and the two are indistinguishable from the report
    # output alone, which is precisely how one such bug (build_include_graph only ever
    # wired .c-file -> header edges, never header -> header) went unnoticed. This check
    # can't tell you which case you're in, but it can stop the flat-graph case from
    # reading as clean silently -- see the Header Include Analysis section (Architecture
    # tab) and its "About these checks" panel for what these numbers mean.
    fp_with_includes = [m for m in fp_modules if m.includes]
    if fp_with_includes:
        max_depth = max((m.include_depth for m in fp_modules), default=0)
        header_to_header_edges = sum(
            1 for m in model.modules for (src, _dst) in m.all_include_edges
            if str(src) != str(m.path)
        )
        if max_depth <= 1 and header_to_header_edges == 0:
            issues.append(PreflightIssue(
                "warning",
                f"Include graph looks suspiciously flat: {len(fp_with_includes)} first-party "
                f"file(s) have direct #includes, but the deepest transitive include depth found "
                f"anywhere is {max_depth} and zero header-to-header edges were recorded. For a "
                f"codebase this size that usually means the include graph isn't being built "
                f"correctly (e.g. header->header edges missing), not that headers genuinely "
                f"never include each other -- treat Circular Includes/Self-Includes/Deepest "
                f"Include Chains results with caution until this is understood.",
            ))

    return issues


def print_preflight_issues(issues: list[PreflightIssue], console) -> bool:
    """Print issues via the given rich Console. Returns True if any 'error'-level
    issue was found (caller should abort in that case for the static pass)."""
    if not issues:
        return False
    has_error = any(i.level == "error" for i in issues)
    console.print("\n[bold]Preflight[/bold]")
    for i in issues:
        colour = "red" if i.level == "error" else "yellow"
        icon = "\u2717" if i.level == "error" else "\u26a0"
        console.print(f"  [{colour}]{icon} {i.message}[/{colour}]")
    return has_error
