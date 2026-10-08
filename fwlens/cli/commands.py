"""
fwlens -- Embedded C Architecture & Static Analysis Platform

Usage:
  python main.py analyze --config config.yaml
  python main.py report  --config config.yaml
  python main.py export  --config config.yaml
  python main.py debug   --config config.yaml
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import click
from rich.console import Console

from fwlens import __version__
from fwlens.timing import phase, timer

console = Console()


_CONFIG_NAMES = ("config.yaml", ".fwlens.yaml", "fwlens.yaml")


class _ConfigFile(click.ParamType):
    """
    A path to config.yaml. When the default name is not in the working directory, look for
    config.yaml, .fwlens.yaml or fwlens.yaml in the working directory and each parent, so
    FWLens can be run from a subdirectory of the project.
    """
    name = "config file"

    def convert(self, value, param, ctx):
        path = Path(value)
        if path.is_file():
            return str(path)
        if value == "config.yaml":
            for directory in (Path.cwd(), *Path.cwd().parents):
                for candidate in _CONFIG_NAMES:
                    if (directory / candidate).is_file():
                        return str(directory / candidate)
        self.fail(f"Config file '{value}' does not exist.", param, ctx)


_CONFIG_FILE = _ConfigFile()


def _load_config_safe(config_path: Path):
    from fwlens.config import ConfigError, load_config
    try:
        return load_config(config_path)
    except ConfigError as e:
        console.print(f"[fwlens] ERROR: {e}")
        sys.exit(1)


def _run_pipeline(config_path: Path, auto_stub: bool = False, jobs=None, timeout=None, no_cache: bool = False,
                  configuration: str | None = None):
    from fwlens.arch import run_architecture
    from fwlens.clones import detect_clones
    from fwlens.complexity_trend import compute_complexity_trends
    from fwlens.cost_benefit import compute_cost_benefit
    from fwlens.defect_analysis import compute_defect_correlation
    from fwlens.effort_estimate import compute_effort_estimate
    from fwlens.git_history import (
        compute_architecture_coupling,
        compute_change_coupling,
        compute_churn_heatmap,
        compute_commit_activity,
        compute_hotspots,
    )
    from fwlens.graph.engines import run_graph_engine
    from fwlens.hotspot_names import flag_hotspot_names
    from fwlens.metrics.aggregates import run_aggregation
    from fwlens.ownership import compute_ownership
    from fwlens.parser.pipeline import run_pipeline
    from fwlens.preflight import print_preflight_issues, run_post_scan_preflight, run_static_preflight
    from fwlens.reliability import compute_bugfix_hotspots, compute_reliability_growth
    from fwlens.risk import compute_composite_risk
    from fwlens.rtos_analysis import run_rtos_analysis
    from fwlens.state_machines import detect_state_machines
    from fwlens.stats.distributions import run_stats_engine
    from fwlens.tech_debt import run_tech_debt_scan

    config = _load_config_safe(config_path)
    if configuration:
        config.project.configuration = configuration          # a build configuration other than the one in the file
    from fwlens.git_history import history_warnings, reset_history_state
    reset_history_state()

    static_issues = run_static_preflight(config)
    if print_preflight_issues(static_issues, console):
        console.print("\n[bold red][fwlens] Aborting -- fix the error(s) above before running analysis.[/bold red]")
        raise SystemExit(1)

    if auto_stub:
        if config.project.mode == "directory":
            console.print("[yellow][fwlens] --auto-stub has no effect in directory mode "
                          "(no $TOOLKIT_DIR$ headers to stub around) -- skipping.[/yellow]")
        else:
            from fwlens.autostub import run_auto_stub
            run_auto_stub(config, console)

    timer.reset()
    timer.show = config.output.show_timing
    t0 = time.perf_counter()
    with phase("Parse project"):
        model = run_pipeline(config, jobs=jobs, timeout=timeout, use_cache=False if no_cache else None)

    def clusters(m, c):
        m.diagnostic_clusters = compute_diagnostic_clusters(m)

    def warnings_(m, c):
        m.history_warnings = history_warnings()

    from fwlens.diagnostic_clusters import compute_diagnostic_clusters
    from fwlens.footprint import apply_map_file
    steps = [
        ("Linker map", apply_map_file), ("Diagnostic clusters", clusters), ("Aggregate metrics", run_aggregation),
        ("Call graph", run_graph_engine), ("Statistics", run_stats_engine), ("Hotspots", compute_hotspots),
        ("Change coupling", compute_change_coupling), ("Churn heatmap", compute_churn_heatmap),
        ("Commit activity", compute_commit_activity), ("Architecture coupling", compute_architecture_coupling),
        ("Ownership", compute_ownership), ("Hotspot names", lambda m, c: flag_hotspot_names(m)),
        ("Complexity trends", compute_complexity_trends), ("Effort estimate", compute_effort_estimate),
        ("Reliability growth", compute_reliability_growth), ("Bug-fix hotspots", compute_bugfix_hotspots),
        ("Defect correlation", compute_defect_correlation), ("History warnings", warnings_),
        ("Cost-benefit", compute_cost_benefit), ("RTOS analysis", run_rtos_analysis),
        ("State machines", lambda m, c: detect_state_machines(m)), ("Technical debt", lambda m, c: run_tech_debt_scan(m)),
        ("Clone detection", lambda m, c: detect_clones(m)), ("Composite risk", lambda m, c: compute_composite_risk(m)),
        ("Architecture", run_architecture),
    ]
    for name, step in steps:
        with phase(name):
            step(model, config)
    elapsed = time.perf_counter() - t0
    console.print(f"[cyan][fwlens][/cyan] Analysis complete in [bold]{elapsed:.1f}s[/bold]")

    with phase("Post-scan checks"):
        post_issues = run_post_scan_preflight(config, model)
    print_preflight_issues(post_issues, console)

    return model, config


_CONFIG_TEMPLATES = {
    "cmake": """# fwlens configuration for CMake project
tool:
  libclang_path: C:\\Program Files\\LLVM\\bin\\libclang.dll  # Adjust for your OS

project:
  compile_commands: build/compile_commands.json
  mode: cmake

scope:
  first_party: [src, inc]
  sdk: [sdk]
  third_party_lib: [lib, vendor]
  analyse: [first_party]

thresholds:
  cyclomatic_complexity: 15
  cognitive_complexity: 20
  function_loc: 100
""",
    "make": """# fwlens configuration for Make project
tool:
  libclang_path: C:\\Program Files\\LLVM\\bin\\libclang.dll  # Adjust for your OS

project:
  compile_commands: compile_commands.json
  mode: make

scope:
  first_party: [src, inc]
  sdk: [sdk]
  third_party_lib: [lib, vendor]
  analyse: [first_party]

thresholds:
  cyclomatic_complexity: 15
  cognitive_complexity: 20
  function_loc: 100
""",
    "ewp": """# fwlens configuration for IAR Embedded Workbench (.ewp) project
tool:
  libclang_path: C:\\Program Files\\LLVM\\bin\\libclang.dll

project:
  ewp: Project.ewp
  configuration: Release
  toolkit_dir: C:\\Program Files\\IAR Systems\\Embedded Workbench 9.6\\arm

scope:
  first_party: [Src, Inc]
  sdk: [sdk]
  third_party_lib: [Lib]
  analyse: [first_party]

thresholds:
  cyclomatic_complexity: 15
  cognitive_complexity: 20
  function_loc: 100
""",
    "directory": """# fwlens configuration for Directory Scan mode
tool:
  libclang_path: C:\\Program Files\\LLVM\\bin\\libclang.dll  # Adjust for your OS

project:
  source_dir: .

scope:
  first_party: [.]
  sdk: []
  third_party_lib: []
  analyse: [first_party]

thresholds:
  cyclomatic_complexity: 15
  cognitive_complexity: 20
  function_loc: 100
"""
}


def _keep_output_alive() -> None:
    """
    Under Measure-Command, a pipe or a redirect, Windows gives Python a legacy code page such as cp1252,
    and the first icon rich prints (the warning sign in the preflight list) raised UnicodeEncodeError and
    stopped the run. A character the stream cannot encode is now written as '?'.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")           # type: ignore[union-attr]
        except (AttributeError, ValueError, OSError):
            pass


def _print_timing() -> None:
    if timer.show:
        timer.render(console)


@click.group()
@click.pass_context
def cli(ctx):
    """fwlens -- Embedded C Architecture & Static Analysis Platform."""
    _keep_output_alive()
    ctx.call_on_close(_print_timing)          # also when a gate ends the command with exit code 1


@cli.command()
@click.option("--output", "-o", default="config.yaml", help="Output file path (default: config.yaml)")
@click.option("--type", "-t", "project_type", type=click.Choice(["cmake", "make", "ewp", "directory", "auto"]), default="auto", help="Project type template")
def init(output: str, project_type: str):
    """Generate a starter config.yaml template for your project."""
    target_path = Path(output)
    if target_path.exists():
        console.print(f"[yellow][fwlens] WARNING: '{output}' already exists. Overwrite? (y/n)[/yellow]")
        return

    if project_type == "auto":
        cwd = Path.cwd()
        if (cwd / "CMakeLists.txt").exists() or (cwd / "build" / "compile_commands.json").exists():
            project_type = "cmake"
        elif (cwd / "Makefile").exists() or (cwd / "compile_commands.json").exists():
            project_type = "make"
        elif list(cwd.glob("*.ewp")):
            project_type = "ewp"
        else:
            project_type = "directory"

    template = _CONFIG_TEMPLATES.get(project_type, _CONFIG_TEMPLATES["directory"])
    target_path.write_text(template, encoding="utf-8")
    console.print(f"[cyan][fwlens][/cyan] Created starter configuration template ([bold]{project_type}[/bold] mode): [bold]{target_path.resolve()}[/bold]")


@cli.command(name="config-schema")
@click.option("--output", "-o", "out_path", type=click.Path(), default=None,
              help="Write the schema to this file instead of standard output.")
def config_schema(out_path):
    """Print the JSON Schema for config.yaml (generated from the config dataclasses)."""
    import json

    from fwlens.config_schema import json_schema
    text = json.dumps(json_schema(), indent=2) + "\n"
    if out_path:
        Path(out_path).write_text(text, encoding="utf-8")
    else:
        click.echo(text, nl=False)


@cli.command()
@click.option("--config", "-c", default="config.yaml", help="Path to config.yaml (optional)")
def doctor(config: str):
    """Environment and configuration self-check."""
    console.print("[bold cyan]fwlens doctor -- System & Environment Diagnostics[/bold cyan]\n")

    # 1. Python version check
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    console.print(f"  [green]✓[/green] Python version: {py_ver} (>= 3.10)")

    # 2. Config & libclang check
    from fwlens.libclang_locate import LibclangError, locate_libclang
    cfg_path = Path(config)
    libclang_path = None
    target = "native"
    if cfg_path.exists():
        try:
            from fwlens.config import load_config
            cfg = load_config(cfg_path)
            libclang_path = cfg.tool.libclang_path
            target = cfg.tool.target or "native"
            console.print(f"  [green]✓[/green] Config file loaded: [bold]{cfg_path}[/bold]")
            mf = cfg.project.map_file
            if mf is not None and not mf.exists():
                console.print(f"  [yellow]![/yellow] project.map_file does not exist yet: {mf} "
                              "(build first; footprint is skipped until it does)")
            elif mf is not None:
                from fwlens.parser.mapfile import parse_linker_mapfile
                found = len(parse_linker_mapfile(mf))
                mark = "[green]✓[/green]" if found else "[yellow]![/yellow]"
                console.print(f"  {mark} Map file {mf.name}: {found} objects with sizes"
                              + ("" if found else " (only GCC-style .text/.data/.bss lines are read)"))
            for label, value in (
                ("project.ewp", cfg.project.ewp), ("project.source_dir", cfg.project.source_dir),
                ("project.compile_commands", cfg.project.compile_commands),
                ("project.map_file", cfg.project.map_file),
                ("project.uvprojx", cfg.project.uvprojx), ("project.cproject", cfg.project.cproject),
                ("project.proj_dir", cfg.project.proj_dir), ("project.toolkit_dir", cfg.project.toolkit_dir),
                ("tool.libclang_path", cfg.tool.libclang_path), ("tool.sysroot", cfg.tool.sysroot),
                *[("tool.system_include_dirs", d) for d in cfg.tool.system_include_dirs],
                ("output.reports_dir", cfg.output.reports_dir), ("output.exports_dir", cfg.output.exports_dir),
                ("output.cache_dir", cfg.output.cache_dir), ("output.db_path", cfg.output.db_path),
            ):
                if value is not None:
                    console.print(f"      [dim]{label}[/dim] = {value}")
        except Exception as e:
            console.print(f"  [yellow]![/yellow] Config load warning: {e}")
    else:
        console.print(f"  [dim]•[/dim] Config file '{config}' not found (using default check)")

    try:
        loc = locate_libclang(libclang_path)
        console.print(f"  [green]✓[/green] libclang found: [bold]{loc.path}[/bold] (source: {loc.source})")
    except LibclangError as e:
        console.print(f"  [red]✗[/red] libclang discovery failed: {e}")

    # 3. Host compiler check
    from fwlens.sysinc import detect_system_includes
    inc_dirs, compiler, triple = detect_system_includes(target)
    if compiler:
        console.print(f"  [green]✓[/green] System include compiler: [bold]{compiler}[/bold] (target: '{triple or target}', {len(inc_dirs)} include dirs)")
    else:
        console.print(f"  [yellow]![/yellow] No system include compiler found for target '{target}'")

    # 4. Git binary check
    import shutil
    git_bin = shutil.which("git")
    if git_bin:
        console.print(f"  [green]✓[/green] Git binary found: [bold]{git_bin}[/bold]")
    else:
        console.print("  [yellow]![/yellow] Git binary not found")


@cli.result_callback()
def _post_group(*args, **kwargs):
    pass


def _print_header(command: str, config_path: str):
    console.print(f"[cyan][fwlens][/cyan] Version : [bold]{__version__}[/bold]")
    console.print(f"[cyan][fwlens][/cyan] Running : [dim]{__file__}[/dim]")
    console.print(f"[cyan][fwlens][/cyan] Command : {command}")
    console.print(f"[cyan][fwlens][/cyan] Config  : {Path(config_path).resolve()}")


# Shared --baseline / --fail-on-breach / --update-baseline options for `analyze` and `report`.
def _parse_error_option(f):
    return click.option(
        "--fail-on-parse-error", is_flag=True, default=False,
        help="Exit 1 if the share of files with fatal/error parse diagnostics exceeds "
             "tool.parse_error_threshold (default 0, so any such file fails). "
             "A run that parsed nothing always fails.")(f)


def _parse_health_failed(model, config, fail_on_parse_error: bool) -> bool:
    """True when parsing was so incomplete the results should not be trusted."""
    stats = getattr(model, "parse_stats", None) or {}
    total = stats.get("in_scope", 0)
    if total and stats.get("parsed_ok", 0) == 0:
        console.print("[bold red][fwlens] Nothing could be parsed -- failing so an empty result "
                      "cannot pass a gate.[/bold red]")
        return True
    if fail_on_parse_error and total:
        ratio = stats.get("files_with_errors", 0) / total
        if ratio > config.tool.parse_error_threshold:
            console.print(f"[bold red][fwlens] {stats['files_with_errors']}/{total} files have fatal/error "
                          f"parse diagnostics (threshold {config.tool.parse_error_threshold:.0%}).[/bold red]")
            return True
    return False


def _gitlab_option(f):
    return click.option(
        "--gitlab-codequality", "gitlab_codequality", default=None, type=click.Path(),
        help="Write a GitLab Code Quality report (JSON) to this path. Defaults to "
             "gl-code-quality-report.json when GITLAB_CI=true.")(f)


def _findings_option(f):
    return click.option(
        "--findings-json", "findings_json", default=None, type=click.Path(),
        help="Write the findings with stable ids and fingerprints to this file, for use as the "
             "--base reference of `fwlens compare` / `pr-comment` in a later pipeline.")(f)


def _diff_options(f):
    f = click.option("--changed-scope", "changed_scope", type=click.Choice(["file", "function"]),
                      default="file", show_default=True,
                      help="With --changed-since: report findings in changed files, or only in "
                           "functions that overlap a changed hunk.")(f)
    f = click.option("--changed-since", "changed_since", default=None, metavar="REF",
                      help="Report and gate only findings in code changed since REF (merge base). "
                           "The whole project is still parsed, so totals stay correct. Defaults to "
                           "GITHUB_BASE_REF or CI_MERGE_REQUEST_DIFF_BASE_SHA when set. A base that "
                           "cannot be found (shallow clone) falls back to all findings, with a message.")(f)
    return f


def _apply_diff_mode(breaches, model, config, changed_since, changed_scope):
    from fwlens.diffmode import changed_lines, detect_base, filter_breaches
    from fwlens.identity import project_root, relative_posix

    base = detect_base(changed_since)
    if not base:
        return breaches
    root = project_root(config)
    changes, problem = changed_lines(root, base)
    if changes is None:
        console.print(f"[yellow][fwlens] Diff mode: {problem} Reporting all findings.[/yellow]")
        return breaches
    lengths = {(relative_posix(f.file, root), f.name): f.loc for f in model.first_party_functions()}
    kept = filter_breaches(breaches, changes, changed_scope, lengths)
    console.print(f"[cyan][fwlens][/cyan] Diff mode vs [bold]{base}[/bold]: {len(changes.files)} changed file(s), "
                  f"{len(kept)} of {len(breaches)} finding(s) in changed {changed_scope}s")
    return kept


def _sarif_option(f):
    return click.option(
        "--sarif", "sarif_path", default=None, type=click.Path(),
        help="Write the findings as SARIF 2.1.0 to this path (for GitHub code scanning, "
             "github/codeql-action/upload-sarif). `report` also writes "
             "exports/fwlens.sarif when output.formats includes sarif.")(f)


def _ci_report_options(f):
    f = click.option(
        "--junit", "junit_path", default=None, type=click.Path(),
        help="Write the findings as JUnit XML (one failed test case per finding), for CI test views "
             "such as GitLab artifacts:reports:junit.")(f)
    f = click.option(
        "--markdown-summary", "markdown_summary", default=None, type=click.Path(),
        help="Write a Markdown summary of the findings to this path. Pass $GITHUB_STEP_SUMMARY to "
             "show it on the workflow run (it is appended to, not overwritten).")(f)
    return f


def _history_options(f):
    f = click.option("--record-run", is_flag=True, default=False,
                     help="Store a summary of this run (and its findings) in output.db_path, for trends and --ratchet.")(f)
    f = click.option("--run-label", default=None, help="Name for the stored run, for example a release tag.")(f)
    f = click.option("--ratchet", is_flag=True, default=False,
                     help="Exit 1 when total findings or layer violations are higher than in the previous "
                          "accepted run in output.db_path. Fewer is fine. With --record-run, a failing run "
                          "is stored but does not become the new reference.")(f)
    return f


def _handle_history(model, config, breaches, record_run, run_label, ratchet) -> bool:
    """Record the run and apply the ratchet. Returns True when the ratchet fails."""
    if not (record_run or ratchet):
        return False
    from fwlens.history_db import (
        HistoryError,
        previous_accepted,
        ratchet_failures,
        record_run as store,
        summarise,
    )
    from fwlens.identity import project_root
    db = config.output.db_path
    summary = summarise(model, breaches)
    failures: list[str] = []
    try:
        if ratchet:
            previous = previous_accepted(db)
            if previous is None:
                console.print(f"[yellow][fwlens] --ratchet: no earlier accepted run in {db}; nothing to compare "
                              "with, so this run passes.[/yellow]")
            failures = ratchet_failures(summary, previous)
            for msg in failures:
                console.print(f"[red][fwlens] Ratchet: {msg} (run #{previous['id']}).[/red]")
            if previous is not None and not failures:
                console.print(f"[green][fwlens] Ratchet: no worse than run #{previous['id']}.[/green]")
        if record_run:
            run_id = store(db, summary, breaches, label=run_label, accepted=not failures, root=project_root(config))
            console.print(f"[cyan][fwlens][/cyan] Run #{run_id} recorded in [bold]{db}[/bold]"
                          + ("" if not failures else " (not accepted: the ratchet failed)"))
    except HistoryError as e:
        console.print(f"[red][fwlens] {e}[/red]")
        raise SystemExit(2)
    return bool(failures)


def _emit_ci_reports(breaches, model, junit_path, markdown_summary):
    if junit_path:
        from fwlens.output.reporters import JUnitReporter
        path = JUnitReporter().emit(breaches, junit_path)
        console.print(f"[cyan][fwlens][/cyan] JUnit report: [bold]{path}[/bold] ({len(breaches)} finding(s))")
    if markdown_summary:
        from fwlens.output.reporters import markdown_summary as render
        text = render(breaches, functions=len(list(model.first_party_functions())),
                      modules=len(list(model.first_party_modules())))
        target = Path(markdown_summary)
        target.parent.mkdir(parents=True, exist_ok=True)
        mode = "a" if os.environ.get("GITHUB_STEP_SUMMARY") and \
            target == Path(os.environ["GITHUB_STEP_SUMMARY"]) else "w"
        with open(target, mode, encoding="utf-8") as fh:
            fh.write(text)
        console.print(f"[cyan][fwlens][/cyan] Markdown summary: [bold]{target}[/bold]")


def _emit_sarif(model, config, path, breaches=None):
    from fwlens.output.sarif import write_sarif_report
    written = write_sarif_report(model, config, Path(path), breaches)
    console.print(f"[cyan][fwlens][/cyan] SARIF report: [bold]{written}[/bold]")


def _emit_gitlab_report(breaches, gitlab_codequality):
    from fwlens.output.reporters import GitLabReporter, default_gitlab_report_path, running_on_gitlab
    if not gitlab_codequality and not running_on_gitlab():
        return
    path = GitLabReporter().emit(breaches, gitlab_codequality or default_gitlab_report_path())
    console.print(f"[cyan][fwlens][/cyan] GitLab Code Quality report: [bold]{path}[/bold] "
                  f"({len(breaches)} finding(s))")


def _baseline_options(f):
    f = click.option("--github-annotations", is_flag=True, default=False,
                      help="Emit GitHub Actions workflow commands (::warning file=...::) for PR diff annotations.")(f)
    f = click.option("--prune", is_flag=True, default=False,
                      help="With --update-baseline, also remove baseline entries that no longer "
                           "match any breach (resolved).")(f)
    f = click.option("--accept-id", "accept_ids", multiple=True,
                      help="With --update-baseline, accept only this breach id "
                           "(repeatable). Omit to use --accept-all instead.")(f)
    f = click.option("--accept-all", is_flag=True, default=False,
                      help="With --update-baseline, accept every breach found in this run.")(f)
    f = click.option("--update-baseline", "update_baseline_flag", is_flag=True, default=False,
                      help="Write accepted breaches into --baseline instead of gating on them.")(f)
    f = click.option("--fail-on-breach", is_flag=True, default=False,
                      help="Exit 1 if any new or worsened breach vs --baseline is found.")(f)
    f = click.option("--baseline", "baseline_path", default=None, type=click.Path(),
                      help="Path to baseline.json for breach gating. "
                           "Without this, breaches are reported but nothing is gated.")(f)
    return f


def emit_github_annotations(breaches):
    """Output GitHub Actions workflow commands so breaches appear inline on PR code diffs."""
    from fwlens.output.reporters import GitHubReporter
    GitHubReporter().emit(breaches)


def _handle_baseline(model, config, *, baseline_path, fail_on_breach,
                      update_baseline_flag, accept_all, accept_ids, github_annotations=False,
                      prune=False, gitlab_codequality=None, findings_json=None, sarif_path=None,
                      changed_since=None, changed_scope="file", junit_path=None, markdown_summary=None,
                      record_run=False, run_label=None, ratchet=False):
    """Compute breaches and either update the baseline or gate on it. Returns True to fail the run."""
    from fwlens.baseline import (
        classify_against_baseline,
        compute_breaches,
        load_baseline,
        update_baseline,
    )
    from fwlens.output.console import print_baseline_summary

    breaches = compute_breaches(model, config)
    ratchet_failed = _handle_history(model, config, breaches, record_run, run_label, ratchet)
    from fwlens.diffmode import detect_base
    if detect_base(changed_since):
        if update_baseline_flag:
            console.print("[red][fwlens] --update-baseline cannot be combined with diff mode: "
                          "the baseline would lose findings outside the diff.[/red]")
            raise SystemExit(2)
        breaches = _apply_diff_mode(breaches, model, config, changed_since, changed_scope)

    if github_annotations:
        emit_github_annotations(breaches)
    _emit_gitlab_report(breaches, gitlab_codequality)
    if sarif_path:
        _emit_sarif(model, config, sarif_path, breaches)
    _emit_ci_reports(breaches, model, junit_path, markdown_summary)
    if findings_json:
        from fwlens.pr_check import write_findings
        write_findings(Path(findings_json), breaches, getattr(model, "footprint", None))
        console.print(f"[cyan][fwlens][/cyan] Findings written: [bold]{findings_json}[/bold] "
                      f"({len(breaches)} finding(s))")

    if not baseline_path:
        return ratchet_failed

    path = Path(baseline_path)

    if update_baseline_flag:
        accepted = update_baseline(path, breaches, accept_all=accept_all, accept_ids=list(accept_ids),
                                   prune=prune, match=config.match)
        console.print(f"[cyan][fwlens][/cyan] Baseline updated: [bold]{path}[/bold] "
                      f"({len(accepted)} accepted breach(es) on file)")
        return ratchet_failed

    baseline = load_baseline(path)
    result = classify_against_baseline(breaches, baseline, match=config.match)
    gating = {id(m.current) for m in result.gating()}
    new_or_worsened = [b for b in breaches if id(b) in gating]
    accepted_unchanged = [b for b in breaches if id(b) not in gating]
    print_baseline_summary(new_or_worsened, accepted_unchanged, path, result)

    return bool((fail_on_breach and new_or_worsened) or ratchet_failed)


def _parse_options(f):
    f = click.option("--jobs", "-j", "jobs", type=click.IntRange(min=1), default=None,
                      help="Parallel parse workers (default: tool.jobs, else CPUs minus one).")(f)
    f = click.option("--timeout", "timeout", type=click.FloatRange(min=0), default=None,
                      help="Seconds allowed per source file before its parse is killed and "
                           "reported as a 'timeout' parse error (0 = no limit; default: "
                           "tool.parse_timeout).")(f)
    f = click.option("--no-cache", "no_cache", is_flag=True, default=False,
                      help="Ignore and do not update the per-file parse cache.")(f)
    return f


def _auto_stub_option(f):
    f = click.option("--auto-stub", "auto_stub", is_flag=True, default=False,
                      help="Before parsing, aggregate missing-header/undeclared-function "
                           "errors across the whole project and write stubs to iar_stubs/ "
                           "(same mechanism as debug-parse, generalised beyond one file). "
                           "EWP mode only; no effect in directory mode.")(f)
    return f


@cli.command()
@click.option("--config", "config_path", default="config.yaml",
              type=_CONFIG_FILE, help="Path to config.yaml")
@_auto_stub_option
@_parse_options
@_parse_error_option
@_gitlab_option
@_findings_option
@_sarif_option
@_ci_report_options
@_history_options
@_diff_options
@_baseline_options
def analyze(config_path: str, auto_stub, jobs, timeout, no_cache, fail_on_parse_error, baseline_path, fail_on_breach,
            update_baseline_flag, accept_all, accept_ids, prune, github_annotations,
            gitlab_codequality, findings_json, sarif_path, junit_path, markdown_summary,
            record_run, run_label, ratchet, changed_since, changed_scope):
    """Run analysis and print breach summary to terminal."""
    _print_header("analyze", config_path)
    from fwlens.output.console import print_summary
    model, config = _run_pipeline(Path(config_path), auto_stub=auto_stub, jobs=jobs, timeout=timeout, no_cache=no_cache)
    print_summary(model, config)

    should_fail = _handle_baseline(
        model, config, baseline_path=baseline_path, fail_on_breach=fail_on_breach,
        update_baseline_flag=update_baseline_flag, accept_all=accept_all, accept_ids=accept_ids,
        github_annotations=github_annotations, prune=prune,
        gitlab_codequality=gitlab_codequality, findings_json=findings_json, sarif_path=sarif_path,
        changed_since=changed_since, changed_scope=changed_scope,
        junit_path=junit_path, markdown_summary=markdown_summary,
        record_run=record_run, run_label=run_label, ratchet=ratchet,
    )
    if _parse_health_failed(model, config, fail_on_parse_error):
        should_fail = True
    if should_fail:
        sys.exit(1)


@cli.command()
@click.option("--config", "config_path", default="config.yaml",
              type=_CONFIG_FILE, help="Path to config.yaml")
@_auto_stub_option
@_parse_options
@_parse_error_option
@_gitlab_option
@_findings_option
@_sarif_option
@_ci_report_options
@_history_options
@_diff_options
@_baseline_options
def report(config_path: str, auto_stub, jobs, timeout, no_cache, fail_on_parse_error, baseline_path, fail_on_breach,
           update_baseline_flag, accept_all, accept_ids, prune, github_annotations,
           gitlab_codequality, findings_json, sarif_path, junit_path, markdown_summary,
            record_run, run_label, ratchet, changed_since, changed_scope):
    """Run analysis and generate HTML report + exports."""
    from fwlens.output.console import print_summary
    from fwlens.output.exports import export_csv, export_json
    from fwlens.output.html_report import generate_html_report

    model, config = _run_pipeline(Path(config_path), auto_stub=auto_stub, jobs=jobs, timeout=timeout, no_cache=no_cache)
    print_summary(model, config)

    formats = config.output.formats
    if "html" in formats:
        with phase("HTML report"):
            path = generate_html_report(model, config)
        console.print(f"[cyan][fwlens][/cyan] HTML report: [bold]{path}[/bold]")
    if "csv" in formats:
        with phase("CSV exports"):
            export_csv(model, config)
        console.print(f"[cyan][fwlens][/cyan] CSV exports: [bold]{config.output.exports_dir}[/bold]")
    if "json" in formats:
        with phase("JSON export"):
            export_json(model, config)
        console.print(f"[cyan][fwlens][/cyan] JSON export: [bold]{config.output.exports_dir / 'fwlens_results.json'}[/bold]")
    if "sarif" in formats and not sarif_path:
        with phase("SARIF"):
            _emit_sarif(model, config, config.output.exports_dir / "fwlens.sarif")
    if "sbom" in formats:
        from fwlens.sbom import write_sbom
        with phase("SBOM"):
            written = write_sbom(config, config.output.exports_dir / 'sbom.cdx.json')
        console.print(f"[cyan][fwlens][/cyan] SBOM        : [bold]{written}[/bold]")
    if "cbom" in formats:
        from fwlens.cbom import write_cbom
        with phase("CBOM"):
            written = write_cbom(config, config.output.exports_dir / 'cbom.cdx.json')
        console.print(f"[cyan][fwlens][/cyan] CBOM        : [bold]{written}[/bold]")
    if "architecture" in formats:
        written_arch = _write_architecture_exports(model, config)
        for path in written_arch:
            console.print(f"[cyan][fwlens][/cyan] Architecture  : [bold]{path}[/bold]")
    if "plots" in formats:
        from fwlens.output.plots import generate_plots
        with phase("Plots"):
            plots_dir = generate_plots(model, config)
        console.print(f"[cyan][fwlens][/cyan] Plots       : [bold]{plots_dir}[/bold]")
    if "diagrams" in formats:
        from fwlens.output.diagrams import generate_architecture_diagram, generate_dependency_svg
        with phase("Diagrams"):
            arch_path = generate_architecture_diagram(model, config)
            svg_path = generate_dependency_svg(model, config)
        console.print(f"[cyan][fwlens][/cyan] Architecture diagram: [bold]{arch_path}[/bold]")
        console.print(f"[cyan][fwlens][/cyan] Dependency SVG      : [bold]{svg_path}[/bold]")

    should_fail = _handle_baseline(
        model, config, baseline_path=baseline_path, fail_on_breach=fail_on_breach,
        update_baseline_flag=update_baseline_flag, accept_all=accept_all, accept_ids=accept_ids,
        github_annotations=github_annotations, prune=prune,
        gitlab_codequality=gitlab_codequality, findings_json=findings_json, sarif_path=sarif_path,
        changed_since=changed_since, changed_scope=changed_scope,
        junit_path=junit_path, markdown_summary=markdown_summary,
        record_run=record_run, run_label=run_label, ratchet=ratchet,
    )
    if _parse_health_failed(model, config, fail_on_parse_error):
        should_fail = True
    if should_fail:
        sys.exit(1)


@cli.command()
@click.option("--config", "config_path", default="config.yaml",
              type=_CONFIG_FILE, help="Path to config.yaml")
@_auto_stub_option
@_parse_options
@_sarif_option
def export(config_path: str, auto_stub, jobs, timeout, no_cache, sarif_path):
    """Run analysis and export CSV + JSON only (no HTML report). Add --sarif PATH for SARIF."""
    from fwlens.output.exports import export_csv, export_json
    model, config = _run_pipeline(Path(config_path), auto_stub=auto_stub, jobs=jobs, timeout=timeout, no_cache=no_cache)
    export_csv(model, config)
    export_json(model, config)
    if sarif_path:
        _emit_sarif(model, config, sarif_path)
    console.print(f"[cyan][fwlens][/cyan] Exports written to: [bold]{config.output.exports_dir}[/bold]")


@cli.command(name="sbom")
@click.option("--config", "config_path", default="config.yaml", type=_CONFIG_FILE, help="Path to config.yaml")
@click.option("--output", "output_path", default=None, type=click.Path(),
              help="Where to write the CycloneDX JSON (default: <exports_dir>/sbom.cdx.json).")
def sbom_cmd(config_path, output_path):
    """Write a Software Bill of Materials (CycloneDX 1.6 JSON) from the source tree and project file."""
    from fwlens.config import load_config
    from fwlens.sbom import write_sbom
    config = load_config(Path(config_path))
    target = Path(output_path) if output_path else config.output.exports_dir / "sbom.cdx.json"
    written = write_sbom(config, target)
    doc = json.loads(written.read_text(encoding="utf-8"))
    unknown = sum(1 for c in doc["components"]
                  if any(p["name"] == "fwlens:version-source" and p["value"] == "unknown" for p in c["properties"]))
    console.print(f"[cyan][fwlens][/cyan] SBOM: [bold]{written}[/bold] ({len(doc['components'])} component(s), "
                  f"{unknown} without a version)")


def _write_architecture_exports(model, config) -> list:
    """PlantUML and Structurizr DSL files for the recovered architecture."""
    from fwlens.arch.export import write_exports
    if model.architecture is None:
        console.print("[yellow][fwlens] Architecture model is off (architecture.enabled: false) -- nothing to export.[/yellow]")
        return []
    with phase("Architecture export"):
        return write_exports(model.architecture, config.output.reports_dir / "architecture", config.config_path.parent.name or "Firmware")


@cli.group(name="architecture")
def architecture_group():
    """Recovered architecture: exports, rules, baselines and comparisons (see docs/ARCHITECTURE_RECOVERY.md)."""


@architecture_group.command(name="export")
@click.option("--config", "config_path", default="config.yaml", type=_CONFIG_FILE, help="Path to config.yaml")
def architecture_export(config_path):
    """Write the recovered architecture as PlantUML (architecture.puml) and Structurizr DSL (architecture.dsl)."""
    model, config = _run_pipeline(Path(config_path))
    _write_architecture_exports(model, config)


@architecture_group.command(name="save")
@click.option("--config", "config_path", default="config.yaml", type=_CONFIG_FILE, help="Path to config.yaml")
@click.option("--output", "output_path", default=None, type=click.Path(),
              help="Where to write the snapshot (default: architecture.baseline from the config, else architecture.snapshot.json).")
def architecture_save(config_path, output_path):
    """Save the recovered architecture as a snapshot to compare later runs with (architecture diff, architecture.baseline)."""
    from fwlens.arch import drift
    from fwlens.identity import project_root
    model, config = _run_pipeline(Path(config_path))
    if model.architecture is None:
        console.print("[yellow][fwlens] Architecture model is off (architecture.enabled: false) -- nothing to save.[/yellow]")
        return
    target = Path(output_path) if output_path else (config.architecture.baseline or Path("architecture.snapshot.json"))
    drift.save(model.architecture, project_root(config), target)
    console.print(f"[cyan][fwlens][/cyan] Architecture snapshot: [bold]{target}[/bold] "
                  f"({len(model.architecture.components)} component(s))")


@architecture_group.command(name="diff")
@click.option("--config", "config_path", default="config.yaml", type=_CONFIG_FILE, help="Path to config.yaml")
@click.option("--baseline", "baseline_path", default=None, type=click.Path(exists=True, dir_okay=False),
              help="A snapshot from `architecture save` (default: architecture.baseline from the config).")
@click.option("--revision", default=None, help="Compare with the code at this git revision (analysed in a temporary worktree).")
@click.option("--output", "output_path", default=None, type=click.Path(),
              help="Also write the differences as JSON.")
@click.option("--fail-on-new", is_flag=True, help="Exit 1 when there are new cycles, violations or leaks.")
def architecture_diff(config_path, baseline_path, revision, output_path, fail_on_new):
    """Compare the recovered architecture with a saved snapshot or an earlier revision: components, dependencies,
    cycles, violations, leaks, levels, coupling and patterns that changed."""
    from fwlens.arch import drift
    from fwlens.identity import project_root
    model, config = _run_pipeline(Path(config_path))
    if model.architecture is None:
        console.print("[yellow][fwlens] Architecture model is off (architecture.enabled: false) -- nothing to compare.[/yellow]")
        return
    root = project_root(config)
    try:
        if revision:
            old = drift.snapshot_at_ref(Path(config_path), revision, root)
            label = f"revision {revision}"
        else:
            source = Path(baseline_path) if baseline_path else config.architecture.baseline
            if source is None:
                raise ValueError("give --baseline or --revision, or set architecture.baseline in the config")
            old, label = drift.load(source), str(source)
        report = drift.diff(old, drift.snapshot(model.architecture, root))
    except (ValueError, RuntimeError) as exc:
        console.print(f"[red][fwlens] {exc}[/red]")
        sys.exit(1)
    console.print(f"[cyan][fwlens][/cyan] Architecture compared with {label}")
    for line in drift.lines(report):
        console.print(line, markup=False)
    if output_path:
        Path(output_path).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if fail_on_new and report["worse"]:
        sys.exit(1)


@architecture_group.command(name="variants")
@click.option("--config", "config_paths", multiple=True, default=("config.yaml",), type=_CONFIG_FILE,
              help="Path to config.yaml. Give it twice to compare two projects (for example two compile_commands.json).")
@click.option("--configuration", "configurations", multiple=True,
              help="A build configuration or target in the project file (project.configuration). Give it twice, "
                   "or once per --config, to name the two variants.")
@click.option("--output", "output_path", default=None, type=click.Path(),
              help="Where to write the differences as JSON (default: <exports_dir>/architecture_variants.json).")
def architecture_variants(config_paths, configurations, output_path):
    """Compare the architecture of two variants of one code base (two build configurations, or two configs):
    what only one of them has, and how components, dependencies, domains and patterns differ."""
    from fwlens.arch import drift
    from fwlens.identity import project_root
    paths, names = list(config_paths), list(configurations)
    if len(paths) == 2 and len(names) in (0, 1, 2):
        pairs = [(paths[0], names[0] if names else None), (paths[1], names[1] if len(names) > 1 else None)]
    elif len(paths) == 1 and len(names) == 2:
        pairs = [(paths[0], names[0]), (paths[0], names[1])]
    else:
        console.print("[red][fwlens] Give two --config files, or one --config with two --configuration names.[/red]")
        sys.exit(1)
    snaps, labels, exports = [], [], None
    for path, configuration in pairs:
        model, config = _run_pipeline(Path(path), configuration=configuration)
        if model.architecture is None:
            console.print("[yellow][fwlens] Architecture model is off (architecture.enabled: false) -- nothing to compare.[/yellow]")
            return
        snaps.append(drift.snapshot(model.architecture, project_root(config)))
        labels.append(configuration or Path(path).stem)
        exports = exports or config.output.exports_dir
    if labels[0] == labels[1]:       # same file name: tell the two apart by folder, then by order
        labels = [Path(p).resolve().parent.name or l for (p, _c), l in zip(pairs, labels)]
    if labels[0] == labels[1]:
        labels = [f"{labels[0]} (1)", f"{labels[1]} (2)"]
    report = drift.diff(snaps[0], snaps[1])
    console.print(f"[cyan][fwlens][/cyan] Architecture of {labels[0]} compared with {labels[1]}")
    for line in drift.variant_lines(report, labels[0], labels[1]):
        console.print(line, markup=False)
    target = Path(output_path) if output_path else exports / "architecture_variants.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps({"a": labels[0], "b": labels[1], "differences": report}, indent=2) + "\n", encoding="utf-8")
    console.print(f"[cyan][fwlens][/cyan] Variant differences: [bold]{target}[/bold]")


@architecture_group.command(name="adopt")
@click.option("--config", "config_path", default="config.yaml", type=_CONFIG_FILE, help="Path to config.yaml")
@click.option("--output", "output_path", default="architecture.adopted.yaml", type=click.Path(),
              help="Where to write the YAML to merge into config.yaml (default: architecture.adopted.yaml).")
def architecture_adopt(config_path, output_path):
    """Write the recovered architecture (components, domains, inferred layers) as a starting point for
    architecture.intended_layers and architecture.rules."""
    from fwlens.arch.adopt import adopted
    from fwlens.identity import project_root
    model, config = _run_pipeline(Path(config_path))
    if model.architecture is None:
        console.print("[yellow][fwlens] Architecture model is off (architecture.enabled: false) -- nothing to adopt.[/yellow]")
        return
    target = Path(output_path)
    target.write_text(adopted(model.architecture, project_root(config)), encoding="utf-8")
    console.print(f"[cyan][fwlens][/cyan] Adopted architecture: [bold]{target}[/bold] "
                  f"({len(model.architecture.components)} component(s)); merge it into config.yaml")


@cli.command(name="cbom")
@click.option("--config", "config_path", default="config.yaml", type=_CONFIG_FILE, help="Path to config.yaml")
@click.option("--output", "output_path", default=None, type=click.Path(),
              help="Where to write the CycloneDX JSON (default: <exports_dir>/cbom.cdx.json).")
def cbom_cmd(config_path, output_path):
    """Write a Cryptography Bill of Materials (CycloneDX 1.6 JSON): the algorithms, protocols and
    libraries the source names. Detected usage only; not a complete inventory."""
    from fwlens.cbom import write_cbom
    from fwlens.config import load_config
    config = load_config(Path(config_path))
    target = Path(output_path) if output_path else config.output.exports_dir / "cbom.cdx.json"
    written = write_cbom(config, target)
    doc = json.loads(written.read_text(encoding="utf-8"))
    assets = [c for c in doc["components"] if c["type"] == "cryptographic-asset"]
    weak = sum(1 for c in assets if any(p["name"] == "fwlens:weak" for p in c["properties"]))
    console.print(f"[cyan][fwlens][/cyan] CBOM: [bold]{written}[/bold] ({len(assets)} asset(s), {weak} flagged weak; "
                  f"detected usage only)")


def _compare_options(f):
    # Defaults come from the pr_check section of config.yaml; an option given here overrides it.
    opts = [
        click.option("--config", "config_path", default="config.yaml", type=_CONFIG_FILE,
                     help="Path to config.yaml"),
        click.option("--base", "base_path", default=None, type=click.Path(),
                     help="Reference results: a findings file (from --findings-json) or a baseline.json "
                          "from the target branch. Default: pr_check.base."),
        click.option("--base-ref", "base_ref", default=None,
                     help="Git ref of the target branch. Analyses its merge-base in a temporary worktree "
                          "(slower fallback when no --base artifact exists). Default: pr_check.base_ref."),
        click.option("--current", "current_path", default=None, type=click.Path(exists=True),
                     help="Findings file for the current checkout. Without it the analysis is run now."),
        click.option("--markdown", "markdown_path", default=None, type=click.Path(),
                     help="Also write the Markdown comment to this file."),
        click.option("--max-items", default=None, type=int, help="Rows listed per table (default 20)."),
        click.option("--uncertain-gates/--no-uncertain-gates", default=None,
                     help="Also fail on loosely matched findings, not only on worse ones."),
        click.option("--fail-on-new/--no-fail-on-new", default=None,
                     help="Exit 1 when there are new or worsened findings or a footprint limit is exceeded."),
        click.option("--max-flash-growth", "max_flash_growth", type=int, default=None, metavar="BYTES",
                     help="Fail when flash grows by more than BYTES versus the reference "
                          "(needs project.map_file; default pr_check.max_flash_growth_bytes)."),
        click.option("--max-ram-growth", "max_ram_growth", type=int, default=None, metavar="BYTES",
                     help="Fail when RAM grows by more than BYTES versus the reference."),
        click.option("--report-url", default=None, help="Link to the full HTML report artefact."),
        click.option("--base-label", default=None, help="Name used for the reference in the text."),
    ]
    for o in reversed(opts):
        f = o(f)
    return f


def _pr_settings(config_path, **cli):
    """The pr_check config section with any option given on the command line applied on top."""
    from fwlens.config import PRCheckConfig, load_config
    try:
        pc = load_config(Path(config_path)).pr_check
    except FileNotFoundError:
        pc = PRCheckConfig()
    pick = lambda name, conf: conf if cli.get(name) is None else cli[name]   # noqa: E731
    return PRCheckConfig(
        base=pick("base_path", pc.base), base_ref=pick("base_ref", pc.base_ref),
        uncertain_gates=pick("uncertain_gates", pc.uncertain_gates),
        fail_on_new=pick("fail_on_new", pc.fail_on_new), max_items=pick("max_items", pc.max_items),
        base_label=pick("base_label", pc.base_label), report_url=pick("report_url", pc.report_url),
        max_flash_growth_bytes=pick("max_flash_growth", pc.max_flash_growth_bytes),
        max_ram_growth_bytes=pick("max_ram_growth", pc.max_ram_growth_bytes),
        status=pick("status", pc.status),
    )


def _build_comparison(config_path, current_path, settings):
    from fwlens.baseline import compute_breaches
    from fwlens.identity import project_root
    from fwlens.pr_check import (
        breaches_from_entries,
        compare,
        findings_at_ref,
        load_footprint,
        load_reference,
        no_reference,
    )

    current_footprint = None
    if current_path:
        current = breaches_from_entries(load_reference(Path(current_path)))
        current_footprint = load_footprint(Path(current_path))
    else:
        model, config = _run_pipeline(Path(config_path))
        current = compute_breaches(model, config)
        current_footprint = getattr(model, "footprint", None)

    reference, base_footprint = None, None
    base_path = settings.base
    if base_path and Path(base_path).exists():
        reference = load_reference(Path(base_path))
        base_footprint = load_footprint(Path(base_path))
    elif base_path:
        console.print(f"[yellow][fwlens] Reference results not found: {base_path}[/yellow]")
    if reference is None and settings.base_ref:
        from fwlens.config import load_config
        root = project_root(load_config(Path(config_path)))
        reference = findings_at_ref(Path(config_path), settings.base_ref, root)
    if reference is None:
        console.print("[yellow][fwlens] No reference results available -- reporting without comparison.[/yellow]")
        comparison = no_reference(current)
    else:
        from fwlens.config import MatchConfig, load_config
        try:
            cfg = load_config(Path(config_path))
            match, renames = cfg.match, None
            if settings.base_ref:
                from fwlens.pr_check import git_rename_hints
                renames = git_rename_hints(project_root(cfg), settings.base_ref)
        except FileNotFoundError:
            match, renames = MatchConfig(), None
        comparison = compare(current, reference, uncertain_gates=settings.uncertain_gates,
                             match=match, renames=renames)
    comparison.current_footprint = current_footprint
    comparison.base_footprint = base_footprint
    comparison.max_flash_growth = settings.max_flash_growth_bytes
    comparison.max_ram_growth = settings.max_ram_growth_bytes
    if (settings.max_flash_growth_bytes is not None or settings.max_ram_growth_bytes is not None) \
            and comparison.growth("flash_bytes") is None:
        console.print("[yellow][fwlens] Footprint limits set but no footprint is recorded for both sides "
                      "(needs project.map_file and a reference written with --findings-json) "
                      "-- not checked.[/yellow]")
    return comparison


def _render_and_write(comparison, markdown_path, settings):
    from fwlens.pr_check import render_markdown
    md = render_markdown(comparison, max_items=settings.max_items, report_url=settings.report_url,
                         base_label=settings.base_label)
    if markdown_path:
        Path(markdown_path).parent.mkdir(parents=True, exist_ok=True)
        Path(markdown_path).write_text(md, encoding="utf-8")
        console.print(f"[cyan][fwlens][/cyan] Markdown written: [bold]{markdown_path}[/bold]")
    return md


def _status_text(comparison) -> str:
    if comparison.reference_missing:
        return f"{comparison.current_total} findings, no reference to compare"
    text = f"{len(comparison.new)} new, {len(comparison.worsened)} worse, {len(comparison.resolved)} resolved"
    return text + "; " + "; ".join(comparison.footprint_failures) if comparison.footprint_failures else text


@cli.command(name="compare")
@_compare_options
def compare_cmd(config_path, base_path, base_ref, current_path, markdown_path, max_items,
                uncertain_gates, fail_on_new, max_flash_growth, max_ram_growth, report_url, base_label):
    """Compare current findings with a reference (target branch) and print the Markdown summary."""
    settings = _pr_settings(
        config_path, base_path=base_path, base_ref=base_ref, max_items=max_items,
        uncertain_gates=uncertain_gates, fail_on_new=fail_on_new, max_flash_growth=max_flash_growth,
        max_ram_growth=max_ram_growth, report_url=report_url, base_label=base_label)
    comparison = _build_comparison(config_path, current_path, settings)
    print(_render_and_write(comparison, markdown_path, settings))
    if settings.fail_on_new and not comparison.passed:
        sys.exit(1)


@cli.command(name="pr-comment")
@_compare_options
@click.option("--post", "post_to", type=click.Choice(["auto", "github", "gitlab", "none"]), default="auto",
              show_default=True, help="Where to post the comment. auto picks from the CI environment.")
@click.option("--dry-run", is_flag=True, default=False, help="Print the Markdown, post nothing.")
@click.option("--pr", "pr_number", type=int, default=None, help="PR / MR number (default from the CI environment).")
@click.option("--no-update", is_flag=True, default=False, help="Always create a new comment instead of updating.")
@click.option("--status/--no-status", "status", default=None,
              help="Also set a commit status named 'fwlens' (default pr_check.status).")
def pr_comment(config_path, base_path, base_ref, current_path, markdown_path, max_items, uncertain_gates,
               fail_on_new, max_flash_growth, max_ram_growth, report_url, base_label, post_to, dry_run,
               pr_number, no_update, status):
    """Post (or update) one quality-check comment on the current PR / MR."""
    from fwlens.pr_check import (
        PostError,
        detect_platform,
        post_github,
        post_gitlab,
        post_status,
        write_github_step_summary,
    )
    settings = _pr_settings(
        config_path, base_path=base_path, base_ref=base_ref, max_items=max_items,
        uncertain_gates=uncertain_gates, fail_on_new=fail_on_new, max_flash_growth=max_flash_growth,
        max_ram_growth=max_ram_growth, report_url=report_url, base_label=base_label, status=status)
    comparison = _build_comparison(config_path, current_path, settings)
    md = _render_and_write(comparison, markdown_path, settings)

    platform = detect_platform() if post_to == "auto" else (None if post_to == "none" else post_to)
    if dry_run or platform is None:
        print(md)
    else:
        try:
            poster = post_github if platform == "github" else post_gitlab
            action = poster(md, update_existing=not no_update, **({"pr": pr_number} if platform == "github"
                                                                  else {"mr": pr_number}))
            console.print(f"[cyan][fwlens][/cyan] {platform} comment {action}.")
        except PostError as e:
            # Typically a read-only token on a fork PR: keep the result visible instead of failing.
            console.print(f"[yellow][fwlens] Could not post the comment: {e}[/yellow]")
            if platform == "github" and write_github_step_summary(md):
                console.print("[cyan][fwlens][/cyan] Wrote the summary to the job summary instead.")
            else:
                print(md)

    if settings.status and not dry_run:
        try:
            where = post_status(comparison.passed, _status_text(comparison))
            console.print(f"[cyan][fwlens][/cyan] {where} commit status set.")
        except PostError as e:
            console.print(f"[yellow][fwlens] Could not set the commit status: {e}[/yellow]")

    if settings.fail_on_new and not comparison.passed:
        sys.exit(1)


@cli.group(name="standards")
def standards_group():
    """Optional coding-standard compliance (MISRA C, CERT C ...) described in YAML."""


@standards_group.command(name="list")
@click.option("--config", "config_path", default=None, type=click.Path(exists=True),
              help="Config to read standards.extra_rule_dirs and standards.enabled from.")
@click.option("--rule-dir", "rule_dirs", multiple=True, type=click.Path(), help="Extra directory of rule files.")
def standards_list(config_path, rule_dirs):
    """List known rules, how each is checked, and which are enabled."""
    from rich.table import Table

    from fwlens.standards import RuleFileError, load_standards, select_rules
    extra = [Path(d) for d in rule_dirs]
    selected = set()
    if config_path:
        from fwlens.config import load_config
        cfg = load_config(Path(config_path))
        extra += cfg.standards.extra_rule_dirs
    try:
        standards = load_standards(extra)
        if config_path:
            selected = {r.key for r in select_rules(standards, cfg.standards.enabled)}
    except RuleFileError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)
    for std in standards.values():
        t = Table(title=f"{std.name} ({std.revision})", show_lines=False)
        for col in ("Id", "Category", "Title", "Check", "Enabled"):
            t.add_column(col)
        for rule in std.rules.values():
            how = rule.check_type + (f" ({rule.engine})" if rule.engine else "")
            t.add_row(rule.id, rule.category, rule.title, how, "yes" if rule.key in selected else "")
        console.print(t)


@standards_group.command(name="validate")
@click.argument("paths", nargs=-1, type=click.Path(exists=True))
def standards_validate(paths):
    """Validate rule files and deviation files (default: the built-in rule files)."""
    import yaml as _yaml

    from fwlens.standards import RuleFileError, load_standards
    from fwlens.standards.deviations import load_deviations
    from fwlens.standards.rules import BUILTIN_DIR, load_standard_file

    files: list[Path] = []
    for p in (paths or [str(BUILTIN_DIR)]):
        pp = Path(p)
        files += sorted(pp.glob("*.yaml")) if pp.is_dir() else [pp]
    failed = 0
    known = load_standards([])
    rule_files, dev_files = [], []
    for f in files:
        try:
            top = _yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        except _yaml.YAMLError as e:
            console.print(f"[red]{f}: invalid YAML: {e}[/red]")
            failed += 1
            continue
        (dev_files if isinstance(top, dict) and "deviations" in top else rule_files).append(f)
    for f in rule_files:
        try:
            std = load_standard_file(f)
            known[std.id] = std
            console.print(f"[green]OK[/green] {f} ({len(std.rules)} rules)")
        except RuleFileError as e:
            console.print(f"[red]{e}[/red]")
            failed += 1
    for f in dev_files:
        try:
            console.print(f"[green]OK[/green] {f} ({len(load_deviations(f, known))} deviations)")
        except RuleFileError as e:
            console.print(f"[red]{e}[/red]")
            failed += 1
    if failed:
        sys.exit(1)


@standards_group.command(name="report")
@click.option("--config", "config_path", default="config.yaml", type=_CONFIG_FILE)
@click.option("--format", "fmt", type=click.Choice(["markdown", "json"]), default="markdown", show_default=True)
@click.option("--output", "output_path", default=None, type=click.Path(), help="Write to a file instead of stdout.")
@click.option("--fail-on-violation", is_flag=True, default=False,
              help="Exit 1 if any active finding or deviation problem exists.")
def standards_report(config_path, fmt, output_path, fail_on_violation):
    """Run the analysis and print the compliance matrix for the enabled standards."""
    from fwlens.standards import RuleFileError, run_standards
    from fwlens.standards.matrix import render_json, render_markdown
    model, config = _run_pipeline(Path(config_path))
    if not config.standards.enabled:
        console.print("[yellow][fwlens] No standards enabled. Add standards.enabled to the config.[/yellow]")
        sys.exit(1)
    try:
        result = run_standards(model, config)
    except RuleFileError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)
    text = render_json(result) if fmt == "json" else render_markdown(result)
    if output_path:
        Path(output_path).write_text(text, encoding="utf-8")
        console.print(f"[cyan][fwlens][/cyan] Compliance matrix written: [bold]{output_path}[/bold]")
    else:
        print(text)
    if fail_on_violation and result.findings:
        sys.exit(1)


@cli.command(name="diff-breach")
@click.option("--config", "config_path", default="config.yaml",
              type=_CONFIG_FILE, help="Path to config.yaml (used for thresholds only)")
@click.option("--from-json", "from_json_path", required=True, type=click.Path(exists=True),
              help="fwlens_results.json from the baseline commit (e.g. checked out at hash A)")
@click.option("--to-json", "to_json_path", required=True, type=click.Path(exists=True),
              help="fwlens_results.json from the comparison commit (e.g. checked out at hash B)")
@click.option("--fail-on-breach", is_flag=True, default=False,
              help="Exit 1 if any breach is new or worse in --to-json vs --from-json.")
def diff_breach(config_path: str, from_json_path: str, to_json_path: str, fail_on_breach: bool):
    """
    Compare threshold breaches between two fwlens_results.json exports, e.g. from two
    git hashes. No .ewp/source access needed -- both files come from a prior
    `export` or `report` run (in EWP or directory mode, at whichever commits you checked
    out). Only reports breaches that are new or worsened going --from-json -> --to-json.

    \b
    Typical usage:
      git checkout main            &&  fwlens export --config config.yaml
      cp output/exports/fwlens_results.json main.json
      git checkout feature-branch  &&  fwlens export --config config.yaml
      fwlens diff-breach --from-json main.json --to-json output/exports/fwlens_results.json --fail-on-breach
    """
    from fwlens.baseline import compute_breaches_from_json, diff_against_baseline
    from fwlens.config import load_config
    from fwlens.output.console import print_baseline_summary

    config = load_config(Path(config_path))
    from_breaches = compute_breaches_from_json(Path(from_json_path), config)
    to_breaches = compute_breaches_from_json(Path(to_json_path), config)
    from_as_baseline = {b.id: b.to_dict() for b in from_breaches}

    console.print(f"[cyan][fwlens][/cyan] Comparing breaches: "
                  f"[bold]{from_json_path}[/bold] -> [bold]{to_json_path}[/bold]")
    new_or_worsened, accepted_unchanged = diff_against_baseline(to_breaches, from_as_baseline, match=config.match)
    print_baseline_summary(new_or_worsened, accepted_unchanged, f"{from_json_path} -> {to_json_path}")

    if fail_on_breach and new_or_worsened:
        sys.exit(1)


@cli.command(name="call-graph")
@click.option("--config", "config_path", default="config.yaml",
              type=_CONFIG_FILE, help="Path to config.yaml")
@click.option("--function", "function_name", required=True,
              help="Function name to scope the diagram to")
@click.option("--direction", type=click.Choice(["callers", "callees", "both"]), default="both",
              help="callers = blast radius (what breaks if this changes), "
                   "callees = dispatch chain (what this reaches), both = default")
@click.option("--depth", default=4, help="Max hops from the root function")
def call_graph(config_path: str, function_name: str, direction: str, depth: int):
    """Generate an on-demand Mermaid call-graph diagram scoped to one function."""
    from fwlens.output.diagrams import generate_call_graph_diagram

    model, config = _run_pipeline(Path(config_path))

    try:
        diagram_md = generate_call_graph_diagram(model, function_name, direction, depth)
    except ValueError as e:
        console.print(f"[red][fwlens] {e}[/red]")
        sys.exit(1)

    out_dir = config.output.reports_dir / "diagrams"
    out_dir.mkdir(parents=True, exist_ok=True)
    safe_name = "".join(c if c.isalnum() else "_" for c in function_name)
    out_path = out_dir / f"call_graph_{safe_name}_{direction}.md"
    out_path.write_text(
        f"# Call Graph: {function_name}  ({direction}, depth {depth})\n\n{diagram_md}\n",
        encoding="utf-8",
    )
    console.print(f"[cyan][fwlens][/cyan] Call graph diagram: [bold]{out_path}[/bold]")


@cli.command()
@click.option("--config", "config_path", default="config.yaml",
              type=_CONFIG_FILE, help="Path to config.yaml")
@click.option("--n", default=20, help="Number of sample paths to show per class")
def debug(config_path: str, n: int):
    """Show EWP parse results and boundary classification without running analysis."""
    from collections import Counter

    from rich import box
    from rich.table import Table

    from fwlens.config import load_config
    from fwlens.parser.ewp import parse_ewp

    config = load_config(Path(config_path))
    if config.project.mode == "directory":
        console.print("[red]`debug` inspects .ewp parsing and IAR boundary classification -- "
                      "not available in directory mode (no .ewp file). "
                      "Run `analyze` instead.[/red]")
        return
    console.print(f"\n[cyan]proj_dir :[/cyan] {config.project.proj_dir}")
    console.print(f"[cyan]toolkit  :[/cyan] {config.project.toolkit_dir}")
    console.print(f"[cyan]scope    :[/cyan] first_party={config.scope.first_party}")
    console.print(f"[cyan]analyse  :[/cyan] {config.scope.analyse}\n")

    ewp = parse_ewp(config)
    console.print(f"Total .c files in EWP: [bold]{len(ewp.source_files)}[/bold]")

    bc_counts = Counter(tu.boundary_class.value for tu in ewp.source_files)
    console.print("\n[bold]Boundary classification breakdown:[/bold]")
    for bc, count in sorted(bc_counts.items()):
        colour = "green" if bc == "first_party" else "dim"
        console.print(f"  [{colour}]{bc:20s}[/{colour}] {count}")

    # All top-level segments vs configured fragments -- mirrors the same two-step
    # resolution _classify_boundary() actually uses (relative_to(proj_dir), then
    # walking proj_dir's ancestors for the common IAR layout where proj_dir is an
    # EWARM subfolder and sources sit one level up via $PROJ_DIR$\..\Src\...).
    # Using only the first step here would flag every file as "not under proj_dir"
    # in that (very normal) layout even though real classification handles it fine.
    from pathlib import PureWindowsPath
    all_tops: Counter = Counter()
    not_under_proj = []
    for tu in ewp.source_files:
        top = None
        try:
            rel = tu.path.relative_to(config.project.proj_dir)
            top = rel.parts[0] if rel.parts else None
        except ValueError:
            wp = PureWindowsPath(tu.path)
            candidate = PureWindowsPath(config.project.proj_dir).parent
            for _ in range(8):
                try:
                    rel = wp.relative_to(candidate)
                    top = rel.parts[0] if rel.parts else None
                    break
                except ValueError:
                    if candidate.parent == candidate:
                        break
                    candidate = candidate.parent
        if top is not None:
            all_tops[top] += 1
        else:
            not_under_proj.append(str(tu.path)[:100])

    console.print("\n[bold]Top-level path segments (resolved same way as real classification):[/bold]")
    for seg, count in sorted(all_tops.items(), key=lambda x: -x[1]):
        match_fp  = seg.lower() in [f.lower() for f in config.scope.first_party]
        match_sdk = seg.lower() in [f.lower() for f in config.scope.sdk]
        match_lib = seg.lower() in [f.lower() for f in config.scope.third_party_lib]
        if match_fp:
            label = " [green]<-- first_party[/green]"
        elif match_sdk:
            label = " [blue]<-- sdk[/blue]"
        elif match_lib:
            label = " [yellow]<-- lib[/yellow]"
        else:
            label = " [red]<-- NO MATCH[/red]"
        console.print(f"  {seg:40s} {count:4d}{label}")

    if not_under_proj:
        console.print(f"\n[bold]Files that couldn't be resolved to any segment under or near "
                      f"proj_dir ({len(not_under_proj)}):[/bold]")
        console.print("  [dim]These would also fail real classification -- worth investigating.[/dim]")
        for p in not_under_proj[:n]:
            console.print(f"  [dim]{p}[/dim]")

    # Sample resolved paths
    console.print(f"\n[bold]Sample paths (up to {n} per boundary class):[/bold]")
    t = Table(box=box.SIMPLE)
    t.add_column("Boundary", style="cyan")
    t.add_column("Resolved path", style="dim")
    seen: Counter = Counter()
    for tu in ewp.source_files:
        bc = tu.boundary_class.value
        if seen[bc] >= n:
            continue
        seen[bc] += 1
        t.add_row(bc, str(tu.path))
    console.print(t)

@cli.command(name="debug-parse")
@click.option("--config", "config_path", default="config.yaml",
              type=_CONFIG_FILE, help="Path to config.yaml")
@click.option("--file", "target_file", default=None,
              help="Specific .c file to test (default: first in-scope file)")
def debug_parse(config_path: str, target_file: str):
    """Test libclang on a single file and show exactly what happens."""
    import traceback

    import fwlens.parser.ast_walker as _walker_mod
    import fwlens.parser.ewp as _ewp_mod
    from fwlens.config import load_config
    from fwlens.parser.ewp import parse_ewp

    _print_header("debug-parse", config_path)

    # Show which module files are actually loaded (confirms no stale .pyc)
    console.print("\n[bold]0. Module paths (confirms no stale .pyc)[/bold]")
    console.print(f"  ewp.py      : [dim]{_ewp_mod.__file__}[/dim]")
    console.print(f"  ast_walker  : [dim]{_walker_mod.__file__}[/dim]")

    config = load_config(Path(config_path))
    if config.project.mode == "directory":
        console.print("[red]`debug-parse` resolves single files via .ewp/$TOOLKIT_DIR$ lookups -- "
                      "not available in directory mode (no .ewp file).[/red]")
        return

    # --- libclang check ---
    console.print("\n[bold]1. libclang[/bold]")
    lp = config.tool.libclang_path
    if not lp:
        console.print("  [red]tool.libclang_path not set in config.yaml[/red]")
        return
    if not lp.exists():
        console.print(f"  [red]DLL not found: {lp}[/red]")
        return
    console.print(f"  [green]DLL exists:[/green] {lp}")

    try:
        import clang.cindex as ci
        ci.Config.set_library_file(str(lp))
        idx = ci.Index.create()
        console.print("  [green]libclang loaded and Index created OK[/green]")
    except Exception as e:
        console.print(f"  [red]Failed to load libclang: {e}[/red]")
        return

    # --- Pick a test file ---
    console.print("\n[bold]2. Test file[/bold]")
    ewp = parse_ewp(config)
    scope_values = set(config.scope.analyse)
    in_scope = [tu for tu in ewp.source_files if tu.boundary_class.value in scope_values]

    if not in_scope:
        console.print("  [red]No in-scope files found. Check config.[/red]")
        return

    if target_file:
        candidates = [tu for tu in in_scope if Path(target_file).name.lower() in tu.path.name.lower()]
        tu = candidates[0] if candidates else in_scope[0]
    else:
        # Pick main.c or a small Src file -- avoid header-only / tiny files
        preferred = [t for t in in_scope if t.path.name.lower() == 'main.c' and t.path.exists()]
        if preferred:
            tu = preferred[0]
        else:
            tu = sorted(
                [t for t in in_scope if t.path.exists()],
                key=lambda t: t.path.stat().st_size
            )[-min(5, len(in_scope))]  # pick a mid-sized file

    console.print(f"  File   : {tu.path}")
    console.print(f"  Exists : {tu.path.exists()}")
    console.print(f"  Size   : {tu.path.stat().st_size if tu.path.exists() else 'N/A'} bytes")
    console.print(f"\n  EWP defines ({len(tu.defines)}):")
    for d in tu.defines:
        console.print(f"    {d}")
    console.print(f"\n  IAR compat defines ({len(config.iar_compat_defines)}):")
    for d in config.iar_compat_defines:
        if d.startswith("-U"):
            console.print(f"    [yellow]-U{d[2:]}[/yellow]  (undefine)")
        else:
            console.print(f"    -D{d}")
    console.print(f"\n  Includes ({len(tu.include_paths)}): "
                  f"{[str(p) for p in tu.include_paths[:3]]}{'...' if len(tu.include_paths) > 3 else ''}")

    valid_includes = [p for p in tu.include_paths if p.exists()]
    missing_includes = [p for p in tu.include_paths if not p.exists()]
    console.print(f"  Include paths exist: {len(valid_includes)}/{len(tu.include_paths)}")
    if missing_includes:
        console.print(f"  [yellow]  Missing ({len(missing_includes)}): "
                      f"{[str(p) for p in missing_includes[:5]]}[/yellow]")

    if not tu.path.exists():
        console.print("  [red]Source file does not exist at resolved path. "
                      "Check proj_dir in config.yaml.[/red]")
        return

    # --- Attempt parse ---
    console.print("\n[bold]3. Parse attempt[/bold]")
    clang_args = ["-x", "c", "--target=arm-none-eabi", "-fno-builtin"]
    for d in config.iar_compat_defines:
        if d.startswith("-U"):
            clang_args.append(d)
        else:
            clang_args.append(f"-D{d}")
    for d in tu.defines:
        clang_args.append(f"-D{d}")

    stubs_dir = Path.cwd() / "iar_stubs"
    stubs_dir.mkdir(exist_ok=True)
    clang_args.append(f"-I{stubs_dir}")
    console.print(f"  [green]iar_stubs dir:[/green] {stubs_dir}")

    # Inject LLVM bundled system headers so standard headers like string.h are found.
    # libclang when loaded as a DLL doesn't always auto-locate its own include dir.
    if config.tool.libclang_path:
        llvm_bin = config.tool.libclang_path.parent          # ..\LLVM\bin
        llvm_root = llvm_bin.parent                          # ..\LLVM
        # Search for clang's bundled include dir: LLVM\lib\clang\<version>\include
        clang_lib = llvm_root / "lib" / "clang"
        system_inc = None
        if clang_lib.exists():
            versions = sorted(clang_lib.iterdir(), reverse=True)
            for v in versions:
                candidate = v / "include"
                if candidate.exists():
                    system_inc = candidate
                    break
        if system_inc:
            clang_args.append(f"-I{system_inc}")
            console.print(f"  [green]LLVM system headers:[/green] {system_inc}")
        else:
            console.print(f"  [yellow]LLVM system headers not found under {clang_lib} "
                          f"-- standard headers like string.h may be missing[/yellow]")

    for inc in valid_includes:
        clang_args.append(f"-I{inc}")

    console.print(f"  clang args ({len(clang_args)} total): {clang_args[:6]}...")

    # ---------------------------------------------------------------------------
    # Auto-fix loop: parse, detect stub-fixable errors, patch iar_stubs, repeat.
    # Handles two error classes:
    #   1. 'foo.h' file not found          -> create empty stub header
    #   2. call to undeclared function 'x' -> append prototype to a catch-all stub
    # ---------------------------------------------------------------------------
    import re as _re

    MAX_ROUNDS = 8
    for round_num in range(1, MAX_ROUNDS + 1):
        try:
            tu_parsed = idx.parse(
                str(tu.path),
                args=clang_args,
                options=ci.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD,
            )
        except Exception as e:
            console.print(f"  [red]Parse threw exception: {e}[/red]")
            console.print(traceback.format_exc())
            break

        diags     = list(tu_parsed.diagnostics)
        errors    = [d for d in diags if d.severity >= ci.Diagnostic.Error]
        warnings  = [d for d in diags if d.severity == ci.Diagnostic.Warning]

        # Categorise fixable errors
        missing_headers   = set()
        undeclared_funcs  = set()
        other_errors      = []

        # Headers we must never stub -- clang has its own copies that must win.
        # This list is intentionally narrow: only clang built-in headers that
        # live in LLVM\lib\clang\<ver>\include and would be shadowed by a stub.
        # Standard C library headers (string.h, stdlib.h etc.) are NOT in this
        # list because for bare-metal ARM there is no system libc -- clang has
        # no bundled string.h for arm-none-eabi, so we must provide our own stub.
        NEVER_STUB = {
            'stdint.h', 'stddef.h', 'stdbool.h', 'stdarg.h',
            'float.h', 'limits.h', 'iso646.h', 'stdalign.h',
            'stdnoreturn.h', 'stdatomic.h',
        }

        arch_added = False
        for d in errors:
            m_hdr = _re.search(r"'([^']+\.h)' file not found", d.spelling)
            m_fn  = _re.search(r"call to undeclared (?:library )?function '([^']+)'", d.spelling)
            m_err = _re.search(r'"Please check that (.+) is defined!"', d.spelling)
            if m_hdr and m_hdr.group(1) not in NEVER_STUB:
                missing_headers.add(m_hdr.group(1))
            elif m_fn:
                undeclared_funcs.add(m_fn.group(1))
            elif m_err:
                # #error asking for an arch define -- extract and add to compat defines
                # e.g. "__ARM6M__, __ARM7M__, __ARM7EM__..." -> pick the right one.
                # Two explicit passes, not "first candidate matching ARM7EM or ARM7M":
                # __ARM7M__ and __ARM7EM__ are both independently truthy substring
                # matches for their own check, and __ARM7M__ reliably appears earlier in
                # IAR's own candidate lists, so a single combined check silently prefers
                # the wrong one every time regardless of which appears in the message.
                needed = [s.strip() for s in m_err.group(1).split(',')]
                arch_define = (
                    next((s for s in needed if 'ARM7EM' in s), None)
                    or next((s for s in needed if 'ARM7M' in s), None)
                    or needed[0]
                ).strip('_').strip()
                full = f"__{arch_define.strip('_')}__" if not arch_define.startswith('__') else arch_define
                new_flag = f"-D{full}=1"
                if new_flag not in clang_args:
                    console.print(f"  [yellow]  #error: arch define needed -- adding {full}=1 to this parse[/yellow]")
                    clang_args.append(new_flag)
                    arch_added = True
                else:
                    # Already on the command line and the #error still fired -- redefining
                    # it won't help. This means the header checks more than definedness
                    # (e.g. a value comparison like `__CORE__ == __ARM7EM__`), which
                    # re-appending the same "=1" define can never satisfy. Surface it as
                    # unfixable instead of silently looping.
                    other_errors.append(d)
            else:
                other_errors.append(d)

        # Report non-auto-fixable errors with hints
        if other_errors and round_num == 1:
            for d in other_errors:
                m_type = _re.search(r"unknown type name '([^']+)'", d.spelling)
                if m_type:
                    console.print(
                        f"  [yellow]  Hint: unknown type '{m_type.group(1)}' -- "
                        f"likely needs a missing #define to activate its declaration. "
                        f"Check which EWP define guards it and add to iar_compat_defines.[/yellow]"
                    )

        fixable = len(missing_headers) + len(undeclared_funcs) + (1 if arch_added else 0)
        console.print(
            f"\n  [bold]Round {round_num}[/bold] -- "
            f"{len(errors)} error(s): "
            f"{len(missing_headers)} missing header(s), "
            f"{len(undeclared_funcs)} undeclared function(s), "
            f"{len(other_errors)} other"
        )

        if missing_headers:
            stubs_dir.mkdir(exist_ok=True)
            from fwlens.autostub import _write_header_stub
            for hdr in sorted(missing_headers):
                if (stubs_dir / hdr).exists():
                    console.print(f"  [yellow]  Stub exists but header still missing:[/yellow] {hdr}")
                else:
                    _write_header_stub(stubs_dir, hdr, console)

        if undeclared_funcs:
            stubs_dir.mkdir(exist_ok=True)
            from fwlens.autostub import _write_function_stubs
            _write_function_stubs(stubs_dir, set(undeclared_funcs), console)

        if fixable == 0:
            # Nothing left we can auto-fix -- done
            break

        # Re-run with updated stubs dir (already on clang_args from first pass)
        console.print("  [cyan]  Re-parsing with updated stubs...[/cyan]")

    # Final summary
    console.print("\n  [bold]Final parse result[/bold]")
    if other_errors:
        console.print(f"  [red]{len(other_errors)} unfixable error(s):[/red]")
        for d in other_errors[:10]:
            console.print(f"    [red]{d.location.file}:{d.location.line}: {d.spelling}[/red]")
    else:
        console.print("  [green]0 unfixable errors[/green]")

    if warnings:
        console.print(f"  [dim]{len(warnings)} warning(s) (ignored)[/dim]")

    # Count functions in final parse
    func_count = 0
    for cursor in tu_parsed.cursor.get_children():
        if (cursor.kind == ci.CursorKind.FUNCTION_DECL
                and cursor.is_definition()
                and cursor.location.file
                and Path(cursor.location.file.name) == tu.path):
            func_count += 1
            if func_count <= 5:
                console.print(f"  [green]  Function: {cursor.spelling}[/green]")

    console.print(f"\n  [bold]Functions defined in this file: {func_count}[/bold]")

    if func_count > 0 and not other_errors:
        console.print(
            "\n[green][bold]✓ Parse clean. Run:[/bold][/green]"
            "\n    .\\Run-FwLens.ps1 analyze"
        )
        # Check if we added any arch defines during the loop -- suggest making them permanent
        arch_adds = [a for a in clang_args if 'ARM7EM' in a or 'ARM6M' in a or 'ARM8M' in a]
        if arch_adds:
            console.print(
                "\n[yellow]Tip: add these to iar_compat_defines in config.yaml "
                "to avoid re-detecting each run:[/yellow]"
            )
            for a in arch_adds:
                console.print(f"  - {a.lstrip('-D')}")
    elif func_count > 0:
        console.print(
            "\n[yellow]Functions found but errors remain. "
            "analyze may still produce results -- try it.[/yellow]"
        )

@cli.command(name="dump-ast")
@click.option("--config", "config_path", default="config.yaml",
              type=_CONFIG_FILE, help="Path to config.yaml")
@click.option("--file", "target_file", default=None,
              help="Name (or partial path) of the .c file to parse")
@click.option("--var", "var_name", default=None,
              help="Dump the initialiser subtree of a named global variable")
@click.option("--fn", "fn_name", default=None,
              help="Dump all DECL_REF_EXPR nodes inside a named function")
@click.option("--find-refs", "find_refs", default=None,
              help="Search ALL in-scope files for references to a named global variable "
                   "(finds dispatchers without needing to know which file they are in)")
@click.option("--depth", default=6,
              help="Max AST depth to print (default 6)")
def dump_ast(config_path: str, target_file: str, var_name: str, fn_name: str,
             find_refs: str, depth: int):
    """Dump the libclang AST for a single file to validate analysis assumptions.

    Use --var NAME to see exactly what _collect_fn_refs sees in a dispatch table
    initialiser (validates function pointer detection).

    Use --fn NAME to see all variable/function references inside a function body
    (validates global_reads and dispatcher detection).

    Use --find-refs NAME to search ALL in-scope files for functions that reference
    a named global variable (finds dispatchers without knowing which file they are in).

    Examples:

    \\b
        .\\\\Run-FwLens.ps1 dump-ast --file ATCommands.c --var ATCommandTable
        .\\\\Run-FwLens.ps1 dump-ast --file ModemMgr.c --fn executeATCommand
        .\\\\Run-FwLens.ps1 dump-ast --find-refs ATCommandTable
        .\\\\Run-FwLens.ps1 dump-ast --file ATCommands.c --depth 4
    """
    import clang.cindex as ci

    from fwlens.config import load_config
    from fwlens.parser.ewp import parse_ewp

    _print_header("dump-ast", config_path)

    config = load_config(Path(config_path))
    lp = config.tool.libclang_path
    if not lp or not lp.exists():
        console.print(f"[red]libclang DLL not found: {lp}[/red]")
        return

    ci.Config.set_library_file(str(lp))
    idx = ci.Index.create()

    ewp = parse_ewp(config)
    scope_values = set(config.scope.analyse)
    all_files = ewp.source_files

    # ------------------------------------------------------------------
    # Build shared clang args (no file-specific parts yet)
    # ------------------------------------------------------------------
    def _build_clang_args(tu_info):
        args = ["-x", "c", "--target=arm-none-eabi"]
        for d in config.iar_compat_defines:
            args.append(d if d.startswith("-U") else f"-D{d}")
        for d in tu_info.defines:
            args.append(f"-D{d}")
        stubs_dir = Path.cwd() / "iar_stubs"
        if stubs_dir.exists():
            args.append(f"-I{stubs_dir}")
        if config.tool.libclang_path:
            llvm_root = config.tool.libclang_path.parent.parent
            clang_lib = llvm_root / "lib" / "clang"
            if clang_lib.exists():
                for v in sorted(clang_lib.iterdir(), reverse=True):
                    candidate = v / "include"
                    if candidate.exists():
                        args.append(f"-I{candidate}")
                        break
        for inc in tu_info.include_paths:
            if inc.exists():
                args.append(f"-I{inc}")
        return args

    def _linkage(cursor) -> str:
        try:
            lk = cursor.linkage
            return {
                ci.LinkageKind.NO_LINKAGE:       "no_link",
                ci.LinkageKind.INTERNAL:         "internal",
                ci.LinkageKind.EXTERNAL:         "external",
                ci.LinkageKind.UNIQUE_EXTERNAL:  "unique_ext",
            }.get(lk, str(lk))
        except Exception:
            return "?"

    # ------------------------------------------------------------------
    # Mode: --find-refs  -- scan all in-scope files for a var reference
    # ------------------------------------------------------------------
    if find_refs:
        console.print(f"\n[bold]Searching all in-scope files for references to '{find_refs}'[/bold]\n")
        in_scope = [tu for tu in all_files
                    if tu.boundary_class.value in scope_values and tu.path.exists()]
        console.print(f"  Scanning {len(in_scope)} file(s)...\n")

        hits = []  # list of (file, fn_name, line, linkage)
        for tu_info in in_scope:
            clang_args = _build_clang_args(tu_info)
            try:
                tu_parsed = idx.parse(
                    str(tu_info.path), args=clang_args,
                    options=ci.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD,
                )
            except Exception:
                continue

            tu_path = tu_info.path
            var_ck  = getattr(ci.CursorKind, 'VAR_DECL', None)
            fn_ck   = getattr(ci.CursorKind, 'FUNCTION_DECL', None)
            dr_ck   = getattr(ci.CursorKind, 'DECL_REF_EXPR', None)

            # Walk every function definition looking for DECL_REF to find_refs
            def _scan_fn(fn_cursor):
                found_lines = []
                def _walk(c):
                    try:
                        ck = c.kind
                    except ValueError:
                        return
                    if dr_ck and ck == dr_ck:
                        try:
                            ref = c.referenced
                            if ref and var_ck and ref.kind == var_ck and ref.spelling == find_refs:
                                found_lines.append((c.location.line, _linkage(ref)))
                        except Exception:
                            pass
                    for child in c.get_children():
                        try:
                            if child.location.file and Path(child.location.file.name) == tu_path:
                                _walk(child)
                        except Exception:
                            pass
                _walk(fn_cursor)
                return found_lines

            for cursor in tu_parsed.cursor.get_children():
                try:
                    if not cursor.location.file or Path(cursor.location.file.name) != tu_path:
                        continue
                    if fn_ck and cursor.kind == fn_ck and cursor.is_definition():
                        refs = _scan_fn(cursor)
                        for line, lk in refs:
                            hits.append((tu_info.path.name, cursor.spelling, line, lk))
                except Exception:
                    continue

        if hits:
            console.print(f"  [green]Found {len(hits)} reference(s):[/green]\n")
            console.print(f"  {'File':<30} {'Function':<40} {'Line':>6}  {'Linkage'}")
            console.print(f"  {'-'*30} {'-'*40} {'-'*6}  {'-'*10}")
            for file, fn, line, lk in sorted(hits):
                include = lk in ("internal", "external", "unique_ext")
                mark = "[green]✓[/green]" if include else "[red]✗[/red]"
                console.print(f"  {file:<30} {fn:<40} {line:>6}  {lk} {mark}")
        else:
            console.print(f"  [yellow]No references to '{find_refs}' found in any in-scope function.[/yellow]")
            console.print("  Checking VAR_DECL initialisers (registration chains)...\n")

            # Second pass: look for references in global variable initialisers
            var_hits = []
            for tu_info in in_scope:
                clang_args = _build_clang_args(tu_info)
                try:
                    tu_parsed = idx.parse(
                        str(tu_info.path), args=clang_args,
                        options=ci.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD,
                    )
                except Exception:
                    continue

                tu_path = tu_info.path
                var_ck = getattr(ci.CursorKind, 'VAR_DECL',      None)
                dr_ck  = getattr(ci.CursorKind, 'DECL_REF_EXPR', None)

                for cursor in tu_parsed.cursor.get_children():
                    try:
                        if not cursor.location.file or Path(cursor.location.file.name) != tu_path:
                            continue
                        if not (var_ck and cursor.kind == var_ck and cursor.is_definition()):
                            continue
                        container_name = cursor.spelling

                        def _scan_init(c):
                            try:
                                ck = c.kind
                            except ValueError:
                                return
                            if dr_ck and ck == dr_ck:
                                try:
                                    ref = c.referenced
                                    if ref and var_ck and ref.kind == var_ck and ref.spelling == find_refs:
                                        var_hits.append((tu_info.path.name, container_name,
                                                         c.location.line, _linkage(ref)))
                                except Exception:
                                    pass
                            for child in c.get_children():
                                _scan_init(child)

                        _scan_init(cursor)
                    except Exception:
                        continue

            if var_hits:
                console.print(f"  [green]Found in VAR_DECL initialisers ({len(var_hits)} reference(s)):[/green]\n")
                console.print(f"  {'File':<30} {'Container variable':<40} {'Line':>6}  {'Linkage'}")
                console.print(f"  {'-'*30} {'-'*40} {'-'*6}  {'-'*10}")
                for file, var, line, lk in sorted(var_hits):
                    console.print(f"  {file:<30} {var:<40} {line:>6}  {lk}")
                console.print()
                console.print("  These are registration chains -- the table is embedded in another")
                console.print("  global variable rather than referenced directly by a function.")
                console.print("  The dispatch happens when the container variable is traversed at runtime.")
            else:
                console.print("  [yellow]Not found in VAR_DECL initialisers either.[/yellow]")
                console.print("  This table is genuinely unreferenced in the analysed scope.")
                console.print("  Possible causes:")
                console.print("    - The dispatcher is in SDK/Lib scope (not analysed)")
                console.print("    - The table is accessed via a pointer cast without naming it")
                console.print("    - The reference is in a file not included in the EWP")
        return

    # ------------------------------------------------------------------
    # Single-file modes: --var, --fn, or full AST dump
    # ------------------------------------------------------------------
    if not target_file:
        console.print("[red]--file is required for --var, --fn, and full AST dump modes.[/red]")
        console.print("Use --find-refs NAME to search without specifying a file.")
        return

    candidates = [tu for tu in all_files
                  if Path(target_file).name.lower() in tu.path.name.lower()
                  and tu.path.exists()]
    if not candidates:
        console.print(f"[red]No file matching '{target_file}' found in EWP.[/red]")
        return
    tu_info = candidates[0]
    console.print(f"  File   : [cyan]{tu_info.path}[/cyan]")
    console.print(f"  Group  : {tu_info.iar_group}   Boundary: {tu_info.boundary_class.value}")

    clang_args = _build_clang_args(tu_info)

    tu_parsed = idx.parse(
        str(tu_info.path),
        args=clang_args,
        options=ci.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD,
    )

    errors = [d for d in tu_parsed.diagnostics if d.severity >= ci.Diagnostic.Error]
    if errors:
        console.print(f"  [yellow]{len(errors)} parse error(s) -- AST may be incomplete[/yellow]")
        for e in errors[:5]:
            console.print(f"    [dim]{e.spelling}[/dim]")

    tu_path = tu_info.path

    # -----------------------------------------------------------------------
    # -----------------------------------------------------------------------
    # Helper: recursive AST printer
    # -----------------------------------------------------------------------
    def _print_node(cursor, indent: int, max_depth: int):
        if indent > max_depth:
            return
        try:
            kind_name = cursor.kind.name
        except ValueError:
            kind_name = "UNKNOWN_KIND"

        spelling  = cursor.spelling or ""
        loc       = ""
        try:
            if cursor.location.file:
                loc = f"  [{cursor.location.file.name}:{cursor.location.line}]"
        except Exception:
            pass

        # For DECL_REF_EXPR show what it references
        ref_info = ""
        if "DECL_REF" in kind_name:
            try:
                ref = cursor.referenced
                if ref:
                    ref_info = (f"  -> {ref.kind.name}  '{ref.spelling}'"
                                f"  linkage={_linkage(ref)}")
            except Exception:
                pass

        prefix = "  " * indent
        style = ""
        if "CALL_EXPR" in kind_name:
            style = "[yellow]"
        elif "DECL_REF" in kind_name:
            style = "[cyan]"
        elif "VAR_DECL" in kind_name or "FUNCTION_DECL" in kind_name:
            style = "[green]"

        style.replace("[", "[/") if style else ""
        console.print(
            f"{prefix}{style}{kind_name}[/] "
            f"'{spelling}'{ref_info}[dim]{loc}[/dim]"
            if style else
            f"{prefix}{kind_name} '{spelling}'{ref_info}[dim]{loc}[/dim]"
        )

        for child in cursor.get_children():
            try:
                if child.location.file and Path(child.location.file.name) == tu_path:
                    _print_node(child, indent + 1, max_depth)
            except Exception:
                pass

    # -----------------------------------------------------------------------
    # Mode: --var  -- find a VAR_DECL and dump its initialiser
    # -----------------------------------------------------------------------
    if var_name:
        console.print(f"\n[bold]VAR_DECL subtree for '{var_name}'[/bold]  (depth {depth})\n")
        found = False
        for cursor in tu_parsed.cursor.get_children():
            try:
                if not cursor.location.file or Path(cursor.location.file.name) != tu_path:
                    continue
                var_ck = getattr(ci.CursorKind, 'VAR_DECL', None)
                if var_ck and cursor.kind == var_ck and cursor.spelling == var_name:
                    found = True
                    console.print(f"  [green]Found:[/green] {cursor.spelling}  "
                                  f"linkage={_linkage(cursor)}  "
                                  f"line={cursor.location.line}  "
                                  f"type='{cursor.type.spelling}'")
                    console.print()
                    _print_node(cursor, 0, depth)
                    console.print()
                    # Summary: which FUNCTION_DECLs appear in the subtree
                    fn_refs = []
                    def _gather(c):
                        try:
                            ck = c.kind
                        except ValueError:
                            pass
                        else:
                            dr = getattr(ci.CursorKind, 'DECL_REF_EXPR', None)
                            fd = getattr(ci.CursorKind, 'FUNCTION_DECL', None)
                            if dr and ck == dr and fd:
                                try:
                                    ref = c.referenced
                                    if ref and ref.kind == fd and ref.spelling:
                                        fn_refs.append(ref.spelling)
                                except Exception:
                                    pass
                        for child in c.get_children():
                            _gather(child)
                    _gather(cursor)
                    if fn_refs:
                        console.print(f"  [bold]Function references found ({len(fn_refs)}):[/bold]")
                        for fn in fn_refs:
                            console.print(f"    [cyan]{fn}[/cyan]")
                    else:
                        console.print("  [yellow]No FUNCTION_DECL references found in subtree.[/yellow]")
            except Exception as e:
                console.print(f"  [red]Error: {e}[/red]")
        if not found:
            console.print(f"  [red]'{var_name}' not found as a VAR_DECL in {tu_path.name}.[/red]")
            console.print("  Tip: the variable must be defined (not just declared) in this file.")
        return

    # -----------------------------------------------------------------------
    # Mode: --fn  -- find a FUNCTION_DECL and dump DECL_REF_EXPR nodes
    # -----------------------------------------------------------------------
    if fn_name:
        console.print(f"\n[bold]DECL_REF_EXPR nodes inside '{fn_name}'[/bold]\n")
        found = False
        for cursor in tu_parsed.cursor.get_children():
            try:
                if not cursor.location.file or Path(cursor.location.file.name) != tu_path:
                    continue
                fn_ck = getattr(ci.CursorKind, 'FUNCTION_DECL', None)
                if fn_ck and cursor.kind == fn_ck and cursor.spelling == fn_name and cursor.is_definition():
                    found = True
                    console.print(f"  [green]Found:[/green] {cursor.spelling}  "
                                  f"line={cursor.location.line}")
                    console.print()

                    var_refs = []
                    fn_refs  = []
                    indirect = 0

                    def _walk_fn(c):
                        nonlocal indirect
                        try:
                            ck = c.kind
                        except ValueError:
                            return
                        call_ck = getattr(ci.CursorKind, 'CALL_EXPR', None)
                        dr_ck   = getattr(ci.CursorKind, 'DECL_REF_EXPR', None)
                        var_ck  = getattr(ci.CursorKind, 'VAR_DECL', None)
                        fn_ck2  = getattr(ci.CursorKind, 'FUNCTION_DECL', None)
                        if call_ck and ck == call_ck and not c.spelling:
                            indirect += 1
                        if dr_ck and ck == dr_ck:
                            try:
                                ref = c.referenced
                                if ref:
                                    lk = _linkage(ref)
                                    if var_ck and ref.kind == var_ck:
                                        var_refs.append((ref.spelling, lk,
                                                         c.location.line))
                                    elif fn_ck2 and ref.kind == fn_ck2:
                                        fn_refs.append((ref.spelling,
                                                        c.location.line))
                            except Exception:
                                pass
                        for child in c.get_children():
                            try:
                                if child.location.file and Path(child.location.file.name) == tu_path:
                                    _walk_fn(child)
                            except Exception:
                                pass

                    _walk_fn(cursor)

                    console.print("  [bold]VAR_DECL references (global_reads candidates):[/bold]")
                    if var_refs:
                        for name, lk, line in sorted(set(var_refs)):
                            include = lk in ("internal", "external", "unique_ext")
                            mark = "[green]✓ included[/green]" if include else "[red]✗ excluded (no_link)[/red]"
                            console.print(f"    '{name}'  linkage={lk}  line={line}  {mark}")
                    else:
                        console.print("    (none)")

                    console.print("\n  [bold]FUNCTION_DECL references (direct callees):[/bold]")
                    if fn_refs:
                        for name, line in sorted(set(fn_refs)):
                            console.print(f"    '{name}'  line={line}")
                    else:
                        console.print("    (none)")

                    console.print(f"\n  [bold]Indirect call sites:[/bold] {indirect}")
            except Exception as e:
                console.print(f"  [red]Error: {e}[/red]")
        if not found:
            console.print(f"  [red]'{fn_name}' not found as a function definition in {tu_path.name}.[/red]")
        return

    # -----------------------------------------------------------------------
    # Default mode: dump full file AST up to --depth
    # -----------------------------------------------------------------------
    console.print(f"\n[bold]Full AST for {tu_path.name}[/bold]  (depth {depth})\n")
    for cursor in tu_parsed.cursor.get_children():
        try:
            if cursor.location.file and Path(cursor.location.file.name) == tu_path:
                _print_node(cursor, 0, depth)
        except Exception:
            pass


def main():
    cli()


if __name__ == "__main__":
    main()