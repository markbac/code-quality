"""
FWLens CLI commands implementation.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import click
from rich.console import Console

__version__ = "0.29.0"

console = Console()


def _run_pipeline(config_path: Path, auto_stub: bool = False):
    from fwlens.config import load_config
    from fwlens.parser.pipeline import run_pipeline
    from fwlens.metrics.aggregates import run_aggregation
    from fwlens.graph.engines import run_graph_engine
    from fwlens.stats.distributions import run_stats_engine
    from fwlens.git_history import (
        compute_hotspots, compute_change_coupling, compute_churn_heatmap,
        compute_architecture_coupling, compute_commit_activity,
    )
    from fwlens.tech_debt import run_tech_debt_scan
    from fwlens.clones import detect_clones
    from fwlens.risk import compute_composite_risk
    from fwlens.effort_estimate import compute_effort_estimate
    from fwlens.reliability import compute_reliability_growth, compute_bugfix_hotspots
    from fwlens.defect_analysis import compute_defect_correlation
    from fwlens.cost_benefit import compute_cost_benefit
    from fwlens.rtos_analysis import run_rtos_analysis
    from fwlens.state_machines import detect_state_machines
    from fwlens.ownership import compute_ownership
    from fwlens.hotspot_names import flag_hotspot_names
    from fwlens.complexity_trend import compute_complexity_trends
    from fwlens.preflight import run_static_preflight, run_post_scan_preflight, print_preflight_issues

    config = load_config(config_path)

    static_issues = run_static_preflight(config)
    if print_preflight_issues(static_issues, console):
        console.print("\n[bold red][fwlens] Aborting -- fix the error(s) above before running analysis.[/bold red]")
        raise SystemExit(1)

    if auto_stub:
        if config.project.mode == "directory":
            console.print("[yellow][fwlens] --auto-stub has no effect in directory mode -- skipping.[/yellow]")
        else:
            from fwlens.autostub import run_auto_stub
            run_auto_stub(config, console)

    t0 = time.perf_counter()
    model = run_pipeline(config)
    from fwlens.diagnostic_clusters import compute_diagnostic_clusters
    model.diagnostic_clusters = compute_diagnostic_clusters(model)
    run_aggregation(model, config)
    run_graph_engine(model, config)
    run_stats_engine(model, config)
    compute_hotspots(model, config)
    compute_change_coupling(model, config)
    compute_churn_heatmap(model, config)
    compute_commit_activity(model, config)
    compute_architecture_coupling(model, config)
    compute_ownership(model, config)
    flag_hotspot_names(model)
    compute_complexity_trends(model, config)
    compute_effort_estimate(model, config)
    compute_reliability_growth(model, config)
    compute_bugfix_hotspots(model, config)
    compute_defect_correlation(model, config)
    compute_cost_benefit(model, config)
    run_rtos_analysis(model, config)
    detect_state_machines(model)
    run_tech_debt_scan(model)
    detect_clones(model)
    compute_composite_risk(model)
    elapsed = time.perf_counter() - t0
    console.print(f"[cyan][fwlens][/cyan] Analysis complete in [bold]{elapsed:.1f}s[/bold]")

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


@click.group()
def cli():
    """fwlens -- Embedded C Architecture & Static Analysis Platform."""
    pass


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


def main():
    cli()
