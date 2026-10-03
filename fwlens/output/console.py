"""
Console reporter using Rich.

Produces a structured terminal summary of analysis results.
"""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich import box

from fwlens.config import FwLensConfig
from fwlens.model.project import FunctionMetrics, ModuleMetrics, ProjectModel

console = Console()


def print_baseline_summary(new_or_worsened, accepted_unchanged, baseline_path, result=None) -> None:
    """Print the result of diffing computed breaches against a baseline.json.

    ``result`` is an optional fwlens.identity.MatchResult; when given, findings that moved
    with their code, loose matches and resolved baseline entries are listed too, so the
    reader can see what the matcher decided.
    """
    console.print(f"\n[bold]Baseline check[/bold]  [dim]({baseline_path})[/dim]")

    if result is not None:
        moved = result.by_status("moved")
        uncertain = result.by_status("uncertain")
        if moved:
            console.print(f"  [dim]{len(moved)} breach(es) moved or renamed with their code (not counted as new)[/dim]")
        if uncertain:
            console.print(f"  [yellow]{len(uncertain)} breach(es) matched loosely (gated only if worse):[/yellow]")
            for m in uncertain[:10]:
                console.print(f"    [dim]{m.current.id}  <-  {m.base['id']}  ({m.note})[/dim]")
        if result.resolved:
            console.print(f"  [green]{len(result.resolved)} baselined breach(es) resolved[/green] "
                          "[dim](remove with --update-baseline --prune)[/dim]")

    if not new_or_worsened and not accepted_unchanged:
        console.print("  [green]No threshold breaches.[/green]")
        return

    if accepted_unchanged:
        console.print(f"  [dim]{len(accepted_unchanged)} breach(es) accepted in baseline (unchanged)[/dim]")

    if not new_or_worsened:
        console.print("  [green]No new or worsened breaches.[/green]")
        return

    console.print(f"  [red]{len(new_or_worsened)} new or worsened breach(es):[/red]")
    t = Table(box=box.SIMPLE)
    t.add_column("Id", style="cyan", overflow="fold")
    t.add_column("Metric", style="dim")
    t.add_column("Value", justify="right")
    t.add_column("Threshold", justify="right")
    for b in new_or_worsened[:50]:
        t.add_row(b.id, b.metric, f"{b.value:.2f}", f"{b.threshold:.2f}")
    console.print(t)
    if len(new_or_worsened) > 50:
        console.print(f"  [dim]... and {len(new_or_worsened) - 50} more[/dim]")
    console.print(
        "  [dim]Accept with:[/dim] "
        "[cyan]--update-baseline --accept-id \"<id>\"[/cyan]  [dim]or[/dim]  "
        "[cyan]--update-baseline --accept-all[/cyan]"
    )


def _breach(value, threshold) -> str:
    if value > threshold:
        return f"[red]{value}[/red]"
    return str(value)


def _fmt_float(v: float, decimals: int = 2) -> str:
    return f"{v:.{decimals}f}"


def print_summary(model: ProjectModel, config: FwLensConfig) -> None:
    t = config.thresholds
    fp_funcs = model.first_party_functions()
    fp_modules = model.first_party_modules()

    console.rule("[bold cyan]fwlens Analysis Summary[/bold cyan]")

    # Codebase overview
    overview = Table(box=box.SIMPLE, show_header=False)
    overview.add_column("Metric", style="cyan")
    overview.add_column("Value", justify="right")
    overview.add_row("EWP", str(model.ewp_path))
    overview.add_row("Configuration", model.configuration)
    overview.add_row("Modules (first-party)", str(len(fp_modules)))
    overview.add_row("Functions (first-party)", str(len(fp_funcs)))
    overview.add_row("Total LOC (first-party)", str(sum(f.loc for f in fp_funcs)))
    console.print(overview)

    # Parse diagnostics -- surfaced early and prominently, since a file can report a
    # plausible function count while a specific construct silently failed to parse.
    diag_modules = [m for m in model.modules if m.parse_diagnostics]
    if diag_modules:
        total_fatal = sum(1 for m in diag_modules for d in m.parse_diagnostics if d["severity"] == "fatal")
        total_error = sum(1 for m in diag_modules for d in m.parse_diagnostics if d["severity"] == "error")
        total_warn = sum(1 for m in diag_modules for d in m.parse_diagnostics if d["severity"] == "warning")
        console.print(
            f"\n[bold yellow]Parse Diagnostics[/bold yellow]  "
            f"[red]{total_fatal} fatal[/red], [red]{total_error} error(s)[/red], "
            f"[yellow]{total_warn} warning(s)[/yellow] across {len(diag_modules)} file(s)"
        )
        console.print("[dim]A file can report a plausible function count while a specific "
                      "construct silently failed to parse -- check these before trusting "
                      "results from the affected files.[/dim]")
        dt = Table(box=box.SIMPLE)
        dt.add_column("File", style="cyan")
        dt.add_column("Severity")
        dt.add_column("Line", justify="right")
        dt.add_column("Message", style="dim")
        shown = sorted(diag_modules, key=lambda m: -len(m.parse_diagnostics))[:15]
        for m in shown:
            worst = m.parse_diagnostics[0]
            sev_style = {"fatal": "red", "error": "red", "warning": "yellow"}.get(worst["severity"], "")
            extra = f" (+{len(m.parse_diagnostics) - 1} more)" if len(m.parse_diagnostics) > 1 else ""
            in_file = worst.get("in_file", "")
            file_label = m.path.name
            if in_file and Path(in_file) != m.path:
                file_label += f" [yellow](in {Path(in_file).name})[/yellow]"
            dt.add_row(file_label, f"[{sev_style}]{worst['severity']}[/{sev_style}]",
                      str(worst["line"]), worst["message"][:80] + extra)
        console.print(dt)
        if len(diag_modules) > 15:
            console.print(f"[dim]  ... and {len(diag_modules) - 15} more (see fwlens_results.json or the HTML report)[/dim]")

        # Known-shape detectors -- called out explicitly rather than left for the person
        # to notice in the message table, since a prose explanation of the same causes
        # has proven easy to miss across repeated runs. Neither of these is something
        # fwlens can fix on its own: the static_assert one needs a line added to the
        # person's own config.yaml (no diagnostic shape exists to auto-detect and patch
        # it -- see fwlens.autostub's module docstring), and a persisting arch-define
        # message after --auto-stub has already tried every candidate it named means the
        # header's real condition isn't just "is one of these defined" at all.
        all_msgs = [d["message"] for m in diag_modules for d in m.parse_diagnostics]
        implicit_int_count = sum(1 for msg in all_msgs
                                  if "type specifier missing" in msg and "implicit int" in msg)
        if implicit_int_count > 20:
            console.print(
                f"\n[bold red]Likely cause found:[/bold red] {implicit_int_count} "
                f"\"type specifier missing... implicit int\" diagnostic(s) -- this volume "
                f"is the signature of `static_assert` being used without `<assert.h>` in "
                f"scope, not real implicit-int code. Add this to iar_compat_defines in "
                f"your config.yaml:\n"
                f'    - "static_assert=_Static_assert"'
            )
        arch_msg_count = sum(1 for msg in all_msgs if "Please check that" in msg and "is defined!" in msg)
        if arch_msg_count > 5:
            console.print(
                f"\n[bold red]Unresolved arch-define check:[/bold red] {arch_msg_count} "
                f"occurrence(s) of a \"Please check that ... is defined!\" diagnostic. "
                f"Re-run with `--auto-stub` if you haven't -- it now defines every "
                f"candidate macro the message names (not just one guess). If it's still "
                f"here after that, the header's real condition isn't one of the named "
                f"macros at all; run `debug-parse --file <one affected file>` and read "
                f"the header the #error comes from."
            )

        # Diagnostic clusters: any (message shape, line) combination shared across many
        # files, with actual source context -- generalises the two named patterns above
        # to whatever pattern shows up next. See fwlens.diagnostic_clusters for why this
        # is worth having: a diagnostic's own text rarely names the real cause, only where
        # the parser gave up and resynchronised, and dozens of unrelated files landing on
        # the exact same line is never coincidence.
        if model.diagnostic_clusters:
            console.print(f"\n[bold yellow]Diagnostic Clusters[/bold yellow]  "
                          f"[dim]({len(model.diagnostic_clusters)} pattern(s) shared across "
                          f"5+ files -- one shared cause, not N separate problems)[/dim]")
            for c in model.diagnostic_clusters[:5]:
                console.print(f"\n  [bold]{c.file_count} files[/bold] hit this at line "
                              f"{c.line}: [dim]{c.sample_message}[/dim]")
                if c.sample_file != c.sample_tu:
                    console.print(f"  [yellow]in header:[/yellow] {c.sample_file}  "
                                  f"[dim](reported against {c.sample_tu.name}, but this is "
                                  f"where it actually is)[/dim]")
                else:
                    console.print(f"  [dim]in: {c.sample_file}[/dim]")
                for line_no, text in c.context:
                    marker = "[red]>[/red]" if line_no == c.line else " "
                    console.print(f"    {marker} {line_no:>5} | {text}")
            if len(model.diagnostic_clusters) > 5:
                console.print(f"\n  [dim]... and {len(model.diagnostic_clusters) - 5} more "
                              f"cluster(s) -- see the HTML report or diagnostic_clusters "
                              f"in the JSON export.[/dim]")

    # Threshold breach summary
    breaches = {
        "CC > " + str(t.cyclomatic_complexity):
            sum(1 for f in fp_funcs if f.cyclomatic_complexity > t.cyclomatic_complexity),
        "Cognitive > " + str(t.cognitive_complexity):
            sum(1 for f in fp_funcs if f.cognitive_complexity > t.cognitive_complexity),
        "Block depth > " + str(t.block_depth):
            sum(1 for f in fp_funcs if f.block_depth > t.block_depth),
        "LOC > " + str(t.function_loc):
            sum(1 for f in fp_funcs if f.loc > t.function_loc),
        "Params > " + str(t.parameter_count):
            sum(1 for f in fp_funcs if f.parameter_count > t.parameter_count),
        "Return paths > " + str(t.return_path_count):
            sum(1 for f in fp_funcs if f.return_path_count > t.return_path_count),
        "Magic density > " + str(t.magic_number_density):
            sum(1 for f in fp_funcs if f.magic_number_density > t.magic_number_density),
        "Fan-out > " + str(t.fan_out):
            sum(1 for f in fp_funcs if f.fan_out > t.fan_out),
    }

    console.print("\n[bold]Threshold Breaches[/bold]")
    bt = Table(box=box.SIMPLE)
    bt.add_column("Threshold", style="cyan")
    bt.add_column("Breach count", justify="right")
    bt.add_column("% of functions", justify="right")
    n = max(len(fp_funcs), 1)
    for label, count in breaches.items():
        pct = f"{100 * count / n:.1f}%"
        colour = "red" if count > 0 else "green"
        bt.add_row(label, f"[{colour}]{count}[/{colour}]", pct)
    console.print(bt)

    # Exceedance probabilities
    if model.exceedance_probabilities:
        console.print("\n[bold]Exceedance Probabilities[/bold]")
        et = Table(box=box.SIMPLE)
        et.add_column("Metric", style="cyan")
        et.add_column("P(X > threshold)", justify="right")
        for metric, prob in model.exceedance_probabilities.items():
            colour = "red" if prob > 0.1 else "yellow" if prob > 0.05 else "green"
            et.add_row(metric, f"[{colour}]{100*prob:.1f}%[/{colour}]")
        console.print(et)

    # Top offenders by CC
    top_n = config.output.top_n
    top_cc = sorted(fp_funcs, key=lambda f: f.cyclomatic_complexity, reverse=True)[:top_n]
    console.print(f"\n[bold]Top {top_n} Functions by Cyclomatic Complexity[/bold]")
    tcc = Table(box=box.SIMPLE)
    tcc.add_column("Function", style="cyan")
    tcc.add_column("File", style="dim")
    tcc.add_column("CC", justify="right")
    tcc.add_column("Cognitive", justify="right")
    tcc.add_column("LOC", justify="right")
    tcc.add_column("Effort", justify="right")
    tcc.add_column("SDI", justify="right")
    for f in top_cc:
        tcc.add_row(
            f.name,
            f.file.name,
            _breach(f.cyclomatic_complexity, t.cyclomatic_complexity),
            str(f.cognitive_complexity),
            _breach(f.loc, t.function_loc),
            f"{f.halstead_effort:.0f}",
            f"{f.structural_debt_index:.2f}",
        )
    console.print(tcc)

    # Top offenders by structural debt index
    top_sdi = sorted(fp_funcs, key=lambda f: f.structural_debt_index, reverse=True)[:top_n]
    console.print(f"\n[bold]Top {top_n} Functions by Structural Debt Index[/bold]")
    tsdi = Table(box=box.SIMPLE)
    tsdi.add_column("Function", style="cyan")
    tsdi.add_column("File", style="dim")
    tsdi.add_column("SDI", justify="right")
    tsdi.add_column("CC", justify="right")
    tsdi.add_column("Return paths", justify="right")
    tsdi.add_column("Magic density", justify="right")
    tsdi.add_column("Param mut.", justify="right")
    for f in top_sdi:
        tsdi.add_row(
            f.name,
            f.file.name,
            f"[red]{f.structural_debt_index:.2f}[/red]",
            str(f.cyclomatic_complexity),
            _breach(f.return_path_count, t.return_path_count),
            f"{f.magic_number_density:.2f}",
            f"{f.param_mutation_rate:.2f}",
        )
    console.print(tsdi)

    # RTOS: tasks, sync objects, and risk analysis (embOS or other configured RTOS)
    if model.rtos_kind != "none" and (model.rtos_tasks or model.rtos_sync_objects):
        console.print(f"\n[bold]RTOS ({model.rtos_kind}): Tasks[/bold]")
        rt = Table(box=box.SIMPLE)
        rt.add_column("Task", style="cyan")
        rt.add_column("TCB", style="dim")
        rt.add_column("Priority", justify="right")
        rt.add_column("Entry function", style="dim")
        rt.add_column("Stack", style="dim")
        rt.add_column("Stack size", justify="right")
        for t in sorted(model.rtos_tasks, key=lambda x: (x.priority_value is None, -(x.priority_value or 0))):
            prio = str(t.priority_value) if t.priority_value is not None else f"[yellow]{t.priority_expr}[/yellow]"
            stack_size = str(t.stack_size_value) if t.stack_size_value is not None else f"[yellow]{t.stack_size_expr}[/yellow]"
            rt.add_row(t.name, t.tcb_var, prio, t.entry_function, t.stack_expr, stack_size)
        console.print(rt)

        if model.rtos_sync_objects:
            console.print(f"\n[bold]RTOS Synchronisation Objects[/bold]")
            rst = Table(box=box.SIMPLE)
            rst.add_column("Object", style="cyan")
            rst.add_column("Kind")
            rst.add_column("File", style="dim")
            for o in model.rtos_sync_objects:
                rst.add_row(o.var_name, o.kind, o.file.name)
            console.print(rst)

        if model.rtos_priority_collisions:
            console.print(f"\n[bold]Priority Collisions[/bold]  "
                          f"[red]{len(model.rtos_priority_collisions)}[/red]")
            for c in model.rtos_priority_collisions:
                console.print(f"  priority {c.priority_value}: {', '.join(c.task_names)}")

        if model.rtos_inversion_risks:
            console.print(f"\n[bold]Priority Inversion Candidates[/bold]  "
                          f"[red]{len(model.rtos_inversion_risks)}[/red]  "
                          "[dim](non-inheriting semaphore shared across priorities)[/dim]")
            for r in model.rtos_inversion_risks:
                pairs = ", ".join(f"{t}({p if p is not None else '?'})"
                                 for t, p in zip(r.task_names, r.priorities))
                console.print(f"  {r.object_var}: {pairs}")

        if model.rtos_unused_objects:
            console.print(f"\n[bold]Unused RTOS Objects[/bold]  [yellow]{len(model.rtos_unused_objects)}[/yellow]")
            for o in model.rtos_unused_objects:
                console.print(f"  {o.kind} {o.var_name} ({o.file.name})")

    # State machines
    if model.state_machines:
        console.print(f"\n[bold]State Machines Detected[/bold]  [bold]{len(model.state_machines)}[/bold]")
        smt = Table(box=box.SIMPLE)
        smt.add_column("Function", style="cyan")
        smt.add_column("File", style="dim")
        smt.add_column("State var")
        smt.add_column("States", justify="right")
        smt.add_column("Transitions", justify="right")
        for sm in model.state_machines[:top_n]:
            smt.add_row(sm.function_name, sm.file.name, sm.state_var,
                       str(len(sm.states)), str(len(sm.transitions)))
        console.print(smt)

    # Information flow complexity (Henry & Kafura)
    top_if = sorted(fp_funcs, key=lambda f: f.information_flow_complexity, reverse=True)[:top_n]
    top_if = [f for f in top_if if f.information_flow_complexity > 0]
    if top_if:
        console.print(f"\n[bold]Top {len(top_if)} Functions by Information Flow Complexity[/bold]  "
                      "[dim](Henry & Kafura -- length x (fan-in x fan-out)^2)[/dim]")
        ift = Table(box=box.SIMPLE)
        ift.add_column("Function", style="cyan")
        ift.add_column("File", style="dim")
        ift.add_column("Fan-in", justify="right")
        ift.add_column("Fan-out", justify="right")
        ift.add_column("IF4", justify="right")
        for f in top_if:
            ift.add_row(f.name, f.file.name, str(f.fan_in), str(f.fan_out),
                       f"{f.information_flow_complexity:,.0f}")
        console.print(ift)

    # COCOMO effort/schedule estimate
    if model.effort_estimate:
        e = model.effort_estimate
        console.print(f"\n[bold]COCOMO Effort Estimate[/bold]  [dim](mode: {e.mode})[/dim]")
        console.print(
            f"  {e.kloc:.1f} KLOC  ->  [bold]{e.effort_person_months:.1f}[/bold] person-months  /  "
            f"[bold]{e.schedule_months:.1f}[/bold] months  /  "
            f"[bold]{e.average_staffing:.1f}[/bold] average staff"
        )
        console.print("  [dim]1970s-80s-calibrated constants -- a rough historical baseline, "
                      "not a committed schedule[/dim]")

    # Reliability growth (Goel-Okumoto)
    if model.reliability_growth:
        r = model.reliability_growth
        console.print(f"\n[bold]Reliability Growth[/bold]  [dim](Goel-Okumoto NHPP fit "
                      "over fix-commit history)[/dim]")
        if r.trend == "insufficient_data":
            console.print(f"  [dim]{r.fix_commit_count} fix-flavoured commit(s) found -- "
                          f"need at least 8 for a fit[/dim]")
        else:
            trend_colour = {"climbing": "red", "flattening": "yellow", "plateaued": "green"}[r.trend]
            console.print(
                f"  {r.cumulative_to_date} fix commits over {r.days_span} days  ->  "
                f"fitted total [bold]{r.fitted_total_defects:.0f}[/bold]  "
                f"(~[bold]{r.estimated_remaining:.0f}[/bold] estimated remaining)  "
                f"trend: [{trend_colour}]{r.trend}[/{trend_colour}]  "
                f"(R2={r.r_squared:.2f})"
            )

    # Complexity-vs-defect correlation
    if model.defect_correlations:
        console.print(f"\n[bold]Complexity-vs-Defect Correlation[/bold]  "
                      "[dim](Spearman r against fix-commit touch count, this codebase)[/dim]")
        dct = Table(box=box.SIMPLE)
        dct.add_column("Metric", style="cyan")
        dct.add_column("Spearman r", justify="right")
        dct.add_column("p-value", justify="right")
        for c in model.defect_correlations[:8]:
            colour = "red" if abs(c.spearman_r) >= 0.5 else "yellow" if abs(c.spearman_r) >= 0.3 else "dim"
            dct.add_row(c.label, f"[{colour}]{c.spearman_r:+.2f}[/{colour}]", f"{c.p_value:.3f}")
        console.print(dct)

    # Cost/benefit
    if model.cost_benefit:
        cb = model.cost_benefit
        console.print(f"\n[bold]Cost/Benefit: Static vs. Field[/bold]  "
                      "[dim](placeholder cost figures unless configured -- see guide)[/dim]")
        console.print(
            f"  ~{cb.estimated_remaining_defects:.0f} estimated remaining defects  ->  "
            f"[green]${cb.cost_if_static_usd:,.0f}[/green] if caught statically vs. "
            f"[red]${cb.cost_if_field_usd:,.0f}[/red] if found in the field  "
            f"(potential savings: [bold]${cb.potential_savings_usd:,.0f}[/bold])"
        )

    # Commit activity by calendar day (whole codebase, not per file)
    if model.commit_activity:
        total_commits = sum(c.commit_count for c in model.commit_activity)
        dates = sorted(c.date for c in model.commit_activity)
        busiest = max(model.commit_activity, key=lambda c: c.commit_count)
        console.print(
            f"\n[bold]Commit Activity[/bold]  "
            f"[dim](see plots/commit_activity_calendar.png)[/dim]\n"
            f"  {total_commits} commit(s) across {len(dates)} active day(s), "
            f"{dates[0]} to {dates[-1]}  --  busiest day: {busiest.date} "
            f"({busiest.commit_count} commit(s))"
        )

    # Hotspots: churn x structural debt
    if model.git_available and model.hotspots:
        commit_by_path = {m.path: m.commit_count for m in fp_modules}
        top_hot = [f for f in model.hotspots if f.hotspot_score > 0][:top_n]
        if top_hot:
            console.print(f"\n[bold]Top {len(top_hot)} Hotspots (churn x structural debt)[/bold]")
            ht = Table(box=box.SIMPLE)
            ht.add_column("Function", style="cyan")
            ht.add_column("File", style="dim")
            ht.add_column("Commits", justify="right")
            ht.add_column("SDI", justify="right")
            ht.add_column("Hotspot score", justify="right")
            for f in top_hot:
                commits = commit_by_path.get(f.file, 0)
                colour = "red" if f.hotspot_score >= 0.5 else "yellow"
                ht.add_row(
                    f.name, f.file.name, str(commits),
                    f"{f.structural_debt_index:.2f}",
                    f"[{colour}]{f.hotspot_score:.2f}[/{colour}]",
                )
            console.print(ht)
    elif not model.git_available:
        console.print("\n[bold]Hotspots[/bold]  [dim]not a git repository -- skipped[/dim]")

    # Bug-fix-weighted hotspots (same churn x SDI formula, fix-commit churn only)
    if model.git_available and model.bugfix_hotspots:
        top_bugfix = [f for f in model.bugfix_hotspots if f.bugfix_hotspot_score > 0][:top_n]
        if top_bugfix:
            console.print(f"\n[bold]Top {len(top_bugfix)} Bug-Fix-Weighted Hotspots[/bold]  "
                          "[dim](churn restricted to fix-flavoured commits -- config.git.fix_keywords)[/dim]")
            bft = Table(box=box.SIMPLE)
            bft.add_column("Function", style="cyan")
            bft.add_column("File", style="dim")
            bft.add_column("Fix commits", justify="right")
            bft.add_column("Bugfix hotspot score", justify="right")
            fix_by_path = {m.path: m.bugfix_commit_count for m in fp_modules}
            for f in top_bugfix:
                colour = "red" if f.bugfix_hotspot_score >= 0.5 else "yellow"
                bft.add_row(
                    f.name, f.file.name, str(fix_by_path.get(f.file, 0)),
                    f"[{colour}]{f.bugfix_hotspot_score:.2f}[/{colour}]",
                )
            console.print(bft)

    # Hotspot name judgement (Ch.5) -- flagged entries in the churn x SDI hotspot list
    name_flagged = [f for f in model.hotspots if f.vague_name_flag][:top_n]
    if name_flagged:
        console.print(f"\n[bold]Hotspots With Vague Names[/bold]  "
                      f"([bold]{len(name_flagged)}[/bold] shown -- name reveals no responsibility)")
        nf = Table(box=box.SIMPLE)
        nf.add_column("Function", style="cyan")
        nf.add_column("File", style="dim")
        nf.add_column("Reason", style="yellow")
        for f in name_flagged:
            nf.add_row(f.name, f.file.name, f.vague_name_flag)
        console.print(nf)

    # Complexity trend in top hotspots (Ch.6)
    trends_with_data = [t for t in model.complexity_trends if t.trend != "insufficient_data"]
    if trends_with_data:
        console.print(f"\n[bold]Complexity Trend in Top Hotspots[/bold]  "
                      "[dim](sampled from git history -- see plots/complexity_trend.png)[/dim]")
        tt = Table(box=box.SIMPLE)
        tt.add_column("File", style="dim")
        tt.add_column("Trend", justify="center")
        tt.add_column("Slope (per day)", justify="right")
        tt.add_column("R²", justify="right")
        trend_colour = {"worsening": "red", "improving": "green", "stable": "cyan"}
        for t in trends_with_data:
            colour = trend_colour.get(t.trend, "dim")
            tt.add_row(t.file.name, f"[{colour}]{t.trend}[/{colour}]",
                       f"{t.slope:+.3f}", f"{t.r_squared:.2f}")
        console.print(tt)

    # Code ownership / knowledge map (Ch.11-13)
    if model.ownership_risks:
        top_owner = [m for m in model.ownership_risks if m.ownership_risk_score > 0][:top_n]
        if top_owner:
            console.print(f"\n[bold]Ownership Risk (churn x diffuse authorship)[/bold]  "
                          "[dim](frequently changed AND no clear main author)[/dim]")
            ot = Table(box=box.SIMPLE)
            ot.add_column("File", style="dim")
            ot.add_column("Main author", style="cyan")
            ot.add_column("Main author share", justify="right")
            ot.add_column("Authors", justify="right")
            ot.add_column("Ownership risk", justify="right")
            for m in top_owner:
                colour = "red" if m.ownership_risk_score >= 0.5 else "yellow"
                ot.add_row(
                    m.path.name, m.main_author, f"{m.main_author_share:.0%}",
                    str(m.distinct_author_count),
                    f"[{colour}]{m.ownership_risk_score:.2f}[/{colour}]",
                )
            console.print(ot)

    # Composite risk ranking
    if model.composite_risk:
        top_risk = [f for f in model.composite_risk if f.composite_risk_score > 0][:top_n]
        if top_risk:
            console.print(f"\n[bold]Top {len(top_risk)} Composite Risk Ranking[/bold]  "
                          "[dim](SDI + hotspot + module pain + ISR + stack, fused)[/dim]")
            crt = Table(box=box.SIMPLE)
            crt.add_column("Function", style="cyan")
            crt.add_column("File", style="dim")
            crt.add_column("Risk score", justify="right")
            for f in top_risk:
                colour = "red" if f.composite_risk_score >= 0.5 else "yellow"
                crt.add_row(f.name, f.file.name, f"[{colour}]{f.composite_risk_score:.2f}[/{colour}]")
            console.print(crt)

    # Tech debt: TODO/FIXME/HACK markers
    if model.todo_markers:
        from collections import Counter
        tag_counts = Counter(t.tag for t in model.todo_markers)
        summary = "  ".join(f"{tag}: {count}" for tag, count in tag_counts.most_common())
        console.print(f"\n[bold]TODO / FIXME / HACK Markers[/bold]  "
                      f"([bold]{len(model.todo_markers)}[/bold] total -- {summary})")
        tm = Table(box=box.SIMPLE)
        tm.add_column("Tag", style="yellow")
        tm.add_column("File", style="dim")
        tm.add_column("Line", justify="right")
        tm.add_column("Text")
        for t in model.todo_markers[:top_n]:
            tm.add_row(t.tag, t.file.name, str(t.line), t.text[:60])
        console.print(tm)
        if len(model.todo_markers) > top_n:
            console.print(f"  [dim]... and {len(model.todo_markers) - top_n} more (see CSV export)[/dim]")

    # Tech debt: commented-out code
    if model.commented_code_blocks:
        console.print(f"\n[bold]Commented-Out Code[/bold]  "
                      f"([bold]{len(model.commented_code_blocks)}[/bold] block(s) suspected)")
        cc = Table(box=box.SIMPLE)
        cc.add_column("File", style="dim")
        cc.add_column("Lines", justify="right")
        cc.add_column("Line count", justify="right")
        for b in model.commented_code_blocks[:top_n]:
            cc.add_row(b.file.name, f"{b.start_line}-{b.end_line}", str(b.line_count))
        console.print(cc)
        if len(model.commented_code_blocks) > top_n:
            console.print(f"  [dim]... and {len(model.commented_code_blocks) - top_n} more (see CSV export)[/dim]")

    # Tech debt: preprocessor complexity
    complex_modules = sorted(
        [m for m in fp_modules if m.max_ifdef_depth > 0],
        key=lambda m: (m.max_ifdef_depth, m.distinct_feature_flags), reverse=True,
    )[:top_n]
    if complex_modules:
        console.print(f"\n[bold]Preprocessor Complexity[/bold]")
        pc = Table(box=box.SIMPLE)
        pc.add_column("File", style="dim")
        pc.add_column("Max #ifdef depth", justify="right")
        pc.add_column("Directives", justify="right")
        pc.add_column("Distinct flags", justify="right")
        for m in complex_modules:
            depth_colour = "red" if m.max_ifdef_depth >= 4 else "yellow" if m.max_ifdef_depth >= 2 else "green"
            pc.add_row(
                m.path.name, f"[{depth_colour}]{m.max_ifdef_depth}[/{depth_colour}]",
                str(m.ifdef_directive_count), str(m.distinct_feature_flags),
            )
        console.print(pc)

    # Clone / near-duplicate functions
    if model.clone_pairs:
        console.print(f"\n[bold]Near-Duplicate Functions[/bold]  "
                      f"([bold]{len(model.clone_pairs)}[/bold] pair(s) >= 75% similar)")
        dead_overlap = sum(1 for p in model.clone_pairs if p.is_dead_a or p.is_dead_b)
        if dead_overlap:
            console.print(f"  [red]{dead_overlap} pair(s)[/red] also flagged as dead code on "
                          f"at least one side -- listed first, safe removal candidates")
        cl = Table(box=box.SIMPLE)
        cl.add_column("Function A", style="cyan")
        cl.add_column("Function B", style="cyan")
        cl.add_column("Similarity", justify="right")
        cl.add_column("Dead code")
        for p in model.clone_pairs[:top_n]:
            dead_label = ""
            if p.is_dead_a and p.is_dead_b:
                dead_label = "[red]both[/red]"
            elif p.is_dead_a:
                dead_label = f"[red]{p.function_a}[/red]"
            elif p.is_dead_b:
                dead_label = f"[red]{p.function_b}[/red]"
            cl.add_row(
                f"{p.function_a} ({p.file_a.name})",
                f"{p.function_b} ({p.file_b.name})",
                f"{p.similarity:.0%}",
                dead_label,
            )
        console.print(cl)
        if len(model.clone_pairs) > top_n:
            console.print(f"  [dim]... and {len(model.clone_pairs) - top_n} more (see CSV export)[/dim]")

    # Change coupling
    if model.change_coupling:
        console.print(f"\n[bold]Change Coupling[/bold]  "
                      f"([bold]{len(model.change_coupling)}[/bold] file pair(s) change together)")
        ch = Table(box=box.SIMPLE)
        ch.add_column("File A", style="dim")
        ch.add_column("File B", style="dim")
        ch.add_column("Co-changes", justify="right")
        ch.add_column("Coupling", justify="right")
        for p in model.change_coupling[:top_n]:
            ch.add_row(p.file_a.name, p.file_b.name, str(p.co_changes), f"{p.coupling:.0%}")
        console.print(ch)
        if len(model.change_coupling) > top_n:
            console.print(f"  [dim]... and {len(model.change_coupling) - top_n} more (see CSV export)[/dim]")

    # Architecture-level temporal coupling (Ch.8/10 -- "architectural decay")
    if model.layer_coupling:
        console.print(f"\n[bold]Architecture-Level Change Coupling[/bold]  "
                      f"([bold]{len(model.layer_coupling)}[/bold] cross-layer pair(s))")
        lc = Table(box=box.SIMPLE)
        lc.add_column("Layer A", style="dim")
        lc.add_column("Layer B", style="dim")
        lc.add_column("File pairs", justify="right")
        lc.add_column("Co-changes", justify="right")
        lc.add_column("Avg coupling", justify="right")
        lc.add_column("Surprising", justify="right")
        for lp in model.layer_coupling[:top_n]:
            surprising_colour = "red" if lp.surprising_pair_count > 0 else "dim"
            lc.add_row(
                lp.layer_a, lp.layer_b, str(lp.file_pair_count), str(lp.total_co_changes),
                f"{lp.avg_coupling:.0%}",
                f"[{surprising_colour}]{lp.surprising_pair_count}[/{surprising_colour}]",
            )
        console.print(lc)
        console.print("  [dim]\"Surprising\" = no direct #include either way -- "
                      "co-change with no static dependency to explain it (worklist, not verdict)[/dim]")

    # Worst-case stack per entry point
    if model.entry_point_stack_risks:
        console.print("\n[bold]Worst-Case Stack per Entry Point[/bold]")
        st = Table(box=box.SIMPLE)
        st.add_column("Entry point", style="cyan")
        st.add_column("File", style="dim")
        st.add_column("Type", justify="right")
        st.add_column("Stack estimate", justify="right")
        for r in model.entry_point_stack_risks[:top_n]:
            kind = "[yellow]ISR[/yellow]" if r.is_isr else "task/main"
            if not r.stack_estimable or r.stack_depth_estimate is None:
                depth = "[yellow]~ non-estimable[/yellow]"
            else:
                depth = str(r.stack_depth_estimate)
            st.add_row(r.function_name, r.file.name, kind, depth)
        console.print(st)
        if len(model.entry_point_stack_risks) > top_n:
            console.print(f"  [dim]... and {len(model.entry_point_stack_risks) - top_n} more (see CSV export)[/dim]")

    # ISR / main-loop shared-variable risk
    race_risks = [g for g in model.globals if g.volatile_risk]
    if race_risks:
        console.print(f"\n[bold]ISR / Main-Loop Shared Variable Risk[/bold] "
                      f"([red]{len(race_risks)}[/red] non-volatile, dual-context)")
        gt = Table(box=box.SIMPLE)
        gt.add_column("Variable", style="cyan")
        gt.add_column("File", style="dim")
        gt.add_column("ISR access", style="yellow")
        gt.add_column("Main-loop access")
        for g in race_risks[:top_n]:
            isr_side = sorted(set(g.isr_readers) | set(g.isr_writers))
            main_side = sorted((set(g.readers) | set(g.writers)) - set(isr_side))
            gt.add_row(
                g.name, g.file.name,
                ", ".join(isr_side[:3]) + (" ..." if len(isr_side) > 3 else ""),
                ", ".join(main_side[:3]) + (" ..." if len(main_side) > 3 else ""),
            )
        console.print(gt)
        if len(race_risks) > top_n:
            console.print(f"  [dim]... and {len(race_risks) - top_n} more (see CSV export)[/dim]")

    # ISR risks
    if model.isr_risks:
        console.print("\n[bold]ISR Latency Risk[/bold]")
        it = Table(box=box.SIMPLE)
        it.add_column("ISR", style="cyan")
        it.add_column("File", style="dim")
        it.add_column("Own CC", justify="right")
        it.add_column("Transitive CC", justify="right")
        it.add_column("Call depth", justify="right")
        it.add_column("Risk score", justify="right")
        for r in model.isr_risks[:top_n]:
            flag = " [yellow]~[/yellow]" if r.non_estimable else ""
            it.add_row(
                r.isr_name + flag,
                r.file.name,
                str(r.own_cc),
                str(r.transitive_cc_sum),
                str(r.call_depth),
                f"[red]{r.risk_score:.0f}[/red]" if r.risk_score > 50 else f"{r.risk_score:.0f}",
            )
        console.print(it)

    # Dead code candidates
    if model.dead_candidates:
        console.print(f"\n[bold]Dead Code Candidates[/bold] ({len(model.dead_candidates)} suspected)")
        dt = Table(box=box.SIMPLE)
        dt.add_column("Function", style="cyan")
        dt.add_column("File", style="dim")
        dt.add_column("LOC", justify="right")
        for f in model.dead_candidates[:top_n]:
            dt.add_row(f.name, f.file.name, str(f.loc))
        if len(model.dead_candidates) > top_n:
            console.print(f"  [dim]... and {len(model.dead_candidates) - top_n} more (see CSV export)[/dim]")
        console.print(dt)

    # Module coupling
    console.print("\n[bold]Module Coupling (top instability)[/bold]")
    top_unstable = sorted(fp_modules, key=lambda m: m.instability, reverse=True)[:top_n]
    mt = Table(box=box.SIMPLE)
    mt.add_column("Module", style="cyan")
    mt.add_column("Layer", style="dim")
    mt.add_column("Fan-in", justify="right")
    mt.add_column("Fan-out", justify="right")
    mt.add_column("Instability", justify="right")
    mt.add_column("MSD", justify="right")
    mt.add_column("Zone", justify="right")
    mt.add_column("Cycle", justify="right")
    for m in top_unstable:
        cycle_flag = "[red]Y[/red]" if m.in_cycle else "N"
        msd_flag = f"[red]{m.main_sequence_distance:.2f}[/red]" \
            if m.main_sequence_distance > config.thresholds.main_sequence_distance \
            else f"{m.main_sequence_distance:.2f}"
        zone_labels = {
            "pain":         "[red]Pain[/red]",
            "uselessness":  "[yellow]Useless[/yellow]",
            "main_sequence": "[green]OK[/green]",
            "warning":      "[yellow]Warn[/yellow]",
        }
        zone_flag = zone_labels.get(getattr(m, "zone", ""), "[dim]?[/dim]")
        mt.add_row(
            m.path.name,
            m.layer or "Unknown",
            str(m.fan_in),
            str(m.fan_out),
            f"{m.instability:.2f}",
            msd_flag,
            zone_flag,
            cycle_flag,
        )
    console.print(mt)

    # Zone of pain / uselessness summary
    pain_modules = [m for m in fp_modules if getattr(m, "zone", "") == "pain"]
    useless_modules = [m for m in fp_modules if getattr(m, "zone", "") == "uselessness"]
    if pain_modules or useless_modules:
        console.print("\n[bold]Stable Abstractions Violations[/bold]")
        if pain_modules:
            console.print(f"  [red]Zone of Pain[/red] ({len(pain_modules)} modules) "
                          f"-- concrete and stable, hard to change:")
            for m in pain_modules[:5]:
                console.print(f"    [dim]{m.path.name}[/dim]  "
                              f"I={m.instability:.2f}  A={m.abstractness:.2f}")
        if useless_modules:
            console.print(f"  [yellow]Zone of Uselessness[/yellow] ({len(useless_modules)} modules) "
                          f"-- abstract and unstable, not depended upon:")
            for m in useless_modules[:5]:
                console.print(f"    [dim]{m.path.name}[/dim]  "
                              f"I={m.instability:.2f}  A={m.abstractness:.2f}")

    # Architecture violations
    if model.arch_violations:
        console.print(f"\n[bold]Architecture Layer Violations[/bold] "
                      f"([red]{len(model.arch_violations)}[/red] detected)")
        avt = Table(box=box.SIMPLE)
        avt.add_column("From", style="cyan")
        avt.add_column("Layer", style="dim")
        avt.add_column("To", style="cyan")
        avt.add_column("Layer", style="dim")
        avt.add_column("Type", justify="right")
        shown = model.arch_violations[:top_n]
        for v in shown:
            vtype_fmt = f"[red]{v.violation_type}[/red]" \
                if v.violation_type == "skipped" else f"[yellow]{v.violation_type}[/yellow]"
            avt.add_row(
                v.source_module.name,
                v.source_layer,
                v.target_module.name,
                v.target_layer,
                vtype_fmt,
            )
        console.print(avt)
        if len(model.arch_violations) > top_n:
            console.print(f"  [dim]... and {len(model.arch_violations) - top_n} more[/dim]")
    else:
        console.print("\n[bold]Architecture Layer Violations[/bold]  [green]none detected[/green]")

    # Header include analysis (cycles, self-includes, guards, deep chains, unused includes)
    has_header_data = any([
        model.include_cycles, model.self_includes, model.missing_include_guards,
        model.deep_include_chains, model.unused_includes,
    ])
    if has_header_data:
        console.print("\n[bold]Header Include Analysis[/bold]")

        if model.include_cycles:
            console.print(f"\n  [bold]Circular Includes[/bold]  "
                          f"([red]{len(model.include_cycles)}[/red] cycle(s))")
            for c in model.include_cycles[:top_n]:
                chain = " -> ".join(p.name for p in c.files) + f" -> {c.files[0].name}"
                console.print(f"    [red]{c.length}-file cycle[/red]  {chain}")
            if len(model.include_cycles) > top_n:
                console.print(f"    [dim]... and {len(model.include_cycles) - top_n} more[/dim]")
        else:
            console.print("\n  [bold]Circular Includes[/bold]  [green]none detected[/green]")

        if model.self_includes:
            console.print(f"\n  [bold]Self-Includes[/bold]  "
                          f"([yellow]{len(model.self_includes)}[/yellow])")
            for s in model.self_includes[:top_n]:
                console.print(f"    [dim]{s.file.name}[/dim]")
            if len(model.self_includes) > top_n:
                console.print(f"    [dim]... and {len(model.self_includes) - top_n} more[/dim]")
        else:
            console.print("\n  [bold]Self-Includes[/bold]  [green]none detected[/green]")

        if model.missing_include_guards:
            console.print(f"\n  [bold]Missing Include Guards[/bold]  "
                          f"([yellow]{len(model.missing_include_guards)}[/yellow] header(s))")
            mgt = Table(box=box.SIMPLE)
            mgt.add_column("File", style="cyan")
            mgt.add_column("Reason", style="dim")
            for g in model.missing_include_guards[:top_n]:
                mgt.add_row(g.file.name, g.reason)
            console.print(mgt)
            if len(model.missing_include_guards) > top_n:
                console.print(f"    [dim]... and {len(model.missing_include_guards) - top_n} more[/dim]")

        if model.deep_include_chains:
            console.print(f"\n  [bold]Deepest Transitive Include Chains[/bold]  "
                          f"[dim](top {len(model.deep_include_chains)} first-party files)[/dim]")
            dit = Table(box=box.SIMPLE)
            dit.add_column("File", style="cyan")
            dit.add_column("Include depth", justify="right")
            for d in model.deep_include_chains[:top_n]:
                dit.add_row(d.file.name, str(d.depth))
            console.print(dit)

        if model.unused_includes:
            console.print(f"\n  [bold]Possibly Unused Includes[/bold]  "
                          f"([yellow]{len(model.unused_includes)}[/yellow] flagged -- heuristic, "
                          f"verify before removing)")
            uit = Table(box=box.SIMPLE)
            uit.add_column("File", style="cyan")
            uit.add_column("Included header", style="dim")
            for u in model.unused_includes[:top_n]:
                uit.add_row(u.file.name, u.included.name)
            console.print(uit)
            if len(model.unused_includes) > top_n:
                console.print(f"    [dim]... and {len(model.unused_includes) - top_n} more[/dim]")

    console.rule()
    console.print(
        "\n[dim]Next steps:[/dim]  "
        "[cyan].\\Run-FwLens.ps1 report[/cyan]  "
        "[dim](HTML + CSV + JSON)[/dim]   "
        "[cyan].\\Run-FwLens.ps1 export[/cyan]  "
        "[dim](CSV + JSON only)[/dim]\n"
    )