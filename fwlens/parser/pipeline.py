"""
Parallel parsing pipeline.

Dispatches in-scope translation units to worker processes for AST parsing.
Out-of-scope files are registered as modules (for include graph completeness)
but never parsed -- their headers still appear on every in-scope TU's include
path so libclang resolves types correctly.
"""

from __future__ import annotations

import os
import traceback
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from fwlens.config import FwLensConfig
from fwlens.model.project import (
    BoundaryClass, FunctionMetrics, GlobalVarInfo,
    ModuleMetrics, ProjectModel,
)
from fwlens.parser.ewp import parse_ewp, TranslationUnit

console = Console()


def _project_path(config: FwLensConfig) -> Path:
    """The .ewp path, compile_commands.json, or scanned source_dir/proj_dir."""
    return config.project.ewp or config.project.compile_commands or config.project.source_dir or config.project.proj_dir


# ---------------------------------------------------------------------------
# Worker -- runs in a subprocess, must be a module-level function (picklable)
# ---------------------------------------------------------------------------

def _worker(args: tuple) -> tuple:
    """
    Parse one translation unit and return serialisable results.

    Returns:
        (path_str, func_dicts, global_dicts, include_strs, bc_str, iar_group, error_str)
    error_str is None on success, a message string on failure.
    """
    tu_dict, config_path_str = args

    try:
        from pathlib import Path
        from fwlens.config import load_config
        from fwlens.parser.ewp import TranslationUnit
        from fwlens.model.project import BoundaryClass
        from fwlens.parser.ast_walker import walk_translation_unit

        config = load_config(Path(config_path_str))

        tu = TranslationUnit(
            path=Path(tu_dict["path"]),
            defines=tu_dict["defines"],
            include_paths=[Path(p) for p in tu_dict["include_paths"]],
            boundary_class=BoundaryClass(tu_dict["boundary_class"]),
            iar_group=tu_dict["iar_group"],
        )

        functions, globals_, includes, all_include_edges, type_decl_count, file_scope_fn_refs, dispatch_tables_raw, dispatch_table_lines, var_registrations_raw, task_table_entries_raw, diagnostics_raw = walk_translation_unit(tu, config)

        return (
            str(tu.path),
            [f.__dict__ for f in functions],
            [g.__dict__ for g in globals_],
            [str(p) for p in includes],
            all_include_edges,
            str(tu.boundary_class.value),
            tu.iar_group,
            type_decl_count,
            file_scope_fn_refs,
            dispatch_tables_raw,
            dispatch_table_lines,
            var_registrations_raw,
            task_table_entries_raw,
            diagnostics_raw,
            None,  # no error
        )

    except Exception as e:
        return (
            tu_dict.get("path", "?"),
            [], [], [], [],
            tu_dict.get("boundary_class", "unknown"),
            tu_dict.get("iar_group"),
            0,   # type_decl_count
            [],  # file_scope_fn_refs
            {},  # dispatch_tables_raw
            {},  # dispatch_table_lines
            {},  # var_registrations_raw
            [],  # task_table_entries_raw
            [{"severity": "fatal", "message": f"{type(e).__name__}: {e}", "line": 0}],  # diagnostics_raw
            f"{type(e).__name__}: {e}\n{traceback.format_exc()}",
        )


# ---------------------------------------------------------------------------
# Pipeline entry point
# ---------------------------------------------------------------------------

def run_pipeline(config: FwLensConfig) -> ProjectModel:
    """
    Full parse pipeline:
    1.  Parse EWP, compile_commands.json (CMake/Make), or scan directory -- get all TUs
    2.  Classify in-scope vs out-of-scope
    3.  Parse in-scope TUs in parallel with libclang
    4.  Register out-of-scope files as stub modules (no functions)
    5.  Assemble ProjectModel
    """
    if config.project.mode == "directory":
        from fwlens.parser.dirscan import scan_directory
        console.print(f"[cyan][fwlens][/cyan] Scanning directory (no .ewp): "
                      f"[bold]{config.project.source_dir}[/bold]")
        ewp_result = scan_directory(config)
    elif config.project.mode in ("compile_commands", "cmake", "make"):
        from fwlens.parser.compile_commands import parse_compile_commands
        console.print(f"[cyan][fwlens][/cyan] Parsing compilation database ([bold]{config.project.mode}[/bold])...")
        ewp_result = parse_compile_commands(config)
    else:
        console.print("[cyan][fwlens][/cyan] Parsing EWP...")
        # Confirm which ast_walker is loaded -- catches stale .pyc issues
        try:
            from fwlens.parser import ast_walker as _aw
            aw_ver = getattr(_aw, "_MODULE_VERSION", "unknown")
            console.print(f"[dim][fwlens] ast_walker: {aw_ver}  ({_aw.__file__})[/dim]")
        except Exception:
            pass
        ewp_result = parse_ewp(config)

    scope_values = set(config.scope.analyse)
    in_scope  = [tu for tu in ewp_result.source_files if tu.boundary_class.value in scope_values]
    out_scope = [tu for tu in ewp_result.source_files if tu.boundary_class.value not in scope_values]

    console.print(
        f"[cyan][fwlens][/cyan] Found [bold]{len(ewp_result.source_files)}[/bold] source files: "
        f"[green]{len(in_scope)} in scope[/green], "
        f"[dim]{len(out_scope)} excluded (registered as boundary stubs)[/dim]"
    )

    # Validate libclang path before spawning workers
    if config.tool.libclang_path:
        if not config.tool.libclang_path.exists():
            console.print(
                f"[red][fwlens] ERROR: libclang_path not found: {config.tool.libclang_path}[/red]\n"
                f"[red]         Install LLVM and update tool.libclang_path in config.yaml[/red]"
            )
            # Return empty model rather than crashing
            return _empty_model(config, ewp_result, in_scope, out_scope)
    else:
        console.print(
            "[yellow][fwlens] WARNING: tool.libclang_path not set -- "
            "will attempt system libclang (may fail)[/yellow]"
        )

    workers = max(1, (os.cpu_count() or 2) - 1)
    console.print(f"[cyan][fwlens][/cyan] Parsing {len(in_scope)} in-scope files "
                  f"with {workers} worker(s)...")

    tu_dicts = [
        {
            "path":          str(tu.path),
            "defines":       tu.defines,
            "include_paths": [str(p) for p in tu.include_paths],
            "boundary_class": tu.boundary_class.value,
            "iar_group":     tu.iar_group,
        }
        for tu in in_scope
    ]
    config_path_str = str(config.config_path)

    modules:     list[ModuleMetrics] = []
    all_globals: list[GlobalVarInfo] = []
    all_task_table_entries: list[dict] = []
    # Each entry: {"file": str, "short": str, "error_type": str, "full": str}
    parse_errors: list[dict] = []
    parse_ok = 0

    with Progress(
        SpinnerColumn(),
        TextColumn("[cyan][fwlens][/cyan] {task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Parsing files...", total=len(in_scope))

        with ProcessPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(_worker, (tu_dict, config_path_str)): tu_dict
                for tu_dict in tu_dicts
            }
            for future in as_completed(futures):
                try:
                    result = future.result()
                except Exception as e:
                    tu_dict = futures[future]
                    parse_errors.append({
                        "file":       tu_dict.get("path", "?"),
                        "short":      Path(tu_dict.get("path", "?")).name,
                        "error_type": "future-exception",
                        "first_line": f"{type(e).__name__}: {e}",
                        "full":       traceback.format_exc(),
                    })
                    progress.advance(task)
                    continue

                path_str, func_dicts, global_dicts, include_strs, all_include_edges, bc_str, iar_group, type_decl_count, file_scope_fn_refs, dispatch_tables_raw, dispatch_table_lines, var_registrations_raw, task_table_entries_raw, diagnostics_raw, error = result

                if error:
                    first_line = error.splitlines()[0]
                    # Classify error type from first line
                    if "Unknown template argument kind" in first_line:
                        etype = "libclang-unknown-kind"
                    elif "file not found" in first_line:
                        etype = "missing-header"
                    elif "ValueError" in first_line:
                        etype = "binding-error"
                    elif "ImportError" in first_line or "ModuleNotFound" in first_line:
                        etype = "import-error"
                    else:
                        etype = "parse-error"
                    parse_errors.append({
                        "file":       path_str,
                        "short":      Path(path_str).name,
                        "error_type": etype,
                        "first_line": first_line,
                        "full":       error,
                    })
                else:
                    parse_ok += 1

                path = Path(path_str)
                boundary = BoundaryClass(bc_str)

                # Reconstruct FunctionMetrics
                functions: list[FunctionMetrics] = []
                for fd in func_dicts:
                    fm = FunctionMetrics.__new__(FunctionMetrics)
                    fm.__dict__.update(fd)
                    # Ensure Path type
                    fm.file = Path(fd["file"]) if isinstance(fd.get("file"), str) else path
                    # Ensure list fields exist (guard against old pickled dicts)
                    for attr in ("callees", "callers", "global_reads", "global_writes",
                                 "parameters", "magic_numbers"):
                        if not hasattr(fm, attr):
                            setattr(fm, attr, [])
                    functions.append(fm)

                # Reconstruct GlobalVarInfo
                for gd in global_dicts:
                    gv = GlobalVarInfo.__new__(GlobalVarInfo)
                    gv.__dict__.update(gd)
                    gv.file = Path(gd["file"]) if isinstance(gd.get("file"), str) else path
                    all_globals.append(gv)

                includes = [Path(p) for p in include_strs]
                include_edges = [(Path(s), Path(d)) for s, d in all_include_edges]
                for entry in task_table_entries_raw:
                    all_task_table_entries.append({**entry, "file": path})

                file_groups = [iar_group] if iar_group else []
                mm = ModuleMetrics(
                    path=path,
                    boundary_class=boundary,
                    iar_groups=file_groups,
                    functions=functions,
                    function_count=len(functions),
                    includes=includes,
                    all_include_edges=include_edges,
                    loc=sum(f.loc for f in functions),
                    type_decl_count=type_decl_count,
                    file_scope_fn_refs=file_scope_fn_refs,
                    dispatch_tables=dispatch_tables_raw,
                    dispatch_table_lines=dispatch_table_lines,
                    var_registrations=var_registrations_raw,
                    indirect_call_sites=sum(f.indirect_call_count for f in functions),
                    parse_diagnostics=diagnostics_raw,
                )
                modules.append(mm)
                progress.advance(task)

    # Register out-of-scope files as stub modules
    for tu in out_scope:
        file_groups = [tu.iar_group] if tu.iar_group else []
        modules.append(ModuleMetrics(
            path=tu.path,
            boundary_class=tu.boundary_class,
            iar_groups=file_groups,
            functions=[],
            function_count=0,
            includes=[],
            loc=0,
        ))

    # Report parse summary
    total_functions = sum(len(m.functions) for m in modules)
    fail_count = len(parse_errors)
    ok_colour = "green" if fail_count == 0 else ("yellow" if parse_ok > 0 else "red")

    console.print(
        f"[cyan][fwlens][/cyan] Parsed "
        f"[{ok_colour}][bold]{parse_ok}/{len(in_scope)}[/bold][/{ok_colour}] files OK, "
        f"[bold]{total_functions}[/bold] functions extracted"
        + (f", [red]{fail_count} failed[/red]" if fail_count else "")
    )

    if parse_errors:
        # Group by error type
        from collections import Counter
        type_counts = Counter(e["error_type"] for e in parse_errors)

        console.print(f"\n[red][fwlens] Parse failures by type:[/red]")
        type_colours = {
            "libclang-unknown-kind": "yellow",
            "missing-header":        "yellow",
            "binding-error":         "red",
            "import-error":          "red",
            "parse-error":           "dim",
        }
        for etype, count in type_counts.most_common():
            col = type_colours.get(etype, "dim")
            files_of_type = [e["short"] for e in parse_errors if e["error_type"] == etype]
            sample_msg = next(e["first_line"] for e in parse_errors if e["error_type"] == etype)
            console.print(
                f"  [{col}]{etype}[/{col}]  "
                f"[bold]{count}[/bold] file(s)  --  [dim]{sample_msg}[/dim]"
            )
            # Show affected files (up to 8 per type)
            for fname in files_of_type[:8]:
                console.print(f"    [dim]{fname}[/dim]")
            if len(files_of_type) > 8:
                console.print(f"    [dim]... and {len(files_of_type) - 8} more[/dim]")

        # Write full error log
        log_path = config.output.reports_dir.parent / "parse_errors.log"
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(log_path, "w", encoding="utf-8") as lf:
                lf.write(f"fwlens parse error log\n{'='*60}\n\n")
                for e in parse_errors:
                    lf.write(f"FILE: {e['file']}\n")
                    lf.write(f"TYPE: {e['error_type']}\n")
                    lf.write(f"{e['full']}\n{'─'*60}\n\n")
            console.print(f"\n  [dim]Full traces written to: {log_path}[/dim]")
        except Exception as log_err:
            console.print(f"  [dim](Could not write log: {log_err})[/dim]")

        # Actionable hints per error type
        if "libclang-unknown-kind" in type_counts:
            console.print(
                f"\n  [yellow]Hint[/yellow] [bold]libclang-unknown-kind[/bold]: "
                f"LLVM {len(type_counts)} cursor kinds not recognised by the Python bindings. "
                f"These nodes are now skipped gracefully -- re-run to confirm fix is loaded."
            )
        if "missing-header" in type_counts:
            console.print(
                f"\n  [yellow]Hint[/yellow] [bold]missing-header[/bold]: "
                f"Run [cyan].\\Run-FwLens.ps1 debug-parse[/cyan] -- "
                f"missing headers can be auto-stubbed."
            )
        if "import-error" in type_counts:
            console.print(
                f"\n  [red]Hint[/red] [bold]import-error[/bold]: "
                f"A worker process could not import fwlens. "
                f"Check your .venv is active and fwlens is installed."
            )

    if parse_ok == 0 and len(in_scope) > 0:
        console.print(
            "\n[red][fwlens] All files failed to parse. Common causes:[/red]\n"
            "[red]  1. tool.libclang_path is wrong or libclang.dll not found[/red]\n"
            "[red]  2. Source files don't exist at the resolved paths[/red]\n"
            "[red]  3. IAR compat defines are insufficient for this codebase[/red]\n"
            "\n[yellow]Run:  .\\Run-FwLens.ps1 debug-parse  to diagnose[/yellow]"
        )

    model = ProjectModel(
        ewp_path=_project_path(config),
        configuration=ewp_result.configuration_name,
        iar_groups=ewp_result.iar_groups,
        modules=modules,
        globals=all_globals,
        task_table_entries=all_task_table_entries,
    )
    return model


def _empty_model(config, ewp_result, in_scope, out_scope) -> ProjectModel:
    """Return a model with modules registered but no functions -- used on hard errors."""
    modules = []
    for tu in in_scope + out_scope:
        modules.append(ModuleMetrics(
            path=tu.path,
            boundary_class=tu.boundary_class,
            iar_groups=[tu.iar_group] if tu.iar_group else [],
            functions=[], function_count=0, includes=[], loc=0,
        ))
    return ProjectModel(
        ewp_path=_project_path(config),
        configuration=ewp_result.configuration_name,
        iar_groups=ewp_result.iar_groups,
        modules=modules,
        globals=[],
    )