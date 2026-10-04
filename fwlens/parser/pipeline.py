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
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn

from fwlens.config import FwLensConfig
from fwlens.model.project import (
    BoundaryClass,
    FunctionMetrics,
    GlobalVarInfo,
    ModuleMetrics,
    ProjectModel,
)
from fwlens.parser.ewp import parse_ewp

console = Console()


def _project_path(config: FwLensConfig) -> Path:
    """The .ewp path, compile_commands.json, or scanned source_dir/proj_dir."""
    return config.project.ewp or config.project.compile_commands or config.project.source_dir or config.project.proj_dir


# ---------------------------------------------------------------------------
# Worker -- runs in a child process; parse functions must be module-level
# ---------------------------------------------------------------------------

def _failure_result(tu_dict: dict, first_line: str, full: str) -> tuple:
    """A worker result tuple describing a file that could not be parsed."""
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
        [{"severity": "fatal", "message": first_line, "line": 0}],  # diagnostics_raw
        f"{first_line}\n{full}",
    )


def _parse_one(tu_dict: dict, config: FwLensConfig) -> tuple:
    """
    Parse one translation unit with the already-loaded config and return serialisable results.

    Returns a 15-tuple whose last element is None on success or an error string on failure.
    """
    try:
        from fwlens.model.project import BoundaryClass
        from fwlens.parser.ast_walker import walk_translation_unit
        from fwlens.parser.ewp import TranslationUnit

        tu = TranslationUnit(
            path=Path(tu_dict["path"]),
            defines=tu_dict["defines"],
            include_paths=[Path(p) for p in tu_dict["include_paths"]],
            boundary_class=BoundaryClass(tu_dict["boundary_class"]),
            iar_group=tu_dict["iar_group"],
            extra_args=list(tu_dict.get("extra_args", [])),
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
        return _failure_result(tu_dict, f"{type(e).__name__}: {e}", traceback.format_exc())


def _worker_main(conn, config: FwLensConfig, parse_fn) -> None:
    """Child process loop: announce readiness, then parse tasks until told to stop."""
    conn.send("ready")
    while True:
        try:
            tu_dict = conn.recv()
        except EOFError:
            return
        if tu_dict is None:
            return
        conn.send(parse_fn(tu_dict, config))


class _Slot:
    def __init__(self):
        self.proc = None
        self.conn = None
        self.ready = False
        self.task: Optional[dict] = None
        self.deadline: Optional[float] = None


def _start(slot: _Slot, ctx, config: FwLensConfig, parse_fn) -> None:
    parent, child = ctx.Pipe()
    slot.proc = ctx.Process(target=_worker_main, args=(child, config, parse_fn), daemon=True)
    slot.proc.start()
    child.close()
    slot.conn = parent
    slot.ready = False
    slot.task = None
    slot.deadline = None


def _stop(slot: _Slot, kill: bool = False) -> None:
    try:
        if slot.proc is not None and slot.proc.is_alive():
            if kill:
                slot.proc.kill()
            else:
                try:
                    slot.conn.send(None)
                except (OSError, BrokenPipeError):
                    pass
            slot.proc.join(timeout=5)
            if slot.proc.is_alive():
                slot.proc.kill()
                slot.proc.join(timeout=5)
    finally:
        if slot.conn is not None:
            slot.conn.close()


def _parse_parallel(tu_dicts: list[dict], config: FwLensConfig, workers: int,
                    timeout: Optional[float], parse_fn=_parse_one):
    """
    Parse translation units in persistent worker processes and yield (tu_dict, result).

    The config is pickled once per worker. A task that exceeds `timeout` seconds, or whose
    worker dies, is reported as a failure and its worker is killed and replaced, so one
    hung or crashing libclang parse cannot stall or take down the run.
    """
    import multiprocessing
    import time
    from collections import deque
    from multiprocessing.connection import wait

    if not tu_dicts:
        return

    ctx = multiprocessing.get_context("spawn")
    pending = deque(tu_dicts)
    slots = [_Slot() for _ in range(max(1, min(workers, len(tu_dicts))))]
    for s in slots:
        _start(s, ctx, config, parse_fn)

    try:
        outstanding = len(tu_dicts)
        while outstanding:
            for s in slots:
                if s.ready and s.task is None and pending:
                    s.task = pending.popleft()
                    s.deadline = time.monotonic() + timeout if timeout else None
                    s.conn.send(s.task)

            now = time.monotonic()
            deadlines = [s.deadline - now for s in slots if s.deadline is not None]
            wait_for = max(0.0, min(deadlines)) if deadlines else None
            wait([s.conn for s in slots] + [s.proc.sentinel for s in slots], timeout=wait_for)

            now = time.monotonic()
            for s in slots:
                msg, crashed = None, False
                try:
                    if s.conn.poll():
                        msg = s.conn.recv()
                except (EOFError, OSError):
                    crashed = True

                if msg == "ready":
                    s.ready = True
                    continue
                if msg is not None:
                    task, s.task, s.deadline = s.task, None, None
                    outstanding -= 1
                    yield task, msg
                    continue

                if not crashed and s.proc.is_alive():
                    if s.task is not None and s.deadline is not None and now >= s.deadline:
                        task = s.task
                        _stop(s, kill=True)
                        _start(s, ctx, config, parse_fn)
                        outstanding -= 1
                        yield task, _failure_result(
                            task, f"TimeoutError: parse exceeded {timeout:g}s",
                            "The parse was terminated. Raise the limit with --timeout or "
                            "tool.parse_timeout, or investigate the file.")
                    continue

                # The worker exited. If it was parsing something, that file is the cause.
                task = s.task
                code = s.proc.exitcode
                _stop(s, kill=True)
                _start(s, ctx, config, parse_fn)
                if task is not None:
                    outstanding -= 1
                    yield task, _failure_result(
                        task, f"WorkerCrash: parser process exited unexpectedly (exit code {code})",
                        "libclang probably crashed on this file.")
    finally:
        for s in slots:
            _stop(s)


# ---------------------------------------------------------------------------
# Parse cache -- keyed by everything that can change a file's parse result
# ---------------------------------------------------------------------------

_CACHE_SCHEMA = 1


def _sha(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()


def _file_sha(path: str, memo: dict) -> Optional[str]:
    if path not in memo:
        try:
            memo[path] = _sha(Path(path).read_bytes())
        except OSError:
            memo[path] = None
    return memo[path]


def _parse_settings(tool) -> tuple:
    """The ToolConfig fields that change what clang sees (not jobs, timeout or caching)."""
    return (tool.libclang_path, tool.target, tool.sysroot, tool.system_include_dirs,
            tool.clang_args, tool.auto_detect_includes)


def _cache_context(config: FwLensConfig, libclang_path) -> str:
    """Digest of the settings, other than the file itself, that affect parsing."""
    from fwlens import __version__

    lib_id = "default"
    if libclang_path:
        try:
            st = Path(libclang_path).stat()
            lib_id = f"{libclang_path}:{st.st_size}:{st.st_mtime_ns}"
        except OSError:
            lib_id = str(libclang_path)
    parts = (
        _CACHE_SCHEMA, __version__, lib_id, repr(_parse_settings(config.tool)), repr(config.iar_compat_defines),
        repr(getattr(config, "assert_names", None)), repr(getattr(config, "rtos", None)),
        str(config.config_path.parent),
    )
    return _sha(repr(parts).encode())


class ParseCache:
    """On-disk cache of per-file worker results, validated against header contents."""

    def __init__(self, directory: Path, context: str):
        self.dir = Path(directory) / "parse"
        self.context = context
        self._memo: dict = {}
        self.hits = 0

    def _entry_path(self, tu_dict: dict) -> Path:
        src_sha = _file_sha(tu_dict["path"], self._memo) or "missing"
        key = repr((self.context, tu_dict["path"], src_sha, tu_dict["defines"],
                    tu_dict["include_paths"], tu_dict.get("extra_args", []),
                    tu_dict["boundary_class"], tu_dict["iar_group"]))
        return self.dir / f"{_sha(key.encode())}.pkl"

    def get(self, tu_dict: dict) -> Optional[tuple]:
        import pickle
        try:
            with open(self._entry_path(tu_dict), "rb") as fh:
                entry = pickle.load(fh)
            for header, digest in entry["headers"].items():
                if _file_sha(header, self._memo) != digest:
                    return None
            self.hits += 1
            return entry["result"]
        except Exception:
            return None

    def put(self, tu_dict: dict, result: tuple) -> None:
        """Store a clean result. Failures and results with errors are never cached."""
        import pickle
        error, diagnostics = result[-1], result[13]
        if error or any(d.get("severity") in ("fatal", "error") for d in diagnostics or []):
            return
        headers = {}
        for edge in result[4]:
            for p in edge:
                if p != tu_dict["path"]:
                    headers[str(p)] = _file_sha(str(p), self._memo)
        for p in result[3]:
            headers.setdefault(str(p), _file_sha(str(p), self._memo))
        if any(v is None for v in headers.values()):
            return
        try:
            path = self._entry_path(tu_dict)
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(f".{os.getpid()}.tmp")
            with open(tmp, "wb") as fh:
                pickle.dump({"result": result, "headers": headers}, fh)
            os.replace(tmp, path)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Pipeline entry point
# ---------------------------------------------------------------------------

def run_pipeline(config: FwLensConfig, jobs: Optional[int] = None,
                 timeout: Optional[float] = None, use_cache: Optional[bool] = None,
                 _parse_fn=_parse_one) -> ProjectModel:
    """
    Full parse pipeline:
    1.  Parse EWP, compile_commands.json (CMake/Make), or scan directory -- get all TUs
    2.  Classify in-scope vs out-of-scope
    3.  Parse in-scope TUs in parallel with libclang
    4.  Register out-of-scope files as stub modules (no functions)
    5.  Assemble ProjectModel

    `jobs`, `timeout` (seconds per file, 0 disables) and `use_cache` override
    `tool.jobs`, `tool.parse_timeout` and `tool.parse_cache` when given.
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

    # Resolve libclang once, with the same rules the parser uses, before spawning workers.
    # A wrong explicit path is an error: an empty model could otherwise pass a breach
    # gate with nothing analysed (issue #26).
    from fwlens.libclang_locate import LibclangError, locate_libclang
    try:
        location = locate_libclang(config.tool.libclang_path)
    except LibclangError as e:
        raise RuntimeError(str(e)) from e
    console.print(f"[dim][fwlens] libclang: {location.path or 'system default'} ({location.source})[/dim]")

    if jobs is None:
        jobs = config.tool.jobs
    workers = max(1, jobs) if jobs else max(1, (os.cpu_count() or 2) - 1)
    if timeout is None:
        timeout = config.tool.parse_timeout
    if use_cache is None:
        use_cache = config.tool.parse_cache

    tu_dicts = [
        {
            "path":          str(tu.path),
            "defines":       tu.defines,
            "include_paths": [str(p) for p in tu.include_paths],
            "boundary_class": tu.boundary_class.value,
            "iar_group":     tu.iar_group,
            "extra_args":    list(tu.extra_args),
        }
        for tu in in_scope
    ]

    cache = ParseCache(config.output.cache_dir, _cache_context(config, location.path)) if use_cache else None
    cached: list[tuple[dict, tuple]] = []
    to_parse = tu_dicts
    if cache is not None:
        to_parse = []
        for tu_dict in tu_dicts:
            hit = cache.get(tu_dict)
            if hit is not None:
                cached.append((tu_dict, hit))
            else:
                to_parse.append(tu_dict)

    console.print(f"[cyan][fwlens][/cyan] Parsing {len(to_parse)} in-scope files "
                  f"with {workers} worker(s)"
                  + (f", {len(cached)} from cache" if cached else "")
                  + (f", {timeout:g}s limit per file" if timeout else "") + "...")

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

        def _results():
            yield from cached
            for tu_dict, result in _parse_parallel(to_parse, config, workers, timeout, _parse_fn):
                if cache is not None:
                    cache.put(tu_dict, result)
                yield tu_dict, result

        for tu_dict, result in _results():
            path_str, func_dicts, global_dicts, include_strs, all_include_edges, bc_str, iar_group, type_decl_count, file_scope_fn_refs, dispatch_tables_raw, dispatch_table_lines, var_registrations_raw, task_table_entries_raw, diagnostics_raw, error = result

            if error:
                first_line = error.splitlines()[0]
                # Classify error type from first line
                if first_line.startswith("TimeoutError"):
                    etype = "timeout"
                elif first_line.startswith("WorkerCrash"):
                    etype = "worker-crash"
                elif "Unknown template argument kind" in first_line:
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

    # A file can "parse" yet carry fatal or error diagnostics (missing system headers,
    # unresolved macros), so its metrics are partial. Count those separately instead of
    # reporting them as OK (issue #48).
    files_with_errors = 0
    fatal_diagnostics = 0
    for m in modules:
        sevs = [d.get("severity") for d in (m.parse_diagnostics or [])]
        if any(sv in ("fatal", "error") for sv in sevs):
            files_with_errors += 1
        fatal_diagnostics += sum(1 for sv in sevs if sv == "fatal")
    parse_stats = {
        "in_scope": len(in_scope),
        "parsed_ok": parse_ok,
        "failed": fail_count,
        "files_with_errors": files_with_errors,
        "fatal_diagnostics": fatal_diagnostics,
    }
    if files_with_errors:
        ok_colour = "yellow" if ok_colour == "green" else ok_colour

    console.print(
        f"[cyan][fwlens][/cyan] Parsed "
        f"[{ok_colour}][bold]{parse_ok}/{len(in_scope)}[/bold][/{ok_colour}] files, "
        f"[bold]{total_functions}[/bold] functions extracted"
        + (f", [red]{fail_count} failed[/red]" if fail_count else "")
        + (f", [yellow]{files_with_errors} with fatal/error diagnostics[/yellow]" if files_with_errors else "")
    )
    if files_with_errors:
        console.print(
            "[yellow][fwlens] Metrics for files with errors are partial. Common cause: system headers "
            "not found. Set tool.target (use 'native' for host builds), tool.system_include_dirs or "
            "tool.clang_args. Use --fail-on-parse-error to gate on this.[/yellow]"
        )

    if parse_errors:
        # Group by error type
        from collections import Counter
        type_counts = Counter(e["error_type"] for e in parse_errors)

        console.print("\n[red][fwlens] Parse failures by type:[/red]")
        type_colours = {
            "libclang-unknown-kind": "yellow",
            "missing-header":        "yellow",
            "timeout":               "red",
            "worker-crash":          "red",
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
                "\n  [yellow]Hint[/yellow] [bold]missing-header[/bold]: "
                "Run [cyan].\\Run-FwLens.ps1 debug-parse[/cyan] -- "
                "missing headers can be auto-stubbed."
            )
        if "import-error" in type_counts:
            console.print(
                "\n  [red]Hint[/red] [bold]import-error[/bold]: "
                "A worker process could not import fwlens. "
                "Check your .venv is active and fwlens is installed."
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
    model.parse_stats = parse_stats
    model.translation_units = list(in_scope)
    return model
