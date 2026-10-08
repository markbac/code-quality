"""
The report's Inputs tab: what FWLens was given. The config file, the project description (IAR,
Keil, CDT, compilation database, CMake or Make output, or a plain directory), the build files
found next to it, how the files were classified, and the settings that shaped the run. It reads
the project description again rather than the analysis, so it also shows files that were out of
scope.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fwlens import __version__
from fwlens.config import FwLensConfig
from fwlens.timing import timer

MAX_CONFIG_BYTES = 200_000
_SKIP = {".git", "build", "__pycache__", ".cache", "node_modules", ".pytest_cache", "output", ".pio", ".venv"}
_BUILD_NAMES = {"cmakelists.txt", "makefile", "gnumakefile", "compile_commands.json", "platformio.ini", ".cproject",
                ".project", "meson.build", "build.ninja", "west.yml", "kconfig"}
_BUILD_SUFFIXES = {".cmake", ".mk", ".ewp", ".eww", ".ewd", ".uvprojx", ".uvproj", ".uvoptx", ".icf", ".ld", ".lds",
                   ".map", ".sct", ".scf", ".mak"}


def _sha(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()[:12]
    except OSError:
        return ""


def _file_row(label: str, path: Path | None, root: Path) -> dict[str, Any] | None:
    if path is None:
        return None
    exists = path.exists()
    try:
        shown = path.relative_to(root).as_posix()
    except ValueError:
        shown = str(path)
    return {"label": label, "path": shown, "exists": exists,
            "size": path.stat().st_size if exists and path.is_file() else None, "sha": _sha(path) if exists and path.is_file() else ""}


def _project_files(config: FwLensConfig, root: Path) -> list[dict]:
    p = config.project
    candidates = [("Project file (.ewp)", p.ewp if p.mode == "ewp" else None),
                  ("Keil project", p.uvprojx), ("Eclipse CDT project", p.cproject),
                  ("Compilation database", p.compile_commands), ("Linker map", p.map_file),
                  ("Source directory", p.source_dir if p.mode == "directory" else None)]
    return [r for r in (_file_row(label, path, root) for label, path in candidates) if r]


def _discover_build_files(config: FwLensConfig, root: Path) -> list[dict]:
    """Build descriptions near the project: CMake, Make, IDE projects, linker scripts and maps."""
    roots = {config.config_path.parent, config.project.proj_dir}
    for extra in (config.project.source_dir, config.project.ewp, config.project.uvprojx, config.project.cproject,
                  config.project.compile_commands):
        if extra is not None:
            roots.add(extra if extra.is_dir() else extra.parent)
    found: dict[Path, dict] = {}
    for base in sorted(roots):
        if not base.is_dir():
            continue
        stack = [(base, 0)]
        while stack and len(found) < 120:
            directory, depth = stack.pop()
            try:
                entries = sorted(directory.iterdir())
            except OSError:
                continue
            for entry in entries:
                if entry.is_dir():
                    if depth < 3 and entry.name not in _SKIP and not entry.name.startswith("."):
                        stack.append((entry, depth + 1))
                elif entry.name.lower() in _BUILD_NAMES or entry.suffix.lower() in _BUILD_SUFFIXES:
                    found.setdefault(entry, {"path": entry, "kind": _kind(entry), "detail": _detail(entry)})
    rows = []
    for path, row in sorted(found.items()):
        try:
            shown = path.relative_to(root).as_posix()
        except ValueError:
            shown = str(path)
        rows.append({"path": shown, "kind": row["kind"], "detail": row["detail"], "size": path.stat().st_size})
    return rows


def _kind(path: Path) -> str:
    n, s = path.name.lower(), path.suffix.lower()
    if n == "cmakelists.txt" or s == ".cmake":
        return "CMake"
    if n in ("makefile", "gnumakefile") or s in (".mk", ".mak"):
        return "Make"
    if n == "compile_commands.json":
        return "Compilation database"
    if s in (".ewp", ".eww", ".ewd"):
        return "IAR Embedded Workbench"
    if s in (".uvprojx", ".uvproj", ".uvoptx"):
        return "Keil uVision"
    if n in (".cproject", ".project"):
        return "Eclipse CDT / STM32CubeIDE"
    if s in (".icf", ".ld", ".lds", ".sct", ".scf"):
        return "Linker script"
    if s == ".map":
        return "Linker map"
    return "Build file"


def _detail(path: Path) -> str:
    """A few facts from the file itself: CMake targets, Make targets, database size."""
    try:
        if path.stat().st_size > 2_000_000:
            return "large file, not read"
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    n = path.name.lower()
    if n == "cmakelists.txt":
        project = re.search(r"^\s*project\s*\(\s*([\w.-]+)", text, re.IGNORECASE | re.MULTILINE)
        targets = re.findall(r"^\s*add_(?:executable|library)\s*\(\s*([\w.-]+)", text, re.IGNORECASE | re.MULTILINE)
        parts = ([f"project {project.group(1)}"] if project else []) + ([f"targets: {', '.join(targets[:6])}"] if targets else [])
        return "; ".join(parts)
    if n in ("makefile", "gnumakefile") or path.suffix.lower() in (".mk", ".mak"):
        targets = [t for t in re.findall(r"^([A-Za-z][\w.-]*)\s*:(?!=)", text, re.MULTILINE) if not t.startswith(".")]
        return f"targets: {', '.join(targets[:8])}" if targets else ""
    if n == "compile_commands.json":
        try:
            return f"{len(json.loads(text))} entries"
        except ValueError:
            return "not valid JSON"
    if path.suffix.lower() == ".ewp":
        names = re.findall(r"<configuration>\s*<name>([^<]+)</name>", text)
        return "configurations: " + ", ".join(names)
    return ""


def _units(config: FwLensConfig):
    from fwlens.parser.pipeline import read_project
    return read_project(config)


def _file_summary(config: FwLensConfig, root: Path) -> dict[str, Any]:
    result = _units(config)
    by_class = Counter(tu.boundary_class.value for tu in result.source_files)
    analyse = set(config.scope.analyse)
    in_scope = sum(1 for tu in result.source_files if tu.boundary_class.value in analyse)
    ext = Counter(tu.path.suffix.lower() or "(none)" for tu in result.source_files)
    includes = Counter(str(p) for tu in result.source_files for p in tu.include_paths)
    defines = Counter(d for tu in result.source_files for d in tu.defines)
    groups = Counter((tu.iar_group or "(no group)") for tu in result.source_files)

    def shown(p) -> str:
        try:
            return Path(p).relative_to(root).as_posix()
        except ValueError:
            return str(p)

    return {
        "total": len(result.source_files), "in_scope": in_scope, "by_class": dict(by_class), "by_extension": dict(ext),
        "configuration": getattr(result, "configuration_name", ""),
        "groups": [{"name": g, "files": n} for g, n in groups.most_common(40)], "group_total": len(groups),
        "include_dirs": [{"path": shown(p), "used_by": n} for p, n in includes.most_common(60)], "include_total": len(includes),
        "defines": [{"define": d, "files": n} for d, n in defines.most_common(60)], "define_total": len(defines),
        "global_defines": list(getattr(result, "global_defines", []))[:80],
    }


def _settings(config: FwLensConfig) -> list[dict[str, str]]:
    s = config.scope
    rows = [
        ("Project mode", config.project.mode), ("Configuration", config.project.configuration or ""),
        ("libclang", str(config.tool.libclang_path) if config.tool.libclang_path else "bundled or LIBCLANG_PATH"),
        ("clang target", config.tool.target or ""),
        ("First-party folders", ", ".join(s.first_party)), ("SDK folders", ", ".join(s.sdk)),
        ("Third-party folders", ", ".join(s.third_party_lib)), ("Analysed", ", ".join(s.analyse)),
        ("Excluded (directory mode)", ", ".join(s.exclude)),
        ("Compat defines", f"{len(config.iar_compat_defines)} injected into every file"),
        ("Entry points", ", ".join(config.entry_points)), ("Layers", ", ".join(layer.name for layer in config.layers)),
        ("RTOS", config.rtos.kind), ("Output formats", ", ".join(config.output.formats)),
        ("Standards", ", ".join(e.standard + (f" [{', '.join(e.include_categories)}]" if e.include_categories else "")
                                for e in config.standards.enabled) or "none"),
        ("Imported results", ", ".join(f"{tool}: {path.name}" for tool, path in config.standards.imports) or "none"),
        ("Deviations file", str(config.standards.deviations_file or "none")),
        ("SBOM components file", str(config.sbom.components_file or "none")),
        ("CBOM scan scopes", ", ".join(config.cbom.scan_scopes)),
        ("Git history", f"since {config.git.since}" if getattr(config.git, "since", None) else "full history"),
    ]
    return [{"label": a, "value": b} for a, b in rows if b != ""]


def inputs_view(config: FwLensConfig) -> dict[str, Any]:
    root = config.config_path.parent
    try:
        raw = config.config_path.read_bytes()
        text = raw[:MAX_CONFIG_BYTES].decode("utf-8", errors="replace")
        truncated = len(raw) > MAX_CONFIG_BYTES
        sha = hashlib.sha256(raw).hexdigest()[:12]
    except OSError:
        text, truncated, sha = "", False, ""
    out: dict[str, Any] = {
        "version": __version__, "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "config_path": str(config.config_path), "config_sha": sha, "config_text": text, "config_truncated": truncated,
        "warnings": list(config.warnings), "project_files": _project_files(config, root), "settings": _settings(config),
        "build_files": [], "files": None, "error": "", "timing": timer.as_dict() if timer.phases else None,
    }
    try:
        out["build_files"] = _discover_build_files(config, root)
        out["files"] = _file_summary(config, root)
    except Exception as exc:                      # a project description that cannot be read must not lose the report
        out["error"] = f"{type(exc).__name__}: {exc}"
    return out
