"""
Directory-scan mode -- build a synthetic project without any IAR .ewp file.

Recursively globs `project.source_dir` for `*.c` files, the same "just point
it at a folder" approach the older code_governance toolkit used with
ccccc/scc directly on a directory of C sources. There's no compile database
to draw per-file include paths and defines from, so every directory
containing a header is added as an include path for every translation unit --
blunt, but workable for a single-configuration codebase without a full IAR
project.

Produces a `DirScanResult` shaped like `fwlens.parser.ewp.EWPParseResult`
(same `source_files` / `configuration_name` / `iar_groups` attributes) so
`fwlens.parser.pipeline.run_pipeline` can consume either without change.
There is no IAR group tree in this mode, so `iar_groups` is always empty and
layer assignment falls back to path-based matching only.
"""

from __future__ import annotations

import fnmatch
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from rich.console import Console

from fwlens.config import FwLensConfig
from fwlens.model.project import BoundaryClass, IARGroup
from fwlens.parser.ewp import TranslationUnit

console = Console()

_INCLUDE_RE = re.compile(r'^[ \t]*#[ \t]*include[ \t]*[<"]([^>"\n]+)[>"]', re.MULTILINE)
_DEFAULT_IGNORED_DIRS = {".git", "build", "__pycache__", ".cache", "node_modules", ".pytest_cache"}


def _is_excluded(path: Path, source_dir: Path, exclude_patterns: list[str]) -> bool:
    try:
        rel_path = path.relative_to(source_dir).as_posix()
    except ValueError:
        rel_path = path.as_posix()

    for part in path.parts:
        if part in _DEFAULT_IGNORED_DIRS:
            return True

    for pattern in exclude_patterns:
        if fnmatch.fnmatch(rel_path, pattern) or fnmatch.fnmatch(path.name, pattern):
            return True
    return False


@dataclass
class DirScanResult:
    source_files: list[TranslationUnit]
    iar_groups: dict[str, IARGroup]
    configuration_name: str
    warnings: list[str] = field(default_factory=list)


def _classify_boundary(path: Path, source_dir: Path, config: FwLensConfig) -> BoundaryClass:
    try:
        rel_parts = [p.lower() for p in path.relative_to(source_dir).parts]
    except ValueError:
        rel_parts = [p.lower() for p in path.parts]

    fp  = [s.lower() for s in config.scope.first_party]
    sdk = [s.lower() for s in config.scope.sdk]
    lib = [s.lower() for s in config.scope.third_party_lib]

    for part in rel_parts:
        if part in fp:
            return BoundaryClass.FIRST_PARTY
        if part in sdk:
            return BoundaryClass.SDK
        if part in lib:
            return BoundaryClass.THIRD_PARTY_LIB

    return BoundaryClass.FIRST_PARTY


def _includes_of(path: Path) -> list[str]:
    try:
        return _INCLUDE_RE.findall(path.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return []


def _used_include_dirs(c_files: list[Path], headers: list[Path], source_dir: Path) -> tuple[list[Path], set[str]]:
    """
    Include directories reached from the in-scope .c files through #include, following headers
    transitively. A directory is kept when it holds a header named by some include, with any
    leading path of the include accounted for (`#include "drv/uart.h"` keeps the directory that
    contains drv/uart.h). Returns the directories and every include name that was followed.
    """
    by_name: dict[str, list[Path]] = defaultdict(list)
    for h in headers:
        by_name[h.name].append(h)

    dirs: set[Path] = {source_dir}
    seen_names: set[str] = set()
    seen_headers: set[Path] = set()
    queue = list(c_files)
    while queue:
        for name in _includes_of(queue.pop()):
            seen_names.add(name)
            tail = "/" + name.replace("\\", "/")
            for h in by_name.get(Path(name).name, []):
                posix = h.as_posix()
                if not posix.endswith(tail):
                    continue
                dirs.add(Path(posix[: -len(tail)]))
                if h not in seen_headers:
                    seen_headers.add(h)
                    queue.append(h)
    return sorted(dirs), seen_names


def _duplicate_header_warnings(include_dirs: list[Path], included: set[str], source_dir: Path,
                               other_dirs: list[Path] = ()) -> list[str]:
    """
    One warning per included header name found in several directories. `include_dirs` is the
    search path, in order; `other_dirs` are header directories in the tree that are not on it,
    so the warning can also name the copies that an explicit include_dirs leaves out.
    """
    found: dict[str, list[Path]] = defaultdict(list)
    for d in [*include_dirs, *[o for o in other_dirs if o not in include_dirs]]:
        try:
            names = sorted(p.name for p in d.iterdir() if p.is_file() and p.suffix in (".h", ".hpp"))
        except OSError:
            continue
        for n in names:
            found[n].append(d)

    def rel(d: Path) -> str:
        try:
            return d.relative_to(source_dir).as_posix() or "."
        except ValueError:
            return str(d)

    out = []
    for name, dirs in sorted(found.items()):
        if len(dirs) > 1 and dirs[0] in include_dirs and name in {Path(i).name for i in included}:
            out.append(f"Header '{name}' exists in {len(dirs)} directories; "
                       f"'{rel(dirs[0])}' wins (searched first), ignored: "
                       + ", ".join(f"'{rel(d)}'" for d in dirs[1:])
                       + ". Pick one with project.include_dirs or scope.exclude.")
    return out


def scan_directory(config: FwLensConfig) -> DirScanResult:
    source_dir = config.project.source_dir
    exclude_patterns = getattr(config.scope, "exclude", []) or []

    c_files = [
        p for p in sorted(source_dir.rglob("*.c"))
        if not _is_excluded(p, source_dir, exclude_patterns)
    ]
    headers = [p for p in sorted(source_dir.rglob("*.h")) if not _is_excluded(p.parent, source_dir, exclude_patterns)]

    if config.project.include_dirs:
        include_dirs = list(config.project.include_dirs)
        included = {n for f in c_files for n in _includes_of(f)}
        included |= {n for h in headers for n in _includes_of(h)}
    elif config.project.include_mode == "used":
        include_dirs, included = _used_include_dirs(c_files, headers, source_dir)
    else:
        include_dirs = sorted({h.parent for h in headers} | {source_dir})
        included = {n for f in c_files for n in _includes_of(f)}
        included |= {n for h in headers for n in _includes_of(h)}

    other = sorted({h.parent for h in headers})
    warnings = _duplicate_header_warnings(include_dirs, included, source_dir, other)
    for w in warnings:
        console.print(f"[yellow][fwlens] {w}[/yellow]")

    source_files = [
        TranslationUnit(
            path=path,
            defines=list(config.iar_compat_defines),
            include_paths=list(include_dirs),
            boundary_class=_classify_boundary(path, source_dir, config),
            iar_group=None,
        )
        for path in c_files
    ]

    return DirScanResult(
        source_files=source_files,
        iar_groups={},
        configuration_name="directory-scan",
        warnings=warnings,
    )
