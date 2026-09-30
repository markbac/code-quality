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

from dataclasses import dataclass
from pathlib import Path

from fwlens.config import FwLensConfig
from fwlens.model.project import BoundaryClass, IARGroup
from fwlens.parser.ewp import TranslationUnit


@dataclass
class DirScanResult:
    source_files: list[TranslationUnit]
    iar_groups: dict[str, IARGroup]
    configuration_name: str


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

    # No scope rule matched any path segment under source_dir -- default to
    # first_party so pointing fwlens at a bare folder analyses everything.
    return BoundaryClass.FIRST_PARTY


def scan_directory(config: FwLensConfig) -> DirScanResult:
    source_dir = config.project.source_dir

    c_files = sorted(source_dir.rglob("*.c"))
    include_dirs = sorted({p.parent for p in source_dir.rglob("*.h")} | {source_dir})

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
    )
