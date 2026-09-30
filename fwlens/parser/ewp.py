"""
IAR Embedded Workbench .ewp parser.

Extracts:
- IAR group tree (preserved as first-class model entity)
- Source files with per-file configuration overrides
- Global and per-file preprocessor defines
- Include paths
- Build configurations

Handles:
- $PROJ_DIR$ and $TOOLKIT_DIR$ variable expansion (Windows paths)
- no_X IAR negation define pattern
- Per-file <settings> override blocks
- Multiple build configurations
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from fwlens.config import FwLensConfig
from fwlens.model.project import BoundaryClass, IARGroup


@dataclass
class TranslationUnit:
    path: Path
    defines: list[str]
    include_paths: list[Path]
    boundary_class: BoundaryClass
    iar_group: Optional[str]


@dataclass
class EWPParseResult:
    source_files: list[TranslationUnit]
    iar_groups: dict[str, IARGroup]
    global_defines: list[str]
    global_includes: list[Path]
    configuration_name: str


def _expand_path(raw: str, proj_dir: Path, toolkit_dir: Optional[Path]) -> Optional[Path]:
    """
    Expand IAR workspace variables and normalise to a Path.
    Returns None if the path cannot be resolved (e.g. unknown variable).
    """
    if not raw or not raw.strip():
        return None

    s = raw.strip()

    # Replace IAR variables using plain string replacement (re.sub treats
    # Windows backslashes in the replacement string as escape sequences).
    s_lower = s.lower()
    if '$proj_dir$' in s_lower:
        idx = s_lower.index('$proj_dir$')
        s = s[:idx] + str(proj_dir).replace('\\', '/') + s[idx + len('$proj_dir$'):]
    if '$toolkit_dir$' in s.lower():
        if toolkit_dir:
            s_lower2 = s.lower()
            idx = s_lower2.index('$toolkit_dir$')
            s = s[:idx] + str(toolkit_dir).replace('\\', '/') + s[idx + len('$toolkit_dir$'):]
        else:
            return None  # can't resolve without toolkit_dir

    # Remaining unknown variables -- skip
    if '$' in s:
        return None

    # Normalise separators and collapse .. segments.
    # os.path.normpath handles .. traversal without requiring the path to exist.
    try:
        import os
        return Path(os.path.normpath(s.replace("\\", "/")))
    except Exception:
        return None


def _classify_boundary(path: Path, config: FwLensConfig) -> BoundaryClass:
    """
    Classify a file path into a boundary class based on scope config.

    Tries relative_to(proj_dir) first for a clean top-segment match.
    Falls back to scanning all path parts when the file is outside proj_dir
    (e.g. $PROJ_DIR$\\..\\.\\Src\\... resolves to a sibling directory).
    """
    proj_dir = config.project.proj_dir

    # Attempt 1: file is under proj_dir
    try:
        rel = path.relative_to(proj_dir)
        top = rel.parts[0].lower() if rel.parts else ""
        for fragment in config.scope.first_party:
            if top == fragment.lower():
                return BoundaryClass.FIRST_PARTY
        for fragment in config.scope.sdk:
            if top == fragment.lower():
                return BoundaryClass.SDK
        for fragment in config.scope.third_party_lib:
            if top == fragment.lower():
                return BoundaryClass.THIRD_PARTY_LIB
        return BoundaryClass.UNKNOWN
    except ValueError:
        pass

    # Attempt 2: file is outside proj_dir (resolved via ..).
    # Walk up proj_dir's ancestors until we find one that is a parent of path,
    # then check the first diverging segment. Use PureWindowsPath to ensure
    # correct path parsing on the Windows target regardless of host OS.
    from pathlib import PureWindowsPath
    try:
        wp = PureWindowsPath(path)
        candidate = PureWindowsPath(proj_dir).parent
        for _ in range(8):
            try:
                rel = wp.relative_to(candidate)
                top = rel.parts[0].lower() if rel.parts else ""
                for fragment in config.scope.first_party:
                    if top == fragment.lower():
                        return BoundaryClass.FIRST_PARTY
                for fragment in config.scope.sdk:
                    if top == fragment.lower():
                        return BoundaryClass.SDK
                for fragment in config.scope.third_party_lib:
                    if top == fragment.lower():
                        return BoundaryClass.THIRD_PARTY_LIB
                break
            except ValueError:
                candidate = candidate.parent
    except Exception:
        pass

    return BoundaryClass.UNKNOWN


def _extract_defines(settings_el: ET.Element) -> list[str]:
    defines = []
    for opt in settings_el.iter("option"):
        name_el = opt.find("name")
        if name_el is not None and name_el.text == "CCDefines":
            for state in opt.findall("state"):
                if state.text and state.text.strip():
                    defines.append(state.text.strip())
    return defines


def _extract_includes(settings_el: ET.Element, proj_dir: Path,
                      toolkit_dir: Optional[Path]) -> list[Path]:
    includes = []
    for opt in settings_el.iter("option"):
        name_el = opt.find("name")
        if name_el is not None and name_el.text == "CCIncludePath2":
            for state in opt.findall("state"):
                if state.text and state.text.strip():
                    p = _expand_path(state.text.strip(), proj_dir, toolkit_dir)
                    if p is not None:
                        includes.append(p)
    return includes


def _resolve_no_x_defines(defines: list[str]) -> list[str]:
    """
    Apply IAR no_X negation convention.
    A define of no_FOO means FOO is logically off -- remove FOO if present,
    and do not emit no_FOO as a define (it is not a truthy symbol).
    """
    positive = {d.split("=")[0] for d in defines if not d.startswith("no_")}
    negated = {d[3:].split("=")[0] for d in defines if d.startswith("no_")}
    result = []
    for d in defines:
        key = d.split("=")[0]
        if d.startswith("no_"):
            continue  # drop no_X entries
        if key in negated:
            continue  # this positive define is negated
        result.append(d)
    return result


def _walk_groups(
    el: ET.Element,
    parent_name: Optional[str],
    groups: dict[str, IARGroup],
    proj_dir: Path,
    toolkit_dir: Optional[Path],
    global_defines: list[str],
    global_includes: list[Path],
    config: FwLensConfig,
    translation_units: list[TranslationUnit],
):
    """Recursively walk <group> elements, building IARGroup tree and TU list."""
    for child in el:
        if child.tag == "group":
            name_el = child.find("name")
            group_name = name_el.text if name_el is not None else "unnamed"

            if group_name not in groups:
                groups[group_name] = IARGroup(name=group_name, parent=parent_name)
            if parent_name and parent_name in groups:
                if group_name not in groups[parent_name].children:
                    groups[parent_name].children.append(group_name)

            _walk_groups(child, group_name, groups, proj_dir, toolkit_dir,
                         global_defines, global_includes, config, translation_units)

        elif child.tag == "file":
            name_el = child.find("name")
            if name_el is None or not name_el.text:
                continue
            path = _expand_path(name_el.text.strip(), proj_dir, toolkit_dir)
            if path is None:
                continue
            if path.suffix.lower() not in (".c",):
                continue  # only parse .c files

            # Check for per-file settings override
            file_defines = list(global_defines)
            file_includes = list(global_includes)
            for settings in child.findall("configuration"):
                cfg_name_el = settings.find("name")
                if cfg_name_el is not None:
                    # per-file per-config override -- extract and merge
                    override_defines = _extract_defines(settings)
                    override_includes = _extract_includes(settings, proj_dir, toolkit_dir)
                    if override_defines:
                        # Per-file defines are MERGED with globals, not a replacement.
                        # IAR per-file settings add or override specific defines;
                        # the global list still applies for everything else.
                        seen = {d.split('=')[0] for d in file_defines}
                        for d in override_defines:
                            key = d.split('=')[0]
                            if key not in seen:
                                file_defines.append(d)
                                seen.add(key)
                    if override_includes:
                        # Per-file includes are MERGED with globals, not a replacement.
                        # IAR per-file settings add extra paths; the global list still applies.
                        seen = {str(p) for p in file_includes}
                        for p in override_includes:
                            if str(p) not in seen:
                                file_includes.append(p)
                                seen.add(str(p))

            boundary = _classify_boundary(path, config)

            tu = TranslationUnit(
                path=path,
                defines=_resolve_no_x_defines(file_defines),
                include_paths=file_includes,
                boundary_class=boundary,
                iar_group=parent_name,
            )
            translation_units.append(tu)

            if parent_name and parent_name in groups:
                groups[parent_name].files.append(path)


def parse_ewp(config: FwLensConfig) -> EWPParseResult:
    """
    Parse the IAR .ewp file specified in config and return a structured result.
    """
    ewp_path = config.project.ewp
    proj_dir = config.project.proj_dir
    toolkit_dir = config.project.toolkit_dir
    target_config = config.project.configuration

    if not ewp_path.exists():
        raise FileNotFoundError(f"EWP file not found: {ewp_path}")

    tree = ET.parse(ewp_path)
    root = tree.getroot()

    # Find the target configuration block for global settings
    target_config_el = None
    for cfg in root.findall("configuration"):
        name_el = cfg.find("name")
        if name_el is not None and name_el.text == target_config:
            target_config_el = cfg
            break

    if target_config_el is None:
        available = [
            cfg.find("name").text
            for cfg in root.findall("configuration")
            if cfg.find("name") is not None
        ]
        raise ValueError(
            f"Configuration '{target_config}' not found in EWP. "
            f"Available: {available}"
        )

    # Extract global defines and includes from the target configuration.
    # Pass raw defines straight through -- do not strip no_X entries.
    # The firmware uses #ifdef no_X patterns directly, so stripping them
    # would cause libclang to take the wrong #if branches.
    global_defines = _extract_defines(target_config_el)
    global_includes = _extract_includes(target_config_el, proj_dir, toolkit_dir)

    # Walk the file/group tree
    groups: dict[str, IARGroup] = {}
    translation_units: list[TranslationUnit] = []

    _walk_groups(
        root, None, groups, proj_dir, toolkit_dir,
        global_defines, global_includes, config, translation_units,
    )

    # Also pick up top-level <file> entries (outside any group)
    for file_el in root.findall("file"):
        name_el = file_el.find("name")
        if name_el is None or not name_el.text:
            continue
        path = _expand_path(name_el.text.strip(), proj_dir, toolkit_dir)
        if path is None or path.suffix.lower() != ".c":
            continue
        boundary = _classify_boundary(path, config)
        tu = TranslationUnit(
            path=path,
            defines=list(global_defines),
            include_paths=list(global_includes),
            boundary_class=boundary,
            iar_group=None,
        )
        translation_units.append(tu)

    # Deduplicate (same path may appear in multiple groups)
    seen: set[Path] = set()
    unique_tus = []
    for tu in translation_units:
        if tu.path not in seen:
            seen.add(tu.path)
            unique_tus.append(tu)

    return EWPParseResult(
        source_files=unique_tus,
        iar_groups=groups,
        global_defines=global_defines,
        global_includes=global_includes,
        configuration_name=target_config,
    )