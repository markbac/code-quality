"""
Readers for IDE project files other than IAR: Keil uVision (.uvprojx) and Eclipse CDT /
STM32CubeIDE (.cproject). Each produces the same result type as the .ewp reader, so the rest
of the pipeline does not care where the translation units came from.

Both read the settings an IDE stores per target or configuration: preprocessor defines,
include paths and the files to build. They do not run the IDE's compiler, so compiler built-in
defines and flags kept elsewhere (a custom -D in a Keil "Misc controls" box, a toolchain
sysroot) are not seen. Set `tool.sysroot` / `tool.system_include_dirs` for those.
"""

from __future__ import annotations

import os
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from fwlens.config import FwLensConfig
from fwlens.model.project import IARGroup
from fwlens.parser.ewp import EWPParseResult, TranslationUnit, _classify_boundary

_C_SUFFIXES = (".c",)


def _norm(raw: str, base: Path) -> Path:
    """Normalise a project-relative or absolute path written with either separator."""
    text = raw.strip().strip('"').replace("\\", "/")
    p = Path(text)
    return Path(os.path.normpath(p if p.is_absolute() else base / p))


def _split(raw: str | None, seps: str) -> list[str]:
    return [t for t in re.split(f"[{re.escape(seps)}]", raw or "") if t.strip()]


def _pick(names: list[str], wanted: str, what: str, path: Path) -> int:
    """Index of the configuration/target to read. A single one is used whatever it is called."""
    if wanted in names:
        return names.index(wanted)
    if len(names) == 1:
        return 0
    raise ValueError(f"{what} '{wanted}' not found in {path.name}. Available: {names}. "
                     "Set project.configuration to one of them.")


def _result(config, units, groups, defines, includes, name) -> EWPParseResult:
    seen: set[Path] = set()
    unique = []
    for tu in units:
        if tu.path not in seen:
            seen.add(tu.path)
            unique.append(tu)
    return EWPParseResult(source_files=unique, iar_groups=groups, global_defines=defines,
                          global_includes=includes, configuration_name=name)


# --- Keil uVision ---------------------------------------------------------------------

def parse_uvprojx(config: FwLensConfig) -> EWPParseResult:
    """Read one target of a Keil .uvprojx: defines, include paths, and the C files of its groups."""
    path = config.project.uvprojx
    if path is None or not path.exists():
        raise FileNotFoundError(f"Keil project file not found: {path}")
    base = path.parent
    root = ET.parse(path).getroot()
    targets = root.findall("./Targets/Target")
    if not targets:
        raise ValueError(f"{path.name} has no <Target> elements")
    names = [(t.findtext("TargetName") or "").strip() for t in targets]
    target = targets[_pick(names, config.project.configuration, "Target", path)]
    target_name = (target.findtext("TargetName") or "").strip()

    controls = target.find("./TargetOption/TargetArmAds/Cads/VariousControls")
    defines = _split(controls.findtext("Define") if controls is not None else "", ", \t")
    includes = [_norm(p, base) for p in _split(controls.findtext("IncludePath") if controls is not None else "", ";")]

    groups: dict[str, IARGroup] = {}
    units: list[TranslationUnit] = []
    for group in target.findall("./Groups/Group"):
        gname = (group.findtext("GroupName") or "").strip()
        for file_el in group.findall("./Files/File"):
            fpath = (file_el.findtext("FilePath") or "").strip()
            # FileType 1 is C source (2 assembler, 5 C++). Fall back to the suffix when it is missing.
            ftype = (file_el.findtext("FileType") or "").strip()
            if not fpath or (ftype and ftype != "1") or (not ftype and not fpath.lower().endswith(_C_SUFFIXES)):
                continue
            full = _norm(fpath, base)
            groups.setdefault(gname, IARGroup(name=gname)).files.append(full)
            units.append(TranslationUnit(
                path=full, defines=list(config.iar_compat_defines) + defines, include_paths=list(includes),
                boundary_class=_classify_boundary(full, config), iar_group=gname or None))
    return _result(config, units, groups, defines, includes, target_name)


# --- Eclipse CDT / STM32CubeIDE -------------------------------------------------------

_WORKSPACE_LOC = re.compile(r"\$\{workspace_loc:/\$\{ProjName\}/?([^}]*)\}")


def _cdt_include(raw: str, proj_dir: Path, build_dir: Path) -> Path | None:
    text = raw.strip().strip('"')
    m = _WORKSPACE_LOC.fullmatch(text)
    if m:
        return _norm(m.group(1), proj_dir)
    if "${" in text:
        return None                      # another variable: leave it out rather than guess
    p = _norm(text, build_dir)
    return p if p.exists() else _norm(text, proj_dir)


def _excluded(rel: Path, excluding: list[str]) -> bool:
    posix = rel.as_posix()
    return any(posix == e or posix.startswith(e.rstrip("/") + "/") for e in excluding)


def parse_cproject(config: FwLensConfig) -> EWPParseResult:
    """Read one configuration of a .cproject: defines, include paths and the source folders."""
    path = config.project.cproject
    if path is None or not path.exists():
        raise FileNotFoundError(f".cproject file not found: {path}")
    proj_dir = path.parent
    root = ET.parse(path).getroot()
    configs = [c for c in root.iter("configuration") if c.get("name") and c.find(".//toolChain") is not None]
    if not configs:
        raise ValueError(f"{path.name} has no build configuration with a toolchain")
    names = [c.get("name", "") for c in configs]
    cfg = configs[_pick(names, config.project.configuration, "Configuration", path)]
    cfg_name = cfg.get("name", "")
    build_dir = proj_dir / cfg_name

    defines: list[str] = []
    includes: list[Path] = []
    for option in cfg.iter("option"):
        kind = option.get("superClass", "")
        values = [v.get("value", "") for v in option.findall("listOptionValue")]
        if kind.endswith("c.compiler.option.definedsymbols") or kind.endswith("c.compiler.option.defs"):
            defines += [v.strip() for v in values if v.strip()]
        elif kind.endswith("c.compiler.option.includepaths") or kind.endswith("c.compiler.option.incpath"):
            includes += [p for p in (_cdt_include(v, proj_dir, build_dir) for v in values) if p]

    entries = [(e.get("name", ""), [x for x in (e.get("excluding") or "").split("|") if x])
               for e in cfg.findall(".//sourceEntries/entry") if e.get("kind", "sourcePath") == "sourcePath"]
    if not entries:
        entries = [(".", ["build", cfg_name])]

    groups: dict[str, IARGroup] = {}
    units: list[TranslationUnit] = []
    for name, excluding in entries:
        top = _norm(name, proj_dir)
        if not top.is_dir():
            continue
        for src in sorted(top.rglob("*.c")):
            if _excluded(src.relative_to(top), excluding):
                continue
            try:
                group = src.relative_to(proj_dir).parts[0] if src.parent != proj_dir else ""
            except ValueError:
                group = src.parent.name
            if group:
                groups.setdefault(group, IARGroup(name=group)).files.append(src)
            units.append(TranslationUnit(
                path=src, defines=list(config.iar_compat_defines) + defines, include_paths=list(includes),
                boundary_class=_classify_boundary(src, config), iar_group=group or None))
    return _result(config, units, groups, defines, includes, cfg_name)
