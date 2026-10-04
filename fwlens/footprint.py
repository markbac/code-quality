"""Flash and RAM footprint from a linker map file (project.map_file) (#82)."""

from __future__ import annotations

from rich.console import Console

from fwlens.config import FwLensConfig
from fwlens.model.project import ProjectModel
from fwlens.parser.mapfile import parse_linker_mapfile

console = Console()


def _stem(object_name: str) -> str:
    """main.o, main.c.obj and main.obj all name the object for main.c."""
    return object_name.split(".")[0]


def apply_map_file(model: ProjectModel, config: FwLensConfig) -> None:
    """
    Parse project.map_file and attach per-file flash and RAM bytes to the modules whose file
    stem matches an object in the map, plus whole-map totals on model.footprint. Footprint is
    per file; the parser reads object-level sizes, so there are no per-function sizes.
    """
    path = config.project.map_file
    if path is None:
        return
    if not path.exists():
        console.print(f"[yellow][fwlens] project.map_file does not exist: {path}. Footprint skipped.[/yellow]")
        return
    objects = parse_linker_mapfile(path)
    if not objects:
        console.print(f"[yellow][fwlens] No .text/.rodata/.data/.bss entries found in {path}; "
                      "footprint skipped. Supported: GCC-style map lines.[/yellow]")
        return

    by_stem: dict[str, list] = {}
    for m in model.modules:
        by_stem.setdefault(m.path.stem, []).append(m)

    matched = 0
    unmatched = []
    for name, sizes in objects.items():
        mods = by_stem.get(_stem(name))
        if not mods:
            unmatched.append(name)
            continue
        matched += 1
        for m in mods:
            m.flash_bytes += sizes.total_flash
            m.ram_bytes += sizes.total_ram

    model.footprint = {
        "flash_bytes": sum(o.total_flash for o in objects.values()),
        "ram_bytes": sum(o.total_ram for o in objects.values()),
        "objects": len(objects),
        "matched": matched,
        "unmatched": sorted(unmatched),
    }
    console.print(f"[cyan][fwlens][/cyan] Footprint from {path.name}: flash {model.footprint['flash_bytes']} B, "
                  f"RAM {model.footprint['ram_bytes']} B ({matched}/{len(objects)} objects matched to source files)")
