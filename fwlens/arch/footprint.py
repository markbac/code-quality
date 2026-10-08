"""
Flash and RAM per component from the linker map (`project.map_file`).

Each file's bytes come from the existing map support (`fwlens.footprint`); this adds them up per component.
A component none of whose files appear in the map has no figures (`None`), which is not the same as zero bytes:
the report shows it as having no map data. `mapped` of `units` says how many of its files were found in the map.
Without a map file there are no rows.
"""

from __future__ import annotations

from fwlens.arch.edges import norm
from fwlens.arch.model import ArchModel
from fwlens.model.project import ProjectModel


def by_component(model: ProjectModel, arch: ArchModel) -> list[dict]:
    if not model.footprint:
        return []
    modules = {norm(m.path): m for m in model.modules}
    total_flash = model.footprint.get("flash_bytes") or 0
    total_ram = model.footprint.get("ram_bytes") or 0
    rows = []
    for c in arch.components:
        sized = [m for u in c.units if (m := modules.get(u)) and (m.flash_bytes or m.ram_bytes)]
        row: dict = {"component": c.name, "units": len(c.units), "mapped": len(sized),
                     "flash_bytes": None, "ram_bytes": None, "flash_share": None, "ram_share": None}
        if sized:
            flash, ram = sum(m.flash_bytes for m in sized), sum(m.ram_bytes for m in sized)
            row.update(flash_bytes=flash, ram_bytes=ram,
                       flash_share=round(flash / total_flash, 3) if total_flash else None,
                       ram_share=round(ram / total_ram, 3) if total_ram else None)
        rows.append(row)
    rows.sort(key=lambda r: (r["flash_bytes"] is None, -(r["flash_bytes"] or 0), r["component"]))
    return rows
