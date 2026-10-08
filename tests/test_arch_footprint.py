"""Flash and RAM per component from the linker map (#131)."""

from arch_helpers import project

from fwlens.arch import build_architecture
from fwlens.footprint import apply_map_file

FILES = {"a/a1.c": "void a1(void){}\n", "a/a2.c": "void a2(void){}\n", "b/b1.c": "void b1(void){}\n",
         "c/c1.c": "void c1(void){}\n"}
COMPONENTS = [{"name": n.upper(), "units": [f"{n}/*"]} for n in ("a", "b", "c")]
MAP = """
 .text          0x08000000        0x100 build/a1.o
 .bss           0x20000000         0x40 build/a1.o
 .text          0x08000100         0x30 build/b1.o
"""


def _rows(tmp_path, map_text):
    model, config, _a = project(tmp_path, FILES, components=COMPONENTS)
    if map_text is not None:
        config.project.map_file = tmp_path / "p.map"
        config.project.map_file.write_text(map_text)
        apply_map_file(model, config)
    return {r["component"]: r for r in build_architecture(model, config).footprint}


def test_bytes_are_added_up_per_component(tmp_path):
    rows = _rows(tmp_path, MAP)
    assert (rows["A"]["flash_bytes"], rows["A"]["ram_bytes"]) == (0x100, 0x40)
    assert (rows["A"]["units"], rows["A"]["mapped"]) == (2, 1)
    assert rows["B"]["flash_bytes"] == 0x30 and rows["A"]["flash_share"] == round(0x100 / 0x130, 3)


def test_a_component_missing_from_the_map_has_no_figures_not_zero(tmp_path):
    c = _rows(tmp_path, MAP)["C"]
    assert c["flash_bytes"] is None and c["ram_bytes"] is None and c["mapped"] == 0


def test_without_a_map_file_there_are_no_rows(tmp_path):
    assert _rows(tmp_path, None) == {}
