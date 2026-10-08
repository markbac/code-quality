"""Inferred components and directory drift (#119)."""

from arch_helpers import project

from fwlens.arch import build_architecture

SOURCES = {
    "drivers/uart.h": "int uart_put(int c);\nint uart_get(void);\n",
    "drivers/uart.c": '#include "uart.h"\n#include "spi.h"\nint uart_put(int c){ return spi_xfer(c) + spi_xfer(c+1); }\nint uart_get(void){ return spi_xfer(0) + spi_xfer(1); }\n',
    "drivers/spi.h": "int spi_xfer(int c);\nint spi_status(void);\n",
    "drivers/spi.c": '#include "spi.h"\n#include "uart.h"\nint spi_xfer(int c){ return uart_get() + c; }\nint spi_status(void){ return uart_get() + uart_put(1); }\n',
    "app/ui.h": "int ui_draw(int x);\nint ui_key(void);\n",
    "app/ui.c": '#include "ui.h"\nint ui_draw(int x){ return x + ui_key(); }\nint ui_key(void){ return 1; }\n',
    "app/main.c": '#include "ui.h"\nint main(void){ return ui_draw(1) + ui_draw(2) + ui_key(); }\n',
    "drivers/panel.c": '#include "../app/ui.h"\nint panel(void){ return ui_draw(1) + ui_draw(2) + ui_draw(3) + ui_key() + ui_key(); }\n',
}


def _names(arch):
    return {c.name: sorted(u.rsplit("/", 1)[-1] for u in c.units) for c in arch.components}


def _component_of(arch, filename):
    return next(c for c in arch.components if any(u.endswith("/" + filename) for u in c.units))


def test_tightly_coupled_units_form_a_component(tmp_path):
    _m, _c, arch = project(tmp_path, SOURCES)
    assert _component_of(arch, "uart.c") is _component_of(arch, "spi.c")
    assert _component_of(arch, "main.c") is _component_of(arch, "ui.c")
    assert _component_of(arch, "uart.c") is not _component_of(arch, "main.c")


def test_a_file_in_the_wrong_directory_is_reported_as_drift(tmp_path):
    _m, _c, arch = project(tmp_path, SOURCES)
    assert _component_of(arch, "panel.c") is _component_of(arch, "ui.c")
    drifted = [d for d in arch.drift if d.unit.endswith("/panel.c")]
    assert drifted and drifted[0].outside == 1.0
    assert drifted[0].best_component == _component_of(arch, "ui.c").name
    assert not any(d.unit.endswith("/uart.c") for d in arch.drift)


def test_the_same_input_gives_the_same_components(tmp_path):
    model, config, first = project(tmp_path, SOURCES)
    again = build_architecture(model, config)
    assert _names(first) == _names(again)


def test_pinned_components_are_taken_first(tmp_path):
    pinned = [{"name": "Comms", "units": ["drivers/*"]}]
    _m, _c, arch = project(tmp_path, SOURCES, components=pinned)
    comms = next(c for c in arch.components if c.name == "Comms")
    assert comms.source == "pinned"
    assert {u.rsplit("/", 1)[-1] for u in comms.units} == {"uart.c", "spi.c", "panel.c"}


def test_ide_groups_anchor_components_and_the_difference_is_listed(tmp_path):
    model, config, _arch = project(tmp_path, SOURCES)
    for m in model.modules:
        m.iar_groups = ["Everything"]
        m.layer = "Drivers" if "drivers" in m.path.as_posix() else "App"
    arch = build_architecture(model, config)
    assert [c.name for c in arch.components] == ["Everything"]
    assert arch.components[0].source == "group"
    assert arch.differences[0]["kind"] == "spans-layers"


def test_a_large_group_is_split_by_community(tmp_path):
    model, config, _arch = project(tmp_path, SOURCES, max_component_units=3)
    for m in model.modules:
        m.iar_groups = ["Everything"]
    arch = build_architecture(model, config)
    assert len(arch.components) >= 2
    assert all(c.source == "group+community" for c in arch.components)
    assert any(d["kind"] == "group-split" for d in arch.differences)


def test_cohesion_is_the_share_of_coupling_kept_inside(tmp_path):
    _m, _c, arch = project(tmp_path, SOURCES)
    assert all(0 <= c.cohesion <= 1 for c in arch.components)
    assert _component_of(arch, "uart.c").cohesion == 1.0
