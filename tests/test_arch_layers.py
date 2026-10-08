"""Layers inferred from the dependencies, next to the configured ones (#121)."""

from arch_helpers import project

from fwlens.arch import build_architecture
from fwlens.config import LayerRule

SOURCES = {
    "app/app.c": '#include "../svc/svc.h"\n#include "../hal/hal.h"\nint app(void){ return svc_run() + hal_raw(); }\n',
    "svc/svc.h": "int svc_run(void);\n",
    "svc/svc.c": '#include "svc.h"\n#include "../hal/hal.h"\nint svc_run(void){ return hal_read() + hal_read(); }\n',
    "hal/hal.h": "int hal_read(void);\nint hal_raw(void);\n",
    "hal/hal.c": '#include "hal.h"\nint hal_read(void){ return 1; }\nint hal_raw(void){ return 2; }\n',
    "net/a.h": "int net_a(void);\n",
    "net/a.c": '#include "a.h"\n#include "b.h"\nint net_a(void){ return net_b() + net_b(); }\n',
    "net/b.h": "int net_b(void);\n",
    "net/b.c": '#include "b.h"\n#include "a.h"\nint net_b(void){ return net_a(); }\n',
}
PINS = [{"name": n, "units": [f"{n.lower()}/*"]} for n in ("App", "Svc", "Hal")] + [{"name": "Net", "units": ["net/*"]}]


def test_levels_follow_the_dependencies(tmp_path):
    _m, _c, arch = project(tmp_path, SOURCES, components=PINS)
    level = arch.layering.level_of
    assert level["Hal"] == 0 < level["Svc"] < level["App"]


def test_a_dependency_that_jumps_a_layer_is_listed_and_lowers_the_next_layer_share(tmp_path):
    _m, _c, arch = project(tmp_path, SOURCES, components=PINS)
    skips = [(e["source"], e["target"], e["skips"]) for e in arch.layering.skip_edges]
    assert ("App", "Hal", 1) in skips
    assert 0 < arch.layering.next_layer_share < 1


def test_units_that_depend_on_each_other_are_a_cycle_with_back_edges(tmp_path):
    files = {**SOURCES, "net/a.c": SOURCES["net/a.c"].replace("net_b() + net_b()", "net_b() + net_b() + net_b()")}
    pins = [{"name": "A", "units": ["net/a.*"]}, {"name": "B", "units": ["net/b.*"]}] + PINS[:3]
    _m, _c, arch = project(tmp_path, files, components=pins)
    assert arch.layering.cycles == [["A", "B"]]
    assert arch.layering.level_of["A"] == arch.layering.level_of["B"]
    assert [(e["source"], e["target"]) for e in arch.layering.back_edges] == [("B", "A")]


def test_the_configured_layer_order_is_compared_not_applied(tmp_path):
    model, config, _arch = project(tmp_path, SOURCES, components=PINS)
    for m in model.modules:
        m.layer = "Top" if "/hal/" in m.path.as_posix() else "Bottom"        # deliberately the wrong way round
    config.layers = [LayerRule("Bottom"), LayerRule("Top")]
    arch = build_architecture(model, config)
    notes = {(d["source"], d["target"]): d["note"] for d in arch.layering.disagreements}
    assert ("Svc", "Hal") in notes and "configured order says upward" in notes[("Svc", "Hal")]
    assert arch.layering.level_of["Hal"] == 0              # the inferred levels are untouched


def test_no_configured_layers_means_no_disagreements(tmp_path):
    _m, _c, arch = project(tmp_path, SOURCES, components=PINS)
    assert arch.layering.disagreements == []
