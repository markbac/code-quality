"""System-level pattern detection with evidence and confidence (#122)."""

import pytest
from arch_helpers import PROJECT, project

from fwlens.arch import build_architecture
from fwlens.arch.patterns import load_patterns
from fwlens.config import ConfigError
from fwlens.model.project import RTOSSyncObject, RTOSTask, RTOSObjectUsage


def _found(arch, pattern_id, scope="system"):
    return next((p for p in arch.patterns if p.id == pattern_id and p.scope == scope), None)


def _calls(names):
    return "".join(f"int {n}(void){{ return 1; }}\n" for n in names)


def test_super_loop(tmp_path):
    src = _calls(["a", "b", "c"]) + "int main(void){ while (1) { a(); b(); c(); } }\n"
    _m, _c, arch = project(tmp_path, {"main.c": src})
    f = _found(arch, "super_loop")
    assert f and f.confidence == "high"
    assert {s["signal"] for s in f.signals} >= {"main_loop", "loop_calls_several", "no_rtos"}
    assert "main loops forever" in next(s["detail"] for s in f.signals if s["signal"] == "main_loop")


def test_a_program_with_no_loop_is_not_a_super_loop(tmp_path):
    _m, _c, arch = project(tmp_path, {"main.c": "int main(void){ return 0; }\n"})
    assert _found(arch, "super_loop") is None or _found(arch, "super_loop").confidence == "low"


def test_layered(tmp_path):
    from test_arch_layers import PINS, SOURCES
    _m, _c, arch = project(tmp_path, {k: v for k, v in SOURCES.items() if not k.startswith("net/")}, components=PINS[:3])
    f = _found(arch, "layered")
    assert f and f.confidence in ("medium", "high")


def test_hal_with_several_implementations_of_one_ops_struct(tmp_path):
    files = {
        "hal/hal_ops.h": "typedef struct { int (*read)(void); int (*write)(int v); } HalOps;\n",
        "hal/uart_hal.c": '#include "hal_ops.h"\nstatic int r(void){return 1;}\nstatic int w(int v){return v;}\nconst HalOps uart_ops = { r, w };\n',
        "hal/spi_hal.c": '#include "hal_ops.h"\nstatic int r(void){return 2;}\nstatic int w(int v){return v;}\nconst HalOps spi_ops = { r, w };\n',
        "app/app.c": '#include "../hal/hal_ops.h"\nextern const HalOps uart_ops;\nint app(void){ return uart_ops.read(); }\n',
    }
    _m, _c, arch = project(tmp_path, files)
    f = _found(arch, "hal_ports")
    assert f and f.confidence in ("medium", "high")
    assert "HalOps implemented by" in next(s["detail"] for s in f.signals if s["signal"] == "multiple_implementations")


def test_event_driven(tmp_path):
    src = ("enum { EVENT_A, EVENT_B, EVENT_C };\n"
           "void event_subscribe(int id, void (*cb)(void)){ (void)id; (void)cb; }\n"
           "void event_publish(int id){ (void)id; }\n"
           "static void on_a(void){}\n"
           "int main(void){ event_subscribe(EVENT_A, on_a); event_publish(EVENT_A); return 0; }\n")
    _m, _c, arch = project(tmp_path, {"bus.c": src})
    f = _found(arch, "event_driven")
    assert f and f.confidence == "high"


def test_table_driven_state_machine(tmp_path):
    src = ("typedef enum { IDLE, RUN, STOP } State;\nstatic State state;\n"
           "void step(int ev){ switch (state) { case IDLE: if (ev) state = RUN; break; case RUN: if (ev) state = STOP; break; "
           "case STOP: state = IDLE; break; } }\n"
           "static void h1(void){}\nstatic void h2(void){}\n"
           "void (*state_table[])(void) = { h1, h2 };\n"
           "void run(void){ state_table[0](); step(1); }\n")
    _m, _c, arch = project(tmp_path, {"fsm.c": src})
    f = _found(arch, "state_machine_table")
    assert f and {s["signal"] for s in f.signals} >= {"state_machines_present", "state_tables"}


def test_rtos_task_based(tmp_path):
    model, config, _arch = project(tmp_path, {"main.c": "int main(void){ return 0; }\n"})
    model.rtos_tasks = [RTOSTask(f"T{i}", f"tcb{i}", "1", 1, f"e{i}", "s", "64", 64, "OS_CreateTask", tmp_path / "main.c", 1)
                        for i in range(2)]
    model.rtos_sync_objects = [RTOSSyncObject("queue", "q", "OS_Q_Create", tmp_path / "main.c", 1)]
    model.rtos_object_usages = [RTOSObjectUsage("q", f"T{i}", f"e{i}", "wait", tmp_path / "main.c", 1) for i in range(2)]
    arch = build_architecture(model, config)
    f = _found(arch, "rtos_tasks")
    assert f and f.confidence == "high"


def test_pipeline_chain(tmp_path):
    files = {}
    for i in range(5):
        nxt = f'#include "s{i + 1}.h"\n' if i < 4 else ""
        files[f"s{i}.h"] = f"int s{i}(int x);\n"
        files[f"s{i}.c"] = f'#include "s{i}.h"\n{nxt}int s{i}(int x){{ return {f"s{i + 1}(x)" if i < 4 else "x"}; }}\n'
    _m, _c, arch = project(tmp_path, files, components=[{"name": f"S{i}", "units": [f"s{i}.*"]} for i in range(5)])
    f = _found(arch, "pipeline")
    assert f and "S0" in f.signals[0]["detail"]


def test_big_ball_of_mud(tmp_path):
    files = {}
    for a, b in (("a", "b"), ("c", "d")):
        for x, y in ((a, b), (b, a)):
            files[f"{x}.h"] = f"int {x}(int n);\n"
            files[f"{x}.c"] = f'#include "{x}.h"\n#include "{y}.h"\nint {x}(int n){{ return {y}(n) + {y}(n); }}\n'
    _m, _c, arch = project(tmp_path, files, components=[{"name": n.upper(), "units": [f"{n}.*"]} for n in "abcd"])
    f = _found(arch, "big_ball_of_mud")
    assert f and f.confidence in ("medium", "high")


def test_god_component(tmp_path):
    files = {f"big{i}.c": f"int big{i}(void){{ return {i}; }}\n" for i in range(4)}
    files.update({f"t{i}.c": f"extern int big{i}(void);\nint t{i}(void){{ return big{i}(); }}\n" for i in range(4)})
    pins = [{"name": "Big", "units": ["big*"]}] + [{"name": f"T{i}", "units": [f"t{i}.c"]} for i in range(4)]
    _m, _c, arch = project(tmp_path, files, components=pins)
    f = _found(arch, "god_component")
    assert f and f.confidence == "high"


def test_findings_are_ordered_and_have_no_pattern_for_a_trivial_project(tmp_path):
    _m, _c, arch = project(tmp_path, {"x.c": "int x(void){ return 1; }\n"})
    assert all(p.scope == "system" for p in arch.patterns)
    assert [p.id for p in arch.patterns if p.confidence != "low"] == []


def test_a_rule_can_be_replaced_or_added_and_a_bad_signal_is_an_error(tmp_path):
    rules = load_patterns([{"id": "layered", "name": "Mine", "signals": {"acyclic": 1}, "thresholds": {"low": 1}},
                           {"id": "calm", "signals": {"acyclic": 1}}])
    assert next(p for p in rules if p.id == "layered").name == "Mine"
    assert any(p.id == "calm" for p in rules)
    with pytest.raises(ConfigError, match="unknown signal"):
        load_patterns([{"id": "bad", "signals": {"no_such_signal": 1}}])
    _m, _c, arch = project(tmp_path, PROJECT, patterns=[{"id": "acyc", "name": "Acyclic", "signals": {"acyclic": 1}}])
    assert _found(arch, "acyc")
