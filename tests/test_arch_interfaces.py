"""Public and internal symbols, and encapsulation leaks (#118)."""

from arch_helpers import PROJECT, project

SOURCES = {
    **PROJECT,
    "motor.h": "int motor_start(void);\n",
    "motor.c": '#include "motor.h"\nstatic int ramp(void){ return 1; }\nint motor_start(void){ return ramp(); }\n'
               "int motor_secret(void){ return 7; }\n",
    "motor_priv.h": "int motor_private(void);\n",
    "ctl.c": '#include "motor.h"\n#include "motor_priv.h"\nextern int motor_secret(void);\n'
             "int ctl(void){ return motor_start() + motor_secret() + motor_private(); }\n",
}
SOURCES["motor.c"] += "int motor_private(void){ return 2; }\n"


def _interface(arch, name):
    return next(i for i in arch.interfaces if i.unit.endswith("/" + name))


def test_static_and_undeclared_functions_are_internal(tmp_path):
    _m, _c, arch = project(tmp_path, SOURCES)
    motor = _interface(arch, "motor.c")
    assert "motor_start" in motor.public
    assert "ramp" in motor.internal            # static
    assert "motor_secret" in motor.internal    # no header declares it
    assert "motor_private" in motor.internal   # only a private header declares it


def test_reaching_past_the_header_is_a_leak(tmp_path):
    _m, _c, arch = project(tmp_path, SOURCES)
    found = {(lk.symbol, lk.kind) for lk in arch.leaks if lk.source.endswith("/ctl.c")}
    assert ("motor_secret", "undeclared") in found
    assert ("motor_private", "private-header") in found
    assert not any(lk.symbol == "motor_start" for lk in arch.leaks)


def test_private_header_patterns_are_configurable(tmp_path):
    _m, _c, arch = project(tmp_path, SOURCES, private_headers=[])
    assert not any(lk.kind == "private-header" for lk in arch.leaks)
    assert "motor_private" in _interface(arch, "motor.c").public


def test_leak_has_a_file_and_line(tmp_path):
    _m, _c, arch = project(tmp_path, SOURCES)
    leak = next(lk for lk in arch.leaks if lk.symbol == "motor_secret")
    assert leak.file.endswith("ctl.c") and leak.line > 0


def test_a_global_used_without_an_extern_in_a_header_is_a_leak(tmp_path):
    files = {"data.c": "int shared_value;\nint get(void){ return shared_value; }\n",
             "user.c": "extern int shared_value;\nint use(void){ return shared_value + 1; }\n"}
    _m, _c, arch = project(tmp_path, files)
    assert [lk.symbol for lk in arch.leaks if lk.source.endswith("user.c")] == ["shared_value"]


def test_a_dispatch_table_and_an_ops_struct_are_interfaces(tmp_path):
    files = {"ops.h": "typedef struct { int (*open)(void); int (*close)(void); } Ops;\nextern const Ops uart_ops;\n",
             "ops.c": '#include "ops.h"\nstatic int o(void){return 0;}\nstatic int c(void){return 0;}\nconst Ops uart_ops = { o, c };\n'
                      "int (*handlers[])(void) = { o, c };\n"}
    _m, _c, arch = project(tmp_path, files)
    ops = _interface(arch, "ops.c")
    assert ops.abstract_headers and ops.abstract_headers[0].endswith("ops.h")
    assert "handlers" in ops.tables
