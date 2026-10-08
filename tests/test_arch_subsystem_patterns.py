"""Subsystem-level pattern detection: UI and comms first (#123)."""

from arch_helpers import project

from fwlens.arch import build_architecture
from fwlens.model.project import RTOSTask


def _run(tmp_path, files, domain, directory, extra_pins=None, extra_subsystems=None):
    pins = [{"name": domain.upper(), "units": [f"{directory}/*"]}] + (extra_pins or [])
    subs = [{"domain": domain, "units": [f"{directory}/*"]}] + (extra_subsystems or [])
    return project(tmp_path, files, components=pins, subsystems=subs)


def _pattern(arch, pattern_id):
    return next((p for p in arch.patterns if p.id == pattern_id), None)


def _declare(*names):
    return "".join(f"void {n}(void);\n" for n in names)


def test_widget_tree(tmp_path):
    files = {"ui/ui_main.c": _declare("lv_obj_create", "lv_label_create", "lv_btn_create")
             + "void ui_build(void){ lv_obj_create(); lv_label_create(); lv_btn_create(); }\n"}
    _m, _c, arch = _run(tmp_path, files, "ui", "ui")
    f = _pattern(arch, "ui_widget_tree")
    assert f and f.scope == "subsystem" and f.component == "UI"
    assert "lv_obj_create" in f.signals[0]["detail"]


def test_screen_state_machine_with_a_table_of_screens(tmp_path):
    src = ("typedef enum { HOME, MENU, INFO } Screen;\nstatic Screen cur;\n"
           "void ui_step(int k){ switch (cur) { case HOME: if (k) cur = MENU; break; case MENU: if (k) cur = INFO; break; case INFO: cur = HOME; break; } }\n"
           "static void draw_home(void){}\nstatic void draw_menu(void){}\n"
           "void (*screen_table[])(void) = { draw_home, draw_menu };\nvoid ui_draw(void){ screen_table[0](); ui_step(1); }\n")
    _m, _c, arch = _run(tmp_path, {"ui/ui_screens.c": src}, "ui", "ui")
    f = _pattern(arch, "ui_screen_state_machine")
    assert f and f.confidence == "high"


def test_menu_table(tmp_path):
    src = ('typedef struct { const char *label; void (*go)(void); } Item;\n'
           "static void a(void){}\nstatic void b(void){}\nstatic void c(void){}\n"
           'static const Item items[] = { {"Home", a}, {"Settings", b}, {"About", c} };\n'
           "void menu_run(void){ items[0].go(); }\n")
    _m, _c, arch = _run(tmp_path, {"ui/menu.c": src}, "ui", "ui")
    assert _pattern(arch, "ui_menu_table")


def test_model_and_view_split_needs_reads_and_no_writes_of_outside_data(tmp_path):
    files = {"model/model.c": "int speed;\nint mode;\n",
             "ui/view.c": "extern int speed;\nextern int mode;\nint view_text(void){ return speed + mode; }\n"}
    _m, _c, arch = _run(tmp_path, files, "ui", "ui", [{"name": "MODEL", "units": ["model/*"]}])
    assert _pattern(arch, "ui_model_view_split")
    files["ui/view.c"] += "void view_set(void){ speed = 3; }\n"
    _m, _c, arch = _run(tmp_path / "again", files, "ui", "ui", [{"name": "MODEL", "units": ["model/*"]}])
    assert _pattern(arch, "ui_model_view_split") is None


def test_display_driver_layering_needs_the_hal_below(tmp_path):
    files = {"ui/gfx.c": '#include "../hal/lcd_hal.h"\nvoid display_flush(void){ lcd_write(); }\n',
             "hal/lcd_hal.h": "void lcd_write(void);\n", "hal/lcd_hal.c": '#include "lcd_hal.h"\nvoid lcd_write(void){}\n'}
    _m, _c, arch = _run(tmp_path, files, "ui", "ui", [{"name": "HAL", "units": ["hal/*"]}],
                        [{"domain": "hal", "units": ["hal/*"]}])
    f = _pattern(arch, "ui_display_driver_layering")
    assert f and f.confidence == "high"


def test_event_loop(tmp_path):
    files = {"ui/input.c": "int key_event_get(void){ return 0; }\nint touch_poll(void){ return 1; }\n"}
    _m, _c, arch = _run(tmp_path, files, "ui", "ui")
    assert _pattern(arch, "ui_event_loop")


def test_layered_protocol_stack(tmp_path):
    files = {"net/phy.h": "int phy_tx(int b);\n", "net/phy.c": '#include "phy.h"\nint phy_tx(int b){ return b; }\n',
             "net/link.h": "int link_tx(int b);\n", "net/link.c": '#include "link.h"\n#include "phy.h"\nint link_tx(int b){ return phy_tx(b); }\n',
             "net/transport.c": '#include "link.h"\nint parse_frame(int b){ return link_tx(b); }\n'}
    _m, _c, arch = _run(tmp_path, files, "comms", "net")
    f = _pattern(arch, "comms_protocol_stack")
    assert f and f.confidence == "high"


def test_interrupt_ring_buffer(tmp_path):
    src = ("volatile unsigned char rx_buffer[16];\nvolatile int rx_head;\n"
           "void USART1_IRQHandler(void){ rx_buffer[rx_head] = 1; rx_head = rx_head + 1; }\n"
           "int uart_poll(void){ return rx_buffer[0]; }\n")
    _m, _c, arch = _run(tmp_path, {"net/uart.c": src}, "comms", "net")
    assert _pattern(arch, "comms_isr_ring_buffer")


def test_dma_double_buffer(tmp_path):
    _m, _c, arch = _run(tmp_path, {"net/dma.c": "void dma_half_complete_cb(void){}\nvoid dma_complete_cb(void){}\n"}, "comms", "net")
    assert _pattern(arch, "comms_dma_double_buffer")


def test_frame_parser_state_machine(tmp_path):
    src = ("typedef enum { SYNC, LEN, DATA } PState;\nstatic PState st;\n"
           "int parse_frame(int b){ switch (st) { case SYNC: if (b == 0x7e) st = LEN; break; case LEN: st = DATA; break; case DATA: st = SYNC; break; } return st; }\n")
    _m, _c, arch = _run(tmp_path, {"net/framer.c": src}, "comms", "net")
    f = _pattern(arch, "comms_frame_parser")
    assert f and f.confidence == "high"


def test_command_dispatcher(tmp_path):
    src = ("static int h0(int a){return a;}\nstatic int h1(int a){return a;}\nint (*cmd_table[])(int) = { h0, h1 };\n"
           "int dispatch(int c){ return cmd_table[c](c); }\n")
    _m, _c, arch = _run(tmp_path, {"net/cmd.c": src}, "comms", "net")
    assert _pattern(arch, "comms_command_dispatcher")


def test_one_task_per_interface(tmp_path):
    files = {"net/a.c": "void uart_task(void){}\nvoid can_task(void){}\n"}
    model, config, _arch = _run(tmp_path, files, "comms", "net")
    model.rtos_tasks = [RTOSTask(n, n, "1", 1, n, "s", "64", 64, "OS_CreateTask", tmp_path / "net/a.c", 1)
                        for n in ("uart_task", "can_task")]
    arch = build_architecture(model, config)
    assert _pattern(arch, "comms_task_per_interface")


def test_gateway_between_two_interfaces(tmp_path):
    files = {"net/gw.c": "void can_send(int b);\nvoid uart_rx_handler(int b){ can_send(b); }\n"}
    _m, _c, arch = _run(tmp_path, files, "comms", "net")
    f = _pattern(arch, "comms_gateway")
    assert f and "uart to can" in f.signals[0]["detail"]


def test_patterns_are_only_tested_on_their_own_domain(tmp_path):
    files = {"net/uart.c": _declare("lv_obj_create", "lv_label_create", "lv_btn_create")
             + "void f(void){ lv_obj_create(); lv_label_create(); lv_btn_create(); }\n"}
    _m, _c, arch = _run(tmp_path, files, "comms", "net")
    assert _pattern(arch, "ui_widget_tree") is None
