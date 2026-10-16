"""The architecture brief: one JSON file describing the code base (fwlens architecture brief)."""

from __future__ import annotations

import json

import pytest
from arch_helpers import project
from click.testing import CliRunner

import main as fwlens_main
from fwlens.brief import SCHEMA, build_brief
from fwlens.brief.source import SourceFile, _int_value, memory_regions

SOURCES = {
    "app/app.h": "/* Application layer: owns the main state machine. */\n#ifndef APP_H\n#define APP_H\n"
                 "#define APP_TIMEOUT_MS 500U\n#define UART_BAUD 115200\n"
                 "/** States of the application. */\n"
                 "typedef enum { APP_IDLE, APP_RUN, APP_ERROR, APP_STATE_COUNT } AppState;\n"
                 "typedef struct { AppState state; unsigned int next_ms; } AppCtx;\n"
                 "void app_step(void);\nvoid app_init(void);\n#endif\n",
    "app/app.c": '#include "app.h"\n#include "../drv/hal.h"\nstatic AppCtx s_ctx;\n'
                 "/* Starts the app. */\nvoid app_init(void)\n{\n    s_ctx.state = APP_IDLE;\n"
                 '    log_info("app init done");\n}\n'
                 "/** Run one step of the app. */\nvoid app_step(void)\n{\n    switch (s_ctx.state) {\n"
                 "    case APP_IDLE: if (HAL_GetTick() > s_ctx.next_ms) { s_ctx.state = APP_RUN; } break;\n"
                 "    case APP_RUN: if ((unsigned int)(HAL_GetTick() - s_ctx.next_ms) < 5u) { s_ctx.state = APP_IDLE; } break;\n"
                 "    default: break;\n    }\n}\n",
    "app/fsm.c": "typedef void (*state_fn)(void);\nstatic state_fn s_state;\nstatic void st_idle(void);\nstatic void st_busy(void);\n"
                 "static void st_idle(void) { s_state = st_busy; }\nstatic void st_busy(void) { s_state = st_idle; }\n"
                 "void fsm_init(void) { s_state = st_idle; }\nvoid fsm_run(void) { s_state(); }\n",
    "drv/hal.h": "/* Minimal HAL. */\nunsigned int HAL_GetTick(void);\nvoid HAL_Delay(unsigned int ms);\n"
                 "void log_info(const char *msg);\nvoid NVIC_SetPriority(int irq, unsigned int p);\n"
                 "int HAL_FLASH_Program(unsigned int t, unsigned int a, unsigned long long d);\n"
                 "unsigned int crc32_compute(const unsigned char *p, unsigned int n);\n"
                 "typedef struct { unsigned int DR; unsigned int SR; } USART_TypeDef;\n"
                 "#define USART1 ((USART_TypeDef *)0x40011000UL)\n",
    "drv/hal.c": '#include "hal.h"\nstatic volatile unsigned int s_ticks;\n'
                 "unsigned int HAL_GetTick(void) { return s_ticks; }\nvoid SysTick_Handler(void) { s_ticks++; }\n"
                 "void HAL_Delay(unsigned int ms) { unsigned int t = HAL_GetTick(); while ((HAL_GetTick() - t) < ms) { } }\n"
                 "void log_info(const char *msg) { (void)msg; }\n"
                 "void NVIC_SetPriority(int irq, unsigned int p) { (void)irq; (void)p; }\n"
                 "int HAL_FLASH_Program(unsigned int t, unsigned int a, unsigned long long d) { (void)t; (void)a; (void)d; return 0; }\n"
                 "unsigned int crc32_compute(const unsigned char *p, unsigned int n) { (void)p; return n; }\n"
                 "void uart_send(char c) { USART1->DR = (unsigned int)c; }\n"
                 "void EXTI0_IRQHandler(void) { HAL_Delay(1); }\n",
    "update/ota.c": '#include "../drv/hal.h"\n'
                    "static int ota_store(const unsigned char *p, unsigned int n) { return HAL_FLASH_Program(0, 0x08040000u, p[0] + n); }\n"
                    "int ota_receive_chunk(const unsigned char *p, unsigned int n) { if (crc32_compute(p, n) == 0) { return -1; } return ota_store(p, n); }\n",
    "main.c": '#include "app/app.h"\n#include "drv/hal.h"\nvoid fsm_init(void);\nvoid fsm_run(void);\n'
              "static void board_init(void) { NVIC_SetPriority(-1, 3); }\n"
              "int main(void)\n{\n    board_init();\n    app_init();\n    fsm_init();\n"
              "    while (1) {\n        app_step();\n        fsm_run();\n        HAL_Delay(10);\n    }\n}\n",
    "STM32F4.ld": "MEMORY\n{\n  FLASH (rx) : ORIGIN = 0x08000000, LENGTH = 512K\n  RAM (xrw) : ORIGIN = 0x20000000, LENGTH = 128K\n}\n",
    "README.md": "# Demo firmware\n\nA demo used to test the brief.\n",
}


@pytest.fixture(scope="module")
def brief(tmp_path_factory):
    model, config, _arch = project(tmp_path_factory.mktemp("brief"), SOURCES)
    data = build_brief(model, config)
    json.dumps(data)                                    # plain JSON all the way down
    return data


def _symbol(brief, name):
    return next(s for s in brief["symbols"] if s["name"] == name)


def test_the_brief_has_every_section_and_says_how_to_read_it(brief):
    assert brief["schema"] == SCHEMA
    for key in ("meta", "build", "files", "directories", "architecture", "execution", "interrupts", "peripherals",
                "state_machines", "concerns", "memory", "interfaces", "types", "constants", "globals", "symbols",
                "log_messages", "quality", "history", "tests", "documents", "vocabulary", "gaps"):
        assert key in brief, key
    assert brief["how_to_read"] and brief["meta"]["counts"]["functions"] == len(brief["symbols"])


def test_files_carry_their_header_comment_and_paths_are_relative(brief):
    files = {f["path"]: f for f in brief["files"]}
    assert files["app/app.h"]["header_comment"] == "Application layer: owns the main state machine."
    assert files["app/app.h"]["kind"] == "header" and files["main.c"]["kind"] == "source"
    assert "main" in files["main.c"]["functions"]
    assert {d["path"] for d in brief["directories"]} >= {"app", "drv", "update"}


def test_symbols_have_signature_comment_callers_and_reach(brief):
    step = _symbol(brief, "app_step")
    assert step["signature"] == "void app_step(void)"
    assert step["doc"] == "Run one step of the app."
    assert step["callers"] == ["main"] and step["reached_from"] == ["main"]
    assert "time" in step["concerns"]
    assert _symbol(brief, "app_init")["doc"] == "Starts the app."


def test_start_up_sequence_stops_at_the_main_loop_and_lists_the_loop(brief):
    startup = brief["execution"]["startup"]
    assert [s["call"] for s in startup["sequence"]] == ["board_init", "app_init", "fsm_init"]
    board = startup["sequence"][0]
    assert [c["call"] for c in board["calls"]] == ["NVIC_SetPriority"]
    assert [c["call"] for c in startup["main_loop"]["calls"]] == ["app_step", "fsm_run", "HAL_Delay"]


def test_entry_points_include_main_and_isrs_with_their_concerns(brief):
    entries = {e["name"]: e for e in brief["execution"]["entry_points"]}
    assert entries["main"]["kind"] == "main" and entries["main"]["reaches"] > 5
    assert entries["SysTick_Handler"]["kind"] == "isr"
    assert "time" in entries["main"]["concerns"]


def test_switch_state_machine_is_resolved_against_its_enum(brief):
    sm = next(s for s in brief["state_machines"] if s["kind"] == "switch")
    assert sm["function"] == "app_step" and sm["enum"]["name"] == "AppState"
    assert sm["enum"]["doc"] == "States of the application."
    assert sm["unreached_constants"] == ["APP_ERROR"]          # APP_STATE_COUNT is a count, not a state
    assert sm["driven_by"] == ["main"]


def test_function_pointer_state_machine_is_found(brief):
    sm = next(s for s in brief["state_machines"] if s["kind"] == "function_pointer")
    assert sm["state_variable"] == "s_state" and sm["states"] == ["st_busy", "st_idle"]
    assert {"from": "st_idle", "to": "st_busy"} in sm["transitions"]
    assert sm["called_through"] is True


def test_time_concern_finds_the_tick_and_the_wrap_unsafe_comparison(brief):
    time = brief["concerns"]["time"]
    assert [h["function"] for h in time["roles"]["tick_source"]] == ["SysTick_Handler"]
    assert "app_step" in [h["function"] for h in time["roles"]["time_read"]]
    wrap = time["findings"]["wrap_unsafe_comparisons"]
    assert [w["expression"] for w in wrap] == ["HAL_GetTick() > s_ctx.next_ms"]   # the subtraction form is not flagged
    delays = time["findings"]["blocking_delays_reached_from_isr"]
    assert any(d["function"] == "HAL_Delay" and "EXTI0_IRQHandler" in d["isrs"] for d in delays)
    assert time["findings"]["time_counters"][0]["name"] == "s_ticks"
    assert time["findings"]["time_counters"][0]["file"] == "drv/hal.c"


def test_update_flow_traces_receive_to_flash_and_lists_the_gaps(brief):
    flow = brief["concerns"]["update"]["flow"]
    steps = {s["step"]: [f["function"] for f in s["functions"]] for s in flow["steps"]}
    assert "ota_receive_chunk" in steps["image_receive"] and "ota_store" in steps["flash_write"]
    assert steps["verify_integrity"] == ["ota_receive_chunk"]
    chain = next(c for c in flow["receive_to_flash_paths"] if c["from"] == "ota_receive_chunk")
    assert chain["path"] == ["ota_receive_chunk", "ota_store"] and chain["checks_on_path"] == ["verify_integrity"]
    assert "no signature check found in the update code" in flow["gaps"]
    assert "no CRC or hash check found in the update code" not in flow["gaps"]


def test_interrupts_peripherals_memory_and_constants(brief):
    priorities = brief["interrupts"]["priorities"]
    assert priorities == [{"call": "NVIC_SetPriority", "irq": "-1", "line": 5, "priority": "3", "file": "main.c"}]
    peripherals = {p["peripheral"]: p for p in brief["peripherals"]}
    assert peripherals["USART"]["functions"] == ["uart_send"] and peripherals["FLASH"]["via"] == ["HAL_FLASH_Program"]
    regions = brief["memory"]["linker_scripts"][0]["regions"]
    assert regions[0] == {"name": "FLASH", "attributes": "rx", "origin": "0x08000000", "length": "512K"}
    constants = {c["name"]: c for c in brief["constants"]}
    assert constants["APP_TIMEOUT_MS"]["category"] == "time" and constants["UART_BAUD"]["category"] == "comms"


def test_types_logs_documents_and_gaps(brief):
    enum = next(e for e in brief["types"]["enums"] if e["name"] == "AppState")
    assert [c["value"] for c in enum["constants"]] == [0, 1, 2, 3]
    assert next(s for s in brief["types"]["structs"] if s["name"] == "AppCtx")["fields"] == ["AppState state", "unsigned int next_ms"]
    assert brief["log_messages"] == [{"call": "log_info", "line": 8, "text": "app init done", "function": "app_init",
                                      "file": "app/app.c"}]
    assert brief["documents"][0]["title"] == "Demo firmware"
    assert "concern 'Security': nothing detected" in brief["gaps"]


def test_source_helpers(tmp_path):
    src = SourceFile(tmp_path / "x.c", "// Line one\n// line two\nint\nfoo(int a)\n{\n  return a;\n}\n"
                                       "enum { A = 1 << 2, B, C = B + 3 };\n")
    assert src.comment_before(4) == "Line one line two"
    assert src.signature_at(4, "foo") == "int foo(int a)"
    body = src.body_at(4)
    assert body is not None and (body.start_line, body.end_line) == (5, 7)
    assert [c["value"] for c in src.enums()[0]["constants"]] == [4, 5, 8]
    licensed = SourceFile(tmp_path / "y.c", "/* Copyright (c) 2024 Someone\n * SPDX-License-Identifier: MIT */\n"
                                            "/* Serial recovery. */\nint y;\n")
    assert licensed.header_comment() == "Serial recovery."
    assert _int_value("9 ** 9 ** 9", {}) is None and _int_value("__import__('os')", {}) is None
    icf = tmp_path / "a.icf"
    icf.write_text("define region ROM_region = mem:[from 0x08000000 to 0x0807FFFF];\n")
    assert memory_regions(icf) == [{"name": "ROM_region", "origin": "0x08000000", "end": "0x0807FFFF"}]


def test_the_brief_command_and_format_write_the_file(tmp_path, monkeypatch):
    for name, text in SOURCES.items():
        f = tmp_path / "src" / name
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)
    cfg = tmp_path / "config.yaml"
    cfg.write_text("project:\n  source_dir: .\nscope:\n  first_party: [src]\ntool:\n  target: native\n"
                   "output:\n  formats: [brief]\n")
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(fwlens_main.cli, ["architecture", "brief", "--config", str(cfg), "--output", "b.json"])
    assert result.exit_code == 0, result.output
    assert json.loads((tmp_path / "b.json").read_text(encoding="utf-8"))["schema"] == SCHEMA
    result = CliRunner().invoke(fwlens_main.cli, ["report", "--config", str(cfg)])
    assert result.exit_code == 0, result.output
    data = json.loads((tmp_path / "output" / "exports" / "fwlens_brief.json").read_text(encoding="utf-8"))
    assert any(s["name"] == "ota_receive_chunk" for s in data["symbols"])
