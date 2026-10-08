"""Subsystem domain labelling (#120)."""

import pytest
from arch_helpers import project

from fwlens.arch.domains import load_domains
from fwlens.config import ConfigError

SOURCES = {
    "ui/display.h": "int display_draw(int x);\nint menu_open(void);\n",
    "ui/display.c": '#include "display.h"\nint display_draw(int x){ return x; }\nint menu_open(void){ return display_draw(1); }\nint touch_read(void){ return 0; }\n',
    "net/uart_link.h": "int uart_send(int b);\nint modbus_frame(void);\n",
    "net/uart_link.c": '#include "uart_link.h"\nint uart_send(int b){ return b; }\nint modbus_frame(void){ return uart_send(1) + uart_send(2); }\n',
    "misc/thing.c": "int zorp(void){ return 1; }\n",
}


def _domain(arch, filename):
    comp = next(c for c in arch.components if any(u.endswith("/" + filename) for u in c.units))
    return next(s for s in arch.subsystems if s.component == comp.id)


def test_components_get_a_domain_with_evidence(tmp_path):
    _m, _c, arch = project(tmp_path, SOURCES)
    ui = _domain(arch, "display.c")
    assert ui.domain == "ui" and ui.confidence in ("high", "medium")
    assert any(line.startswith("files:") and "display" in line for line in ui.evidence)
    comms = _domain(arch, "uart_link.c")
    assert comms.domain == "comms"
    assert any("uart_send" in line for line in comms.evidence)


def test_a_component_with_no_domain_words_is_unclassified(tmp_path):
    _m, _c, arch = project(tmp_path, SOURCES)
    assert _domain(arch, "thing.c").domain == "unclassified"


def test_words_match_whole_words_only(tmp_path):
    _m, _c, arch = project(tmp_path, {"monkey.c": "int monkeys(void){ return 1; }\n"})
    assert _domain(arch, "monkey.c").domain == "unclassified"     # "key" is not a word of "monkey"


def test_a_pinned_domain_wins(tmp_path):
    pins = [{"domain": "storage", "units": ["misc/*"]}]
    _m, _c, arch = project(tmp_path, SOURCES, subsystems=pins)
    sub = _domain(arch, "thing.c")
    assert (sub.domain, sub.confidence) == ("storage", "high")


def test_your_own_domain_is_added_and_the_same_id_replaces_a_bundled_one():
    domains = load_domains([{"id": "zorp", "name": "Zorp", "words": ["zorp"]}, {"id": "ui", "words": ["only"]}])
    assert any(d.id == "zorp" for d in domains)
    assert next(d for d in domains if d.id == "ui").words == {"only"}


def test_a_domain_without_words_is_a_config_error():
    with pytest.raises(ConfigError):
        load_domains([{"id": "bad"}])
