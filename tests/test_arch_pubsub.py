"""Publish and subscribe and registration mapping (#128)."""

import pytest
from arch_helpers import project

from fwlens.arch.export import plantuml, structurizr
from fwlens.arch.pubsub import call_args, validate
from fwlens.config import ConfigError

FILES = {
    "bus/bus.h": "enum { EVENT_KEY, EVENT_RX };\nvoid event_subscribe(int id, void (*cb)(void));\nvoid event_publish(int id);\n",
    "bus/bus.c": '#include "bus.h"\nvoid event_subscribe(int id, void (*cb)(void)){ (void)id; (void)cb; }\nvoid event_publish(int id){ (void)id; }\n',
    "ui/ui.c": '#include "../bus/bus.h"\nstatic void on_key(void){}\nvoid ui_init(void){ event_subscribe(EVENT_KEY, on_key); }\n',
    "net/net.c": '#include "../bus/bus.h"\nstatic void on_rx(void){}\nvoid net_init(void){ event_subscribe(EVENT_RX, &on_rx); }\n',
    "drv/key_drv.c": '#include "../bus/bus.h"\nvoid key_poll(void){ event_publish(EVENT_KEY); }\n',
    "drv/uart_drv.c": '#include "../bus/bus.h"\nvoid uart_rx_done(void){ event_publish(EVENT_RX); }\n',
}
PINS = [{"name": n.upper(), "units": [f"{n}/*"]} for n in ("bus", "ui", "net", "drv")]


def _events(arch):
    return {e.event: e for e in arch.events}


def test_each_event_has_its_publishers_and_subscribers(tmp_path):
    _m, _c, arch = project(tmp_path, FILES, components=PINS)
    events = _events(arch)
    assert set(events) == {"EVENT_KEY", "EVENT_RX"}
    key = events["EVENT_KEY"]
    assert [p["function"] for p in key.publishers] == ["key_poll"]
    assert [(s["callback"], s["broker"], s["function"]) for s in key.subscribers] == [("on_key", "event_subscribe", "ui_init")]
    assert [s["callback"] for s in events["EVENT_RX"].subscribers] == ["on_rx"]      # &on_rx
    assert key.publishers[0]["line"] > 0 and key.publishers[0]["file"].endswith("key_drv.c")


def test_the_definition_of_the_broker_is_not_a_call(tmp_path):
    _m, _c, arch = project(tmp_path, FILES, components=PINS)
    assert all(p["function"] not in ("event_subscribe", "event_publish") for e in arch.events for p in e.publishers)


def test_flows_between_components_appear_in_the_exports(tmp_path):
    _m, _c, arch = project(tmp_path, FILES, components=PINS)
    text = plantuml(arch)
    assert "c_DRV .[#blue].> c_UI : <<event EVENT_KEY>>" in text
    assert "c_DRV .[#blue].> c_NET : <<event EVENT_RX>>" in text
    assert 'c_DRV -> c_UI "publishes EVENT_KEY" "via event_subscribe"' in structurizr(arch)


def test_the_event_driven_pattern_uses_the_mapping(tmp_path):
    _m, _c, arch = project(tmp_path, FILES, components=PINS)
    found = next(p for p in arch.patterns if p.id == "event_driven")
    assert found.confidence == "high" and "events_mapped" in {s["signal"] for s in found.signals}


def test_brokers_with_unhelpful_names_are_configured_by_argument_position(tmp_path):
    files = {"bus.c": "void bus_hook(int slot, void (*fn)(void)){}\nvoid bus_kick(int slot){}\n"
                      "static void cb(void){}\nvoid wire(void){ bus_hook(7, cb); }\nvoid go(void){ bus_kick(7); }\n"}
    _m, _c, plain = project(tmp_path / "plain", files)
    assert plain.events == []
    _m, _c, arch = project(tmp_path / "cfg", files,
                           register_calls=[{"function": "bus_hook", "id_arg": 0, "callback_arg": 1}],
                           publish_calls=[{"function": "bus_kick", "id_arg": 0}])
    (event,) = arch.events
    assert event.event == "7" and event.publishers[0]["function"] == "go" and event.subscribers[0]["callback"] == "cb"


def test_argument_splitting_respects_nesting():
    text = "f(a, g(b, c), (d, e), [1, 2], {3, 4}, \"x\")"
    assert call_args(text, text.index("(")) == ["a", "g(b, c)", "(d, e)", "[1, 2]", "{3, 4}", '"x"']


@pytest.mark.parametrize("reg,pub", [
    ([{"function": "f", "id_arg": 0}], None),
    ([{"function": "f", "id_arg": -1, "callback_arg": 1}], None),
    (None, [{"function": "f", "id_arg": "0"}]),
    (None, [{"function": "f", "id_arg": 0, "extra": 1}]),
])
def test_bad_event_config_is_an_error(reg, pub):
    with pytest.raises(ConfigError, match="architecture"):
        validate(reg, pub)
