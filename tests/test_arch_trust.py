"""Trust boundary paths from entry points to sensitive code (#130)."""

import pytest
from arch_helpers import project

from fwlens.config import ConfigError

FILES = {
    "comms/uart.c": '#include "proto.h"\nvoid uart_rx_isr(void){ proto_parse(); }\n',
    "comms/proto.h": "void proto_parse(void);\nvoid session_open(void);\n",
    "comms/proto.c": '#include "proto.h"\n#include "../sec/crypto.h"\n#include "../store/nvm.h"\n'
                     "void proto_parse(void){ session_open(); nvm_write(); }\n"
                     "void session_open(void){ aes_decrypt(); }\n",
    "sec/crypto.h": "void aes_decrypt(void);\nint mbedtls_aes_crypt_cbc(int a);\n",
    "sec/crypto.c": '#include "crypto.h"\nvoid aes_decrypt(void){ mbedtls_aes_crypt_cbc(1); }\n',
    "store/nvm.h": "void nvm_write(void);\n",
    "store/nvm.c": '#include "nvm.h"\nvoid nvm_write(void){}\n',
    "app/main.c": 'void idle(void){}\nint main(void){ idle(); return 0; }\n',
}
PINS = [{"domain": "comms", "units": ["comms/*"]}, {"domain": "security", "units": ["sec/*"]},
        {"domain": "storage", "units": ["store/*"]}]
COMPONENTS = [{"name": n.upper(), "units": [f"{n}/*"]} for n in ("comms", "sec", "store", "app")]


def _paths(tmp_path, **overrides):
    _m, _c, arch = project(tmp_path, FILES, components=COMPONENTS, subsystems=PINS, **overrides)
    return {(p["entry"], p["kind"]): p for p in arch.trust_paths}


def test_default_paths_run_from_comms_to_crypto_and_storage(tmp_path):
    paths = _paths(tmp_path)
    crypto = paths[("uart_rx_isr", "crypto")]
    assert [h["function"] for h in crypto["path"]] == ["uart_rx_isr", "proto_parse", "session_open", "aes_decrypt"]
    assert crypto["crossings"] == ["COMMS -> SEC"]
    assert [h["function"] for h in paths[("uart_rx_isr", "storage")]["path"]] == ["uart_rx_isr", "proto_parse", "nvm_write"]
    assert all(entry == "uart_rx_isr" for entry, _k in paths)         # proto_parse is called, so it is not an entry


def test_the_path_names_the_catalogue_api_it_reaches(tmp_path):
    apis = _paths(tmp_path)[("uart_rx_isr", "crypto")]["crypto_apis"]
    assert [(a["api"], a["library"], a["in"]) for a in apis] == [("mbedtls_aes_crypt_cbc", "mbedtls", "aes_decrypt")]


def test_entries_and_sinks_are_configurable(tmp_path):
    paths = _paths(tmp_path, trust_entries=[{"function": "proto_*"}], trust_sinks=[{"kind": "nv", "function": "nvm_*"}])
    assert set(paths) == {("proto_parse", "nv")}
    assert [h["function"] for h in paths[("proto_parse", "nv")]["path"]] == ["proto_parse", "nvm_write"]


def test_a_sink_in_the_entrys_own_component_is_not_a_boundary(tmp_path):
    paths = _paths(tmp_path, trust_sinks=[{"kind": "parse", "component": "COMMS"}])
    assert paths == {}


@pytest.mark.parametrize("entries,sinks", [([{"domain": "a", "function": "b"}], []), ([{"colour": "red"}], []),
                                           ([], [{"domain": "security"}])])
def test_bad_items_are_rejected(entries, sinks):
    from fwlens.arch.trust import validate
    with pytest.raises(ConfigError):
        validate(entries, sinks)
