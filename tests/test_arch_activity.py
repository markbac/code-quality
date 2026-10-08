"""Git history, ownership and shared state by component (#129)."""

from arch_helpers import project

from fwlens.arch import build_architecture
from fwlens.arch.activity import team_of
from fwlens.model.project import CouplingPair

FILES = {
    "ui/ui.c": "int ui_state;\nvoid ui_run(void){ ui_state = 1; }\n",
    "net/net.c": "extern int ui_state;\nvoid net_run(void){ ui_state = 2; }\n",
    "drv/drv.c": "void drv_run(void){}\n",
    "log/log.c": "void log_run(void){}\n",
}
PINS = [{"name": n.upper(), "units": [f"{n}/*"]} for n in ("ui", "net", "drv", "log")]


def _history(model, root):
    by = {m.path.name: m for m in model.modules}
    for name, commits, author in (("ui.c", 20, "Ann"), ("net.c", 10, "Bob Smith"), ("drv.c", 8, "Cy"), ("log.c", 2, "Ann")):
        m = by[name]
        m.commit_count, m.bugfix_commit_count, m.main_author, m.ownership_fragmentation = commits, 3, author, 0.2
    by["ui.c"].functions[0].hotspot_score = 7.5
    model.change_coupling = [CouplingPair(by["drv.c"].path, by["log.c"].path, 6, 8, 7, 0.67)]


def _arch(tmp_path, **overrides):
    model, config, _a = project(tmp_path, FILES, components=PINS, **overrides)
    _history(model, tmp_path)
    return model, build_architecture(model, config)


def test_hotspots_and_ownership_are_grouped_by_component(tmp_path):
    _m, arch = _arch(tmp_path, teams={"web": ["ann*"], "backend": ["bob *"]})
    hot = {r["component"]: r for r in arch.activity["hotspots"]}
    assert hot["UI"]["commits"] == 20 and hot["UI"]["worst_hotspot"] == 7.5 and hot["UI"]["worst_function"] == "ui_run"
    assert arch.activity["hotspots"][0]["component"] == "UI"
    own = {r["component"]: r for r in arch.activity["ownership"]}
    assert own["UI"]["main_authors"] == ["Ann"] and own["UI"]["teams"] == ["web"]


def test_team_of_matches_case_insensitively():
    assert team_of("Bob Smith", {"backend": ["bob *"]}) == "backend"
    assert team_of("Zed", {"backend": ["bob *"]}) == ""


def test_files_that_change_together_without_a_dependency_are_hidden_coupling(tmp_path):
    _m, arch = _arch(tmp_path)
    hidden = arch.activity["hidden_coupling"]
    assert [(r["a"], r["b"], r["co_changes"]) for r in hidden] == [("DRV", "LOG", 6)]


def test_global_shared_between_components_is_listed(tmp_path):
    _m, arch = _arch(tmp_path)
    shared = {r["name"]: r for r in arch.activity["shared_state"]}
    assert shared["ui_state"]["components"] == ["NET", "UI"] and shared["ui_state"]["owner"] == "UI"


def test_without_history_only_shared_state_remains(tmp_path):
    model, config, arch = project(tmp_path, FILES, components=PINS)
    assert arch.activity["hotspots"] == [] and arch.activity["ownership"] == [] and arch.activity["hidden_coupling"] == []
    assert arch.activity["shared_state"]
