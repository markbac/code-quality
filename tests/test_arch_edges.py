"""Typed, weighted dependency edges (#117)."""

from arch_helpers import edge, project

from fwlens.arch.model import DEFAULT_WEIGHTS


def test_every_kind_of_edge_is_found(tmp_path):
    _model, _config, arch = project(tmp_path)
    assert edge(arch, "app.c", "hal.c", "call")
    assert edge(arch, "app.c", "cfg.c", "call")
    assert edge(arch, "app.c", "hal.c", "callback")
    assert edge(arch, "app.c", "cfg.c", "state")          # writes cfg_value
    assert edge(arch, "hal.c", "cfg.c", "state")          # HalState embeds CfgData
    assert edge(arch, "app.c", "cfg.c", "type")
    assert edge(arch, "app.c", "hal.c", "include")
    assert edge(arch, "hal.c", "cfg.c", "include")


def test_no_edge_runs_the_wrong_way_or_to_itself(tmp_path):
    _model, _config, arch = project(tmp_path)
    assert not edge(arch, "cfg.c", "app.c", "call")
    assert not edge(arch, "cfg.c", "hal.c", "call")
    assert all(e.source != e.target for e in arch.edges)


def test_weight_is_count_times_the_kind_weight_and_can_be_overridden(tmp_path):
    _model, _config, arch = project(tmp_path)
    call = edge(arch, "app.c", "hal.c", "call")
    assert call.weight == call.count * DEFAULT_WEIGHTS["call"]
    _m, _c, heavy = project(tmp_path / "again", weights={"call": 10})
    assert edge(heavy, "app.c", "hal.c", "call").weight == edge(heavy, "app.c", "hal.c", "call").count * 10


def test_edges_keep_a_few_file_and_line_pairs_as_evidence(tmp_path):
    _model, _config, arch = project(tmp_path)
    where, line = edge(arch, "app.c", "hal.c", "call").evidence[0]
    assert where.endswith("app.c") and line > 0


def test_the_model_is_stored_and_serialisable(tmp_path):
    model, _config, arch = project(tmp_path)
    assert model.architecture is arch
    assert {e["kind"] for e in arch.as_dict()["edges"]} >= {"call", "include"}
