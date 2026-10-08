"""Shared helpers for the architecture tests: parse a small project, run the graph engine, build the model."""

from __future__ import annotations

from cparse import make_config, parse_model

from fwlens.arch import build_architecture
from fwlens.graph.engines import run_graph_engine

PROJECT = {
    "cfg.h": "typedef struct { int x; } CfgData;\nextern int cfg_value;\nint cfg_get(void);\n",
    "cfg.c": '#include "cfg.h"\nint cfg_value;\nint cfg_get(void){ return cfg_value; }\n',
    "hal.h": '#include "cfg.h"\ntypedef struct { CfgData cfg; } HalState;\nint hal_read(void);\n',
    "hal.c": '#include "hal.h"\nint hal_read(void){ return cfg_get() + 1; }\n',
    "app.c": '#include "hal.h"\n#include "cfg.h"\n'
             "static int (*table[])(void) = { hal_read, cfg_get };\n"
             "int run(void){ CfgData d; d.x = 1; cfg_value = 2; return hal_read() + cfg_get() + table[0](); }\n"
             "int main(void){ return run(); }\n",
}


def project(tmp_path, sources=None, **overrides):
    """(model, config, arch) for a small project; `overrides` are ArchitectureConfig fields."""
    model = parse_model(tmp_path, dict(sources or PROJECT))
    config = make_config(tmp_path)
    for key, value in overrides.items():
        setattr(config.architecture, key, value)
    run_graph_engine(model, config)
    return model, config, build_architecture(model, config)


def edge(arch, source, target, kind):
    """The edge from the unit whose file name is `source` to `target`, of `kind` (None if absent)."""
    for e in arch.edges:
        if e.source.endswith("/" + source) and e.target.endswith("/" + target) and e.kind == kind:
            return e
    return None
