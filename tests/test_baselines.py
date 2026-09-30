"""
Tests for multi-baseline comparison and historical delta tracking.
"""

import tempfile
from pathlib import Path

from fwlens.baseline import (
    Breach, load_baseline, save_baseline, load_baselines_from_paths, compare_historical_baselines
)


def test_multi_baseline_comparison():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        b1_path = tmp_path / "baseline-v1.0.json"
        b2_path = tmp_path / "baseline-v2.0.json"

        breaches_v1 = [
            Breach(id="main.c:10:main:cyclomatic_complexity", kind="function", file="main.c", metric="cyclomatic_complexity", value=20.0, threshold=15.0)
        ]
        save_baseline(b1_path, {b.id: b.to_dict() for b in breaches_v1})

        breaches_v2 = [
            Breach(id="main.c:10:main:cyclomatic_complexity", kind="function", file="main.c", metric="cyclomatic_complexity", value=25.0, threshold=15.0)
        ]
        save_baseline(b2_path, {b.id: b.to_dict() for b in breaches_v2})

        loaded_map = load_baselines_from_paths([b1_path, b2_path])
        assert "v1.0" in loaded_map
        assert "v2.0" in loaded_map

        current_breaches = [
            Breach(id="main.c:10:main:cyclomatic_complexity", kind="function", file="main.c", metric="cyclomatic_complexity", value=30.0, threshold=15.0)
        ]

        comp = compare_historical_baselines(current_breaches, loaded_map)
        assert len(comp["v1.0"]["new_or_worsened"]) == 1
        assert len(comp["v2.0"]["new_or_worsened"]) == 1
