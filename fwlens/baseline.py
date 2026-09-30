"""
Baseline / breach-gating for fwlens.

Ports the CI workflow from the older ccccc-based code_governance toolkit:
threshold breaches get a stable id, get diffed against a stored
`baseline.json`, and CI only fails on breaches that are new or have gotten
worse since the baseline was captured. Existing (unchanged) breaches are
recorded but do not fail the build.

Breach ids follow the same shape code_governance used:
    <file>:<line>:<function>:<metric>          -- function-level
    <file>:<metric>                            -- module-level
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from fwlens.config import FwLensConfig
from fwlens.model.project import ProjectModel

# metric key (matches ThresholdConfig field name) -> FunctionMetrics attribute
_FUNCTION_METRICS = [
    ("cyclomatic_complexity", "cyclomatic_complexity"),
    ("cognitive_complexity", "cognitive_complexity"),
    ("block_depth", "block_depth"),
    ("function_loc", "loc"),
    ("parameter_count", "parameter_count"),
    ("return_path_count", "return_path_count"),
    ("magic_number_density", "magic_number_density"),
    ("fan_out", "fan_out"),
]

# metric key -> ModuleMetrics attribute
_MODULE_METRICS = [
    ("main_sequence_distance", "main_sequence_distance"),
]


@dataclass
class Breach:
    id: str
    kind: str          # "function" | "module"
    file: str
    metric: str
    value: float
    threshold: float

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "kind": self.kind,
            "file": self.file,
            "metric": self.metric,
            "value": self.value,
            "threshold": self.threshold,
        }


def compute_breaches(model: ProjectModel, config: FwLensConfig) -> list[Breach]:
    """Compute all first-party threshold breaches, each with a stable id."""
    t = config.thresholds
    breaches: list[Breach] = []

    for f in model.first_party_functions():
        for metric_key, attr in _FUNCTION_METRICS:
            threshold = getattr(t, metric_key)
            value = getattr(f, attr)
            if value > threshold:
                file_str = str(f.file).replace("\\", "/")
                bid = f"{file_str}:{f.line}:{f.name}:{metric_key}"
                breaches.append(Breach(bid, "function", file_str, metric_key, value, threshold))

    for m in model.first_party_modules():
        for metric_key, attr in _MODULE_METRICS:
            threshold = getattr(t, metric_key)
            value = getattr(m, attr)
            if value > threshold:
                file_str = str(m.path).replace("\\", "/")
                bid = f"{file_str}:{metric_key}"
                breaches.append(Breach(bid, "module", file_str, metric_key, value, threshold))

    return breaches


def compute_breaches_from_json(json_path: Path, config: FwLensConfig) -> list[Breach]:
    """
    Same breach computation as compute_breaches, but reading a fwlens_results.json
    export (e.g. from a different git commit's `export`/`report` run) instead of a
    live ProjectModel. Thresholds always come from the config passed to this call,
    not from whatever config produced the export -- so both sides of a two-hash
    comparison are judged against the same bar.
    """
    with open(json_path, encoding="utf-8") as f:
        payload = json.load(f)

    t = config.thresholds
    breaches: list[Breach] = []

    for fd in payload.get("functions", []):
        for metric_key, attr in _FUNCTION_METRICS:
            threshold = getattr(t, metric_key)
            value = fd.get(attr)
            if value is not None and value > threshold:
                file_str = str(fd.get("file", "")).replace("\\", "/")
                bid = f"{file_str}:{fd.get('line')}:{fd.get('name')}:{metric_key}"
                breaches.append(Breach(bid, "function", file_str, metric_key, value, threshold))

    for md in payload.get("modules", []):
        for metric_key, attr in _MODULE_METRICS:
            threshold = getattr(t, metric_key)
            value = md.get(attr)
            if value is not None and value > threshold:
                file_str = str(md.get("path", "")).replace("\\", "/")
                bid = f"{file_str}:{metric_key}"
                breaches.append(Breach(bid, "module", file_str, metric_key, value, threshold))

    return breaches


def load_baseline(path: Path) -> dict[str, dict]:
    """Load baseline.json into an id -> entry dict. Missing file is an empty baseline."""
    if not path.exists():
        return {}
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    return {entry["id"]: entry for entry in raw.get("accepted", [])}


def save_baseline(path: Path, accepted: dict[str, dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"accepted": sorted(accepted.values(), key=lambda e: e["id"])}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
        f.write("\n")


def diff_against_baseline(
    breaches: list[Breach], baseline: dict[str, dict]
) -> tuple[list[Breach], list[Breach]]:
    """
    Split breaches into (new_or_worsened, accepted_unchanged).

    A baselined breach counts as "worsened" if its current value exceeds the
    value recorded in the baseline -- i.e. baselining a breach accepts its
    current severity, not an open-ended pass.
    """
    new_or_worsened: list[Breach] = []
    accepted_unchanged: list[Breach] = []
    for b in breaches:
        entry = baseline.get(b.id)
        if entry is None or b.value > entry.get("value", b.value):
            new_or_worsened.append(b)
        else:
            accepted_unchanged.append(b)
    return new_or_worsened, accepted_unchanged


def update_baseline(
    path: Path,
    breaches: list[Breach],
    *,
    accept_all: bool = False,
    accept_ids: list[str] | None = None,
) -> dict[str, dict]:
    """
    Merge newly accepted breaches into the baseline file and write it back.

    accept_all accepts every breach currently computed; accept_ids accepts
    only breaches whose id is in the given list. Breaches already in the
    baseline are left as-is unless they also appear in the current pass.
    """
    accept_ids_set = set(accept_ids or [])
    baseline = load_baseline(path)

    for b in breaches:
        if accept_all or b.id in accept_ids_set:
            baseline[b.id] = b.to_dict()

    save_baseline(path, baseline)
    return baseline
