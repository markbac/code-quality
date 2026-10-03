"""
Baseline / breach-gating for fwlens.

Ports the CI workflow from the older ccccc-based code_governance toolkit:
threshold breaches get a stable id, get diffed against a stored
`baseline.json`, and CI only fails on breaches that are new or have gotten
worse since the baseline was captured. Existing (unchanged) breaches are
recorded but do not fail the build.

Breach ids no longer contain a line number (see fwlens.identity and issues #29, #53):
    <file>:<function>:<metric>                 -- function-level (name#2 for a second function of that name)
    <file>:<metric>                            -- module-level
`file` is repo-relative with forward slashes. Each function breach also carries a content
fingerprint so a breach that moves with its code, or follows a renamed function, is
recognised instead of being reported as one fixed and one new.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from fwlens.config import FwLensConfig
from fwlens.identity import (
    SCHEME, MatchResult, body_fingerprint, function_source, make_key, match_findings,
    migrate_legacy_id, project_root, relative_posix, to_posix,
)
from fwlens.model.project import ProjectModel

BASELINE_VERSION = 2

# metric key -> (rule name, short description, default SARIF level). The single table used by
# the breach computation and the SARIF exporter, so they cannot drift apart (issue #27).
METRIC_INFO = {
    "cyclomatic_complexity": ("CyclomaticComplexity", "Cyclomatic complexity exceeds the threshold", "warning"),
    "cognitive_complexity": ("CognitiveComplexity", "Cognitive complexity exceeds the threshold", "warning"),
    "block_depth": ("BlockDepth", "Block nesting depth exceeds the threshold", "warning"),
    "function_loc": ("FunctionLength", "Function length (LOC) exceeds the threshold", "note"),
    "parameter_count": ("ParameterCount", "Parameter count exceeds the threshold", "note"),
    "return_path_count": ("ReturnPaths", "Number of return paths exceeds the threshold", "note"),
    "magic_number_density": ("MagicNumberDensity", "Magic number density exceeds the threshold", "note"),
    "fan_out": ("FanOut", "Distinct callees exceed the threshold", "note"),
    "main_sequence_distance": ("MainSequenceDistance", "Distance from the main sequence exceeds the threshold", "warning"),
}

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
    id: str            # stable key, never contains the line number
    kind: str          # "function" | "module"
    file: str          # repo-relative, forward slashes
    metric: str
    value: float
    threshold: float
    line: Optional[int] = None        # location only, not part of the identity
    function: Optional[str] = None
    fingerprint: dict = field(default_factory=dict)
    # Coding-standard findings (kind "rule"): category such as mandatory/required/advisory,
    # the rule title, and the deviation that covers the finding, if any
    category: Optional[str] = None
    description: Optional[str] = None
    deviation: Optional[str] = None

    def to_dict(self) -> dict:
        d = {
            "id": self.id,
            "kind": self.kind,
            "file": self.file,
            "metric": self.metric,
            "value": self.value,
            "threshold": self.threshold,
        }
        if self.line is not None:
            d["line"] = self.line
        if self.function is not None:
            d["function"] = self.function
        if self.fingerprint:
            d["fingerprint"] = self.fingerprint
        for key in ("category", "description", "deviation"):
            if getattr(self, key) is not None:
                d[key] = getattr(self, key)
        return d


def _assign_ordinals(breaches: list[Breach]) -> None:
    """Give functions that share a name (static functions in one file) distinct, stable keys,
    numbering them in source order."""
    groups: dict[tuple, list[Breach]] = {}
    for b in breaches:
        if b.kind in ("function", "rule"):
            groups.setdefault((b.file, b.function, b.metric), []).append(b)
    for (file, function, metric), items in groups.items():
        items.sort(key=lambda b: b.line or 0)
        for n, b in enumerate(items, start=1):
            b.id = make_key(file, function if function is not None or b.kind != "rule" else "<file>", metric, n)


def compute_breaches(model: ProjectModel, config: FwLensConfig) -> list[Breach]:
    """Compute all first-party threshold breaches, each with a stable id and content fingerprint."""
    t = config.thresholds
    root = project_root(config)
    file_cache: dict = {}
    breaches: list[Breach] = []

    for f in model.first_party_functions():
        for metric_key, attr in _FUNCTION_METRICS:
            threshold = getattr(t, metric_key)
            value = getattr(f, attr)
            if value > threshold:
                file_str = relative_posix(f.file, root)
                fp = body_fingerprint(function_source(f, file_cache))
                breaches.append(Breach("", "function", file_str, metric_key, value, threshold,
                                       line=f.line, function=f.name, fingerprint=fp))

    for m in model.first_party_modules():
        for metric_key, attr in _MODULE_METRICS:
            threshold = getattr(t, metric_key)
            value = getattr(m, attr)
            if value > threshold:
                file_str = relative_posix(m.path, root)
                breaches.append(Breach(make_key(file_str, None, metric_key), "module", file_str,
                                       metric_key, value, threshold))

    _standards_findings(model, config, breaches)
    _assign_ordinals(breaches)
    return breaches


def _standards_findings(model: ProjectModel, config: FwLensConfig, breaches: list[Breach]) -> None:
    """Add coding-standard findings when standards are enabled (optional, off by default)."""
    if not getattr(config, "standards", None) or not config.standards.enabled:
        return
    from fwlens.standards import run_standards
    breaches.extend(run_standards(model, config).findings)


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
    root = project_root(config)
    breaches: list[Breach] = []

    for fd in payload.get("functions", []):
        for metric_key, attr in _FUNCTION_METRICS:
            threshold = getattr(t, metric_key)
            value = fd.get(attr)
            if value is not None and value > threshold:
                file_str = relative_posix(fd.get("file", ""), root)
                breaches.append(Breach("", "function", file_str, metric_key, value, threshold,
                                       line=fd.get("line"), function=fd.get("name")))

    for md in payload.get("modules", []):
        for metric_key, attr in _MODULE_METRICS:
            threshold = getattr(t, metric_key)
            value = md.get(attr)
            if value is not None and value > threshold:
                file_str = relative_posix(md.get("path", ""), root)
                breaches.append(Breach(make_key(file_str, None, metric_key), "module", file_str,
                                       metric_key, value, threshold))

    _assign_ordinals(breaches)
    return breaches


def load_baseline(path: Path) -> dict[str, dict]:
    """
    Load baseline.json into an id -> entry dict. Missing file is an empty baseline.

    Version 1 files (ids containing the line number) are migrated on load. Their entries
    have no content fingerprint, so only same-key matching works for them until the
    baseline is rewritten with --update-baseline.
    """
    if not path.exists():
        return {}
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    entries = raw.get("accepted", [])
    if raw.get("version", 1) < BASELINE_VERSION and entries:
        print(f"[fwlens] NOTE: {path} uses the legacy line-based baseline format; migrated in memory. "
              "Re-run with --update-baseline to store stable ids and fingerprints.")
    migrated = (migrate_legacy_id(entry) for entry in entries)
    return {entry["id"]: entry for entry in migrated}


def load_baselines_from_paths(paths: list[Path]) -> dict[str, dict[str, dict]]:
    """
    Load multiple named baseline JSON files into a map of baseline_label -> (breach_id -> breach_dict).
    Enables comparing current build metrics against multiple historical baselines (e.g. v1.0, v2.0, last-release).
    """
    result = {}
    for p in paths:
        label = p.stem.replace("baseline-", "").replace("baseline_", "") or p.name
        result[label] = load_baseline(p)
    return result


def compare_historical_baselines(
    breaches: list[Breach], baselines_map: dict[str, dict[str, dict]]
) -> dict[str, dict[str, list[Breach]]]:
    """
    Compare current breaches against multiple named baselines.
    Returns: label -> {"new_or_worsened": [...], "accepted_unchanged": [...]}
    """
    comparison = {}
    for label, bdict in baselines_map.items():
        new_worsened, accepted = diff_against_baseline(breaches, bdict)
        comparison[label] = {
            "new_or_worsened": new_worsened,
            "accepted_unchanged": accepted,
        }
    return comparison


def save_baseline(path: Path, accepted: dict[str, dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": BASELINE_VERSION,
        "scheme": SCHEME,
        "accepted": sorted(accepted.values(), key=lambda e: e["id"]),
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
        f.write("\n")


def classify_against_baseline(
    breaches: list[Breach], baseline: dict[str, dict], *,
    similarity: float = 0.85, containment: float = 0.6,
) -> MatchResult:
    """Full classification: new, unchanged, moved, uncertain, plus resolved baseline entries."""
    return match_findings(breaches, baseline.values(), similarity=similarity, containment=containment)


def diff_against_baseline(
    breaches: list[Breach], baseline: dict[str, dict], *, uncertain_gates: bool = False,
) -> tuple[list[Breach], list[Breach]]:
    """
    Split breaches into (new_or_worsened, accepted_unchanged).

    A baselined breach counts as "worsened" if its current value exceeds the value
    recorded in the baseline -- baselining accepts the current severity, not an open-ended
    pass. A breach that moved with its code or follows a renamed function is matched to its
    baseline entry (see fwlens.identity), so it is not reported as new. Loose matches
    (uncertain) are accepted unless ``uncertain_gates`` is set.
    """
    result = classify_against_baseline(breaches, baseline)
    gating = {id(m.current) for m in result.gating(uncertain_gates)}
    new_or_worsened = [b for b in breaches if id(b) in gating]
    accepted_unchanged = [b for b in breaches if id(b) not in gating]
    return new_or_worsened, accepted_unchanged


def update_baseline(
    path: Path,
    breaches: list[Breach],
    *,
    accept_all: bool = False,
    accept_ids: list[str] | None = None,
    prune: bool = False,
) -> dict[str, dict]:
    """
    Merge accepted breaches into the baseline file and write it back.

    accept_all accepts every breach currently computed; accept_ids accepts only breaches whose
    id is in the given list. An accepted breach that matches an existing entry (for example
    because it moved) replaces that entry, so the baseline follows the code. With prune=True,
    entries that match no current breach any more (resolved) are removed, otherwise the
    baseline only ever grows.
    """
    accept_ids_set = set(accept_ids or [])
    baseline = load_baseline(path)
    result = classify_against_baseline(breaches, baseline)

    for m in result.matches:
        b = m.current
        if not (accept_all or b.id in accept_ids_set):
            continue
        if m.base is not None and m.status in ("moved", "uncertain"):
            baseline.pop(m.base["id"], None)
        baseline[b.id] = b.to_dict()

    if prune:
        for entry in result.resolved:
            baseline.pop(entry["id"], None)

    save_baseline(path, baseline)
    return baseline
