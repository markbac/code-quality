"""
CI reporters (issue #30). One small interface, so annotations and machine-readable reports
are not hard-coded per provider. Every reporter consumes the same ``Breach`` list.

    GitHubReporter   ::warning workflow commands for PR diff annotations
    GitLabReporter   Code Quality report (CodeClimate subset) for merge request widgets
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Iterable, Optional

from fwlens.baseline import METRIC_INFO, Breach

DEFAULT_GITLAB_REPORT = "gl-code-quality-report.json"


def severity_for(b: Breach) -> str:
    """Map how far a value exceeds its threshold onto GitLab's severities.

    Note-level metrics are one step quieter: within 25 % over the threshold they are info.
    """
    ratio = (b.value / b.threshold) if b.threshold else float("inf")
    quiet = METRIC_INFO.get(b.metric, ("", "", "warning"))[2] == "note"
    if ratio < 1.25:
        return "info" if quiet else "minor"
    if ratio < 2:
        return "minor" if quiet else "major"
    return "major" if quiet else "critical"


def fingerprint_for(b: Breach) -> str:
    """Stable across commits: derived from the id, which never contains a line number."""
    return hashlib.sha256(b.id.encode("utf-8")).hexdigest()


def to_codequality(breaches: Iterable[Breach]) -> list[dict]:
    entries = []
    for b in breaches:
        entries.append({
            "description": f"{b.metric} is {b.value:g} (threshold {b.threshold:g})"
                           + (f" in {b.function}" if b.function else ""),
            "check_name": f"fwlens/{b.metric}",
            "fingerprint": fingerprint_for(b),
            "severity": severity_for(b),
            "location": {
                "path": b.file,
                "lines": {"begin": max(1, b.line or 1)},
            },
        })
    return entries


class Reporter:
    name = "base"

    def emit(self, breaches: list[Breach], out_path: Optional[Path] = None) -> Optional[Path]:
        raise NotImplementedError


class GitHubReporter(Reporter):
    name = "github"

    def emit(self, breaches, out_path=None):
        for b in breaches:
            line = f",line={b.line}" if b.line else ""
            print(f"::warning file={b.file}{line},title=FWLens Breach [{b.metric}]::"
                  f"{b.metric} is {b.value} (threshold {b.threshold})")
        return None


class GitLabReporter(Reporter):
    name = "gitlab"

    def emit(self, breaches, out_path=None):
        path = Path(out_path or DEFAULT_GITLAB_REPORT)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(to_codequality(breaches), f, indent=2)
            f.write("\n")
        return path


def running_on_gitlab() -> bool:
    return os.environ.get("GITLAB_CI", "").lower() == "true"


def default_gitlab_report_path() -> Path:
    base = os.environ.get("CI_PROJECT_DIR")
    return Path(base) / DEFAULT_GITLAB_REPORT if base else Path(DEFAULT_GITLAB_REPORT)
