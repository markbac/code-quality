"""
CI reporters (issue #30). One small interface, so annotations and machine-readable reports
are not hard-coded per provider. Every reporter consumes the same ``Breach`` list.

    GitHubReporter   ::warning workflow commands for PR diff annotations
    GitLabReporter   Code Quality report (CodeClimate subset) for merge request widgets
    JUnitReporter    JUnit XML: one test case per finding, for CI test-result views
"""

from __future__ import annotations

import hashlib
import json
import os
import xml.etree.ElementTree as ET
from collections.abc import Iterable
from pathlib import Path

from fwlens.baseline import METRIC_INFO, Breach

DEFAULT_GITLAB_REPORT = "gl-code-quality-report.json"


def severity_for(b: Breach) -> str:
    """Map how far a value exceeds its threshold onto GitLab's severities.

    Note-level metrics are one step quieter: within 25 % over the threshold they are info.
    """
    if b.category:
        return {"mandatory": "critical", "required": "major", "advisory": "minor"}.get(b.category, "major")
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
            "description": (f"{b.metric}: {b.description}" if b.kind == "rule" else
                            f"{b.metric} is {b.value:g} (threshold {b.threshold:g})")
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

    def emit(self, breaches: list[Breach], out_path: Path | None = None) -> Path | None:
        raise NotImplementedError


class GitHubReporter(Reporter):
    name = "github"

    def emit(self, breaches, out_path=None):
        for b in breaches:
            line = f",line={b.line}" if b.line else ""
            text = b.description if b.kind == "rule" else f"{b.metric} is {b.value} (threshold {b.threshold})"
            print(f"::warning file={b.file}{line},title=FWLens Breach [{b.metric}]::{text}")


class GitLabReporter(Reporter):
    name = "gitlab"

    def emit(self, breaches, out_path=None):
        path = Path(out_path or DEFAULT_GITLAB_REPORT)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(to_codequality(breaches), f, indent=2)
            f.write("\n")
        return path


def _failure_message(b: Breach) -> str:
    if b.kind == "rule":
        return f"{b.metric}: {b.description}"
    return f"{b.metric} is {b.value:g} (threshold {b.threshold:g})"


def to_junit(breaches: Iterable[Breach], suite_name: str = "fwlens") -> str:
    """
    JUnit XML for the findings. Each source file is a test suite, each finding a test case
    that failed (classname = file, name = function and metric). With no findings the report
    holds one passing case, so CI views show a green result rather than nothing.
    """
    by_file: dict[str, list[Breach]] = {}
    for b in breaches:
        by_file.setdefault(b.file, []).append(b)

    root = ET.Element("testsuites", name=suite_name)
    total = 0
    for file, items in sorted(by_file.items()):
        suite = ET.SubElement(root, "testsuite", name=file, tests=str(len(items)),
                              failures=str(len(items)), errors="0", skipped="0")
        for b in sorted(items, key=lambda x: (x.line or 0, x.id)):
            case = ET.SubElement(suite, "testcase", classname=file,
                                 name=f"{b.function or '<module>'}: {b.metric}")
            failure = ET.SubElement(case, "failure", message=_failure_message(b), type=b.metric)
            where = f"{file}:{b.line}" if b.line else file
            failure.text = f"{where}\n{_failure_message(b)}" + (f" in {b.function}" if b.function else "")
        total += len(items)
    if not by_file:
        suite = ET.SubElement(root, "testsuite", name=suite_name, tests="1", failures="0",
                              errors="0", skipped="0")
        ET.SubElement(suite, "testcase", classname=suite_name, name="no findings")
        total = 0
    root.set("tests", str(max(total, 1)))
    root.set("failures", str(total))
    ET.indent(root)
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode") + "\n"


class JUnitReporter(Reporter):
    name = "junit"

    def emit(self, breaches, out_path=None):
        path = Path(out_path or "fwlens-junit.xml")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(to_junit(breaches), encoding="utf-8")
        return path


def markdown_summary(breaches: list[Breach], *, functions: int, modules: int, max_items: int = 20) -> str:
    """A pull-request-free Markdown summary of the findings, for $GITHUB_STEP_SUMMARY or an MR note."""
    lines = ["## FWLens analysis", "",
             f"{len(breaches)} finding(s) across {functions} function(s) and {modules} module(s).", ""]
    if not breaches:
        return "\n".join(lines) + "\n"
    counts: dict[str, int] = {}
    for b in breaches:
        counts[b.metric] = counts.get(b.metric, 0) + 1
    lines += ["| Metric | Findings |", "| --- | ---: |"]
    lines += [f"| {m} | {n} |" for m, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))]

    def ratio(b: Breach) -> float:
        return (b.value / b.threshold) if b.threshold else float("inf")

    worst = sorted(breaches, key=lambda b: (-ratio(b), b.file, b.line or 0))[:max_items]
    lines += ["", f"### Largest findings (top {len(worst)})", "",
              "| Where | Function | Metric | Value | Threshold |", "| --- | --- | --- | ---: | ---: |"]
    for b in worst:
        where = f"{b.file}:{b.line}" if b.line else b.file
        lines.append(f"| `{where}` | {b.function or ''} | {b.metric} | {b.value:g} | {b.threshold:g} |")
    if len(breaches) > len(worst):
        lines.append(f"\n{len(breaches) - len(worst)} more not shown.")
    return "\n".join(lines) + "\n"


def running_on_gitlab() -> bool:
    return os.environ.get("GITLAB_CI", "").lower() == "true"


def default_gitlab_report_path() -> Path:
    base = os.environ.get("CI_PROJECT_DIR")
    return Path(base) / DEFAULT_GITLAB_REPORT if base else Path(DEFAULT_GITLAB_REPORT)
