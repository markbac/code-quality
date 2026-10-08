"""
Pattern detection: add up the weights of the signals that fire, map the score to a confidence.

The bundled rules are in fwlens/arch/patterns.yaml. A finding lists the signals that fired with their
details, so the verdict can be checked. Several patterns can hold at once (an RTOS design can also be
layered), and a pattern below its `low` threshold is not reported.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from fwlens.arch.model import PatternFinding
from fwlens.arch.signals import SIGNALS, Context
from fwlens.config import ConfigError

_BUNDLED = Path(__file__).parent / "patterns.yaml"
LEVELS = ("low", "medium", "high")


@dataclass
class Pattern:
    id: str
    name: str
    scope: str                  # system or subsystem
    signals: dict               # signal name -> weight
    thresholds: dict            # low, medium, high -> minimum score
    domain: str = ""            # subsystem patterns: the domain they apply to


def _parse(items, where: str) -> list[Pattern]:
    if not isinstance(items, list):
        raise ConfigError(f"{where}: patterns must be a list")
    out = []
    for raw in items:
        if not isinstance(raw, dict) or not raw.get("id"):
            raise ConfigError(f"{where}: every pattern needs an 'id'")
        pid = str(raw["id"])
        signals = raw.get("signals")
        if not isinstance(signals, dict) or not signals:
            raise ConfigError(f"{where}: pattern '{pid}' needs 'signals' as a mapping of signal name to weight")
        unknown = sorted(set(signals) - set(SIGNALS))
        if unknown:
            raise ConfigError(f"{where}: pattern '{pid}' uses unknown signal(s) {unknown}; known: {sorted(SIGNALS)}")
        if any(isinstance(w, bool) or not isinstance(w, (int, float)) or w <= 0 for w in signals.values()):
            raise ConfigError(f"{where}: pattern '{pid}' signal weights must be numbers above 0")
        thresholds = raw.get("thresholds") or {}
        total = sum(signals.values())
        if set(thresholds) - set(LEVELS) or any(not isinstance(v, (int, float)) for v in thresholds.values()):
            raise ConfigError(f"{where}: pattern '{pid}' thresholds are {list(LEVELS)} as numbers")
        thresholds = {"low": total * 0.4, "medium": total * 0.6, "high": total * 0.8, **thresholds}
        scope = str(raw.get("scope", "system"))
        if scope not in ("system", "subsystem"):
            raise ConfigError(f"{where}: pattern '{pid}' scope must be system or subsystem")
        if scope == "subsystem" and not raw.get("domain"):
            raise ConfigError(f"{where}: subsystem pattern '{pid}' needs a 'domain'")
        out.append(Pattern(pid, str(raw.get("name") or pid), scope, {str(k): float(v) for k, v in signals.items()},
                           {k: float(v) for k, v in thresholds.items()}, str(raw.get("domain", ""))))
    return out


def load_patterns(extra: list[dict] | None = None) -> list[Pattern]:
    try:
        raw = yaml.safe_load(_BUNDLED.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"patterns {_BUNDLED}: {exc}") from exc
    patterns = {p.id: p for p in _parse(raw["patterns"], "bundled patterns")}
    for p in _parse(extra or [], "architecture.patterns"):
        patterns[p.id] = p
    return list(patterns.values())


def evaluate(pattern: Pattern, ctx: Context) -> PatternFinding | None:
    fired, score = [], 0.0
    for name, weight in pattern.signals.items():
        ok, detail = SIGNALS[name](ctx)
        if ok:
            score += weight
            fired.append({"signal": name, "weight": weight, "detail": detail})
    level = ""
    for lvl in LEVELS:
        if score >= pattern.thresholds[lvl]:
            level = lvl
    if not level:
        return None
    return PatternFinding(pattern.id, pattern.name, pattern.scope, level, round(score, 2), fired,
                          ctx.component.name if ctx.component else "")


def detect(model, arch, config, patterns: list[Pattern]) -> list[PatternFinding]:
    """System patterns for the whole project, then subsystem patterns for each matching component."""
    findings: list[PatternFinding] = []
    everything = {u for u in arch.units}
    system = Context(model, arch, config, everything)
    for p in patterns:
        if p.scope == "system":
            f = evaluate(p, system)
            if f:
                findings.append(f)
    by_component = {c.id: c for c in arch.components}
    for sub in arch.subsystems:
        comp = by_component[sub.component]
        ctx = Context(model, arch, config, set(comp.units), comp)
        for p in patterns:
            if p.scope == "subsystem" and p.domain == sub.domain:
                f = evaluate(p, ctx)
                if f:
                    findings.append(f)
    order = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: (f.scope != "system", order[f.confidence], -f.score, f.id, f.component))
    return findings
