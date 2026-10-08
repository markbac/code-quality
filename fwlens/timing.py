"""
How long a run takes and where the time goes: named phases (nested ones are indented), the slowest
files to parse, and a table printed when the command ends. The same rows go into
fwlens_results.json and the report's Inputs tab, so two runs can be compared.
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Iterator

MIN_SHOWN_SECONDS = 0.05          # shorter phases are summed into one line
SLOW_FILES_KEPT = 10


@dataclass
class Phase:
    name: str
    depth: int
    seconds: float = 0.0
    detail: str = ""


@dataclass
class RunTimer:
    phases: list[Phase] = field(default_factory=list)
    slow_files: list[tuple[str, float]] = field(default_factory=list)
    show: bool = True
    _started: float = field(default_factory=time.perf_counter)
    _depth: int = 0

    def reset(self) -> None:
        self.phases.clear()
        self.slow_files.clear()
        self._started = time.perf_counter()
        self._depth = 0

    @contextmanager
    def phase(self, name: str, detail: str = "") -> Iterator[Phase]:
        entry = Phase(name, self._depth, detail=detail)
        self.phases.append(entry)                 # appended on entry, so the list is in start order
        self._depth += 1
        began = time.perf_counter()
        try:
            yield entry
        finally:
            entry.seconds = time.perf_counter() - began
            self._depth -= 1

    @property
    def total(self) -> float:
        return time.perf_counter() - self._started

    def note_files(self, seconds_by_file: dict[str, float]) -> None:
        self.slow_files = sorted(seconds_by_file.items(), key=lambda kv: -kv[1])[:SLOW_FILES_KEPT]

    def as_dict(self) -> dict:
        return {"total_seconds": round(self.total, 2),
                "phases": [{"phase": p.name, "depth": p.depth, "seconds": round(p.seconds, 2), "detail": p.detail}
                           for p in self.phases],
                "slowest_files": [{"file": f, "seconds": round(s, 2)} for f, s in self.slow_files]}

    def render(self, console) -> None:
        """Print the table: phases in order, with the share of the whole run, then the slowest files."""
        from rich.table import Table
        if not self.phases:
            return
        total = max(self.total, 1e-9)
        table = Table(title=f"Run time {total:.1f}s", title_justify="left", show_edge=False, pad_edge=False)
        table.add_column("Phase")
        table.add_column("Seconds", justify="right")
        table.add_column("Share", justify="right")
        short = 0.0
        shorter = 0
        for p in self.phases:
            if p.seconds < MIN_SHOWN_SECONDS:
                short += p.seconds
                shorter += 1
                continue
            label = "  " * p.depth + p.name + (f" [dim]{p.detail}[/dim]" if p.detail else "")
            table.add_row(label, f"{p.seconds:.1f}", f"{100 * p.seconds / total:.0f}%")
        if shorter:
            table.add_row(f"[dim]{shorter} shorter phases[/dim]", f"{short:.1f}", f"{100 * short / total:.0f}%")
        console.print()
        console.print(table)
        if self.slow_files and self.slow_files[0][1] >= 1.0:
            files = Table(title="Slowest files to parse", title_justify="left", show_edge=False, pad_edge=False)
            files.add_column("File")
            files.add_column("Seconds", justify="right")
            for name, seconds in self.slow_files:
                if seconds >= 1.0:
                    files.add_row(name, f"{seconds:.1f}")
            console.print(files)


timer = RunTimer()


def phase(name: str, detail: str = ""):
    return timer.phase(name, detail)
