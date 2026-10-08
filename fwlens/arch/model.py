"""The architecture model: plain dataclasses, stored on the project model and written to the JSON export."""

from __future__ import annotations

from dataclasses import dataclass, field

EDGE_KINDS = ("callback", "state", "type", "call", "include")
DEFAULT_WEIGHTS = {"callback": 4.0, "state": 3.0, "type": 2.0, "call": 1.0, "include": 0.5}


@dataclass
class Edge:
    source: str                 # unit (translation unit path, forward slashes)
    target: str
    kind: str                   # one of EDGE_KINDS
    count: int
    weight: float               # count x the kind's weight
    evidence: list = field(default_factory=list)      # [[file, line], ...], a few examples


@dataclass
class Interface:
    unit: str
    public: list = field(default_factory=list)          # functions declared in a header
    internal: list = field(default_factory=list)        # static, or declared in no header (or only a private one)
    tables: list = field(default_factory=list)          # dispatch tables defined here (function-pointer arrays)
    abstract_headers: list = field(default_factory=list)   # headers with a struct of function pointers


@dataclass
class Leak:
    source: str                 # unit that reaches in
    target: str                 # unit whose internal symbol it uses
    symbol: str
    kind: str                   # "undeclared" (no public header declares it) or "private-header"
    file: str
    line: int


@dataclass
class ArchModel:
    weights: dict = field(default_factory=dict)
    units: list = field(default_factory=list)
    edges: list = field(default_factory=list)
    interfaces: list = field(default_factory=list)
    leaks: list = field(default_factory=list)

    def as_dict(self) -> dict:
        from dataclasses import asdict
        return asdict(self)
