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
class Component:
    id: str
    name: str
    units: list = field(default_factory=list)
    source: str = ""            # pinned | group | group+community | community | directory
    cohesion: float = 0.0       # share of the members' coupling that stays inside the component
    configured: list = field(default_factory=list)    # configured layers and IDE groups of the members
    layer: str = ""            # the configured layer most of the members are in


@dataclass
class Drift:
    unit: str
    directory: str
    directory_component: str    # the component most of this directory belongs to
    best_component: str         # the component this unit is coupled to most
    outside: float              # share of its coupling outside the directory's component (0 to 1)
    weight: float               # its total coupling weight


@dataclass
class Subsystem:
    component: str              # component id
    name: str                   # component name
    domain: str                 # ui, comms, storage ... or unclassified
    domain_name: str
    confidence: str             # high, medium or low
    evidence: list = field(default_factory=list)
    scores: dict = field(default_factory=dict)


@dataclass
class LayerModel:
    layers: list = field(default_factory=list)          # [{level, components, cycle}] top first; level 0 is the bottom
    level_of: dict = field(default_factory=dict)        # component name -> inferred level
    cycles: list = field(default_factory=list)          # [[component names]]
    back_edges: list = field(default_factory=list)      # upward dependencies inside cycles
    next_layer_share: float = 1.0                       # share of downward weight that goes to the next layer down
    skip_edges: list = field(default_factory=list)      # downward dependencies that skip one or more layers
    disagreements: list = field(default_factory=list)   # where the configured layer order and the inferred one differ


@dataclass
class PatternFinding:
    id: str
    name: str
    scope: str                  # system or subsystem
    confidence: str             # high, medium or low
    score: float
    signals: list = field(default_factory=list)      # [{signal, weight, detail}] that fired
    component: str = ""         # the component, for a subsystem pattern


@dataclass
class Violation:
    rule: str                   # rule id, "intended-layers" or "no-cycles"
    kind: str                   # rule | layer | cycle
    source: str                 # unit (or component for layers and cycles)
    target: str
    source_component: str
    target_component: str
    file: str
    line: int
    message: str
    kinds: list = field(default_factory=list)       # dependency kinds involved


@dataclass
class ArchModel:
    weights: dict = field(default_factory=dict)
    units: list = field(default_factory=list)
    edges: list = field(default_factory=list)
    interfaces: list = field(default_factory=list)
    leaks: list = field(default_factory=list)
    ops_headers: list = field(default_factory=list)     # headers with a struct of function pointers, owned or not
    components: list = field(default_factory=list)
    drift: list = field(default_factory=list)
    differences: list = field(default_factory=list)
    subsystems: list = field(default_factory=list)
    layering: LayerModel = field(default_factory=LayerModel)
    patterns: list = field(default_factory=list)
    violations: list = field(default_factory=list)

    def as_dict(self) -> dict:
        from dataclasses import asdict
        return asdict(self)
