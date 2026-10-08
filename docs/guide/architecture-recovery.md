# Architecture recovery

[Back to the guide contents](../../FWLENS_GUIDE.md)

## Architecture recovery

FWLens builds a model of the architecture as implemented, from the parse it already does, and writes it to
the JSON export under `architecture`. The design is in
[`docs/ARCHITECTURE_RECOVERY.md`](../ARCHITECTURE_RECOVERY.md) and the programme is tracked in issue #133.
Every finding carries its evidence and a high, medium or low confidence, as the CBOM does. Inferred results are
shown next to what you configured (`layers:`), never instead of it.

```yaml
architecture:
  enabled: true        # false skips the stage
  weights: {callback: 4, state: 3, type: 2, call: 1, include: 0.5}
```

### Typed, weighted dependencies

Each dependency between two units (translation units) has a kind, a count and a weight (count times the weight
of its kind). The existing call and include graphs are unchanged; these edges are built beside them.

| Kind | Meaning |
| :--- | :--- |
| `callback` | a unit stores or passes the address of another unit's function (dispatch table, `&handler`) |
| `state` | a unit uses another unit's global, or a struct in its header embeds another unit's struct |
| `type` | a unit uses a type that another unit declares |
| `call` | a function calls a function defined in another unit |
| `include` | a header of one unit includes a header of another |

Embedding another unit's struct binds layout and lifetime, so it weighs more than passing a `uint32_t`.
Each edge keeps up to three file and line pairs as evidence. Type, struct and address-of facts come from a
lexical read of the source, so a type hidden behind a macro is not seen.

### Interfaces and encapsulation leaks

A function is **public** when a header declares it, and **internal** when it is `static`, declared in no header,
or declared only in a private header. `architecture.private_headers` lists the private header patterns (default
`*_priv.h`, `*_private.h`, `*_internal.h`, `*/internal/*`, `*/private/*`; `[]` means none). A dispatch table is an
interface, and so is a header with a struct of function pointers (an ops struct).

An edge from one unit to an internal symbol of another is a **leak** (`architecture.leaks` in the JSON): usually an
`extern` written in the caller to dodge the header (`undeclared`), or an include of a private header
(`private-header`). Each leak gives the source and target units, the symbol, and the file and line.

### Components and directory drift

Components are inferred, in this order:

1. Components you pin with `architecture.components` (`name` and `units`, path patterns such as `drivers/*`).
2. Units in the same IDE group (IAR, Keil, Eclipse). A group of more than `architecture.max_component_units`
   (default 40) is split by community detection.
3. Everything else, by community detection (Louvain) on the weighted dependency graph. The seed is fixed, so the
   same input always gives the same components. `architecture.resolution` (default 1) makes them smaller when
   raised. Units with no dependencies are grouped by directory.

Each component reports its members, how it was found (`pinned`, `group`, `group+community`, `community`,
`directory`), its cohesion (the share of its members' coupling that stays inside it) and the configured layers
and IDE groups of its members. Where the components disagree with your configuration, `differences` lists it:
a component that spans several configured layers, or an IDE group spread over several components. The configured
modules and layers stay as they were.

**Drift:** each directory is assigned the component most of its units belong to. A unit with at least
`architecture.drift_threshold` (default 0.6) of its coupling outside that component is listed, with the
component it is coupled to most. A file in `drivers/` that is coupled almost entirely to the application is the
typical case.

### Subsystem domains

Each component is given a domain from the catalogue in `fwlens/arch/domains.yaml`: `ui`, `comms`, `storage`,
`power`, `metering`, `security`, `boot_update`, `diagnostics`, `hal` and `os`. The domain is chosen from the names
the component uses, with this evidence, weighted: file names (3 each), included headers (4), RTOS task names (2),
and function names (1 each, up to 8). A word matches a whole word of an identifier split on case and underscores,
so `key` does not match `monkey`.

| Confidence | Meaning |
| :--- | :--- |
| `high` | a score of 12 or more from at least two kinds of evidence, or a domain you pinned |
| `medium` | a score of 5 or more |
| `low` | a score of 2 or more |
| `unclassified` | nothing matched; the report says so instead of guessing |

`architecture.subsystems` pins a domain to units (`domain` and `units`, path patterns; the domain applies to a
component when most of its units match). `architecture.domains` adds your own domains, or replaces a bundled one
with the same `id`: `id`, `name`, `words` (identifier words) and `includes` (header name patterns). The labels
are in `architecture.subsystems` in the JSON export, each with its evidence.

### Inferred layers

Components are collapsed from the unit edges, strongly connected components are condensed, and each component gets
a **level**: 0 for one that depends on nothing else, otherwise one more than the highest level of what it depends
on. Level numbers rise upward, the same way as the order of `layers:` (the first is the lowest). The result
(`architecture.layering` in the JSON) has:

- `layers`: the inferred stack, top first, with the components of each level
- `cycles`: groups of components that depend on each other, which share a level, and `back_edges`: the upward
  dependencies inside each cycle (the weakest ones to remove to break it)
- `next_layer_share`: the share of downward weight that goes to the layer directly below. Near 1 is a strict
  layered design, lower is a relaxed one, and `skip_edges` lists the dependencies that skip layers
- `disagreements`: where your configured `layers:` order and the inferred one differ. A dependency that the
  configuration calls upward is listed with a note saying whether the dependencies agree (the code breaks the
  configured order) or not (the configured order may be wrong). Nothing is applied: the configured layers and the
  existing layer violations are unchanged.

### System patterns

FWLens names the architectural patterns the project follows, from the rules in `fwlens/arch/patterns.yaml`. A
rule adds up the weights of the **signals** that fire (small named checks on the parse, in
`fwlens/arch/signals.py`) and maps the score to a confidence. Several patterns can hold at once, and one below its
`low` threshold is not reported. Each finding (`architecture.patterns` in the JSON) lists the signals that fired and
what each found, so the verdict can be checked.

| Pattern | Main signals |
| :--- | :--- |
| `layered` | three or more inferred layers, no cycles, most downward weight to the next layer, configured `layers:` |
| `hal_ports` | structs of function pointers, several objects of one such type, the hardware abstraction at the bottom |
| `super_loop` | `main` (or an entry point) loops forever calling several functions, no RTOS, short interrupt handlers |
| `rtos_tasks` | two or more RTOS tasks, semaphores or queues, a queue or mailbox shared by tasks |
| `event_driven` | subscribe and register calls, publish and post calls, three or more `EVENT_` identifiers |
| `state_machine_table` | detected state machines, tables named for states or events |
| `pipeline` | a chain of components, each depending on the next, covering most of the project |
| `plugin_registry` | function-pointer structs with several implementations, and registration calls |
| `big_ball_of_mud` | many components in cycles, no layering, dense dependencies (anti-pattern) |
| `god_component` | one component holding a large share of the units and linked to most others (anti-pattern) |

`architecture.patterns` adds a rule or replaces a bundled one with the same `id`. A rule has `id`, `name`, `scope`
(`system` or `subsystem`), `signals` (signal name to weight; an unknown name is an error that lists the known ones),
and optional `thresholds` (`low`, `medium`, `high` scores; the default is 40, 60 and 80 per cent of the total weight).
Pattern verdicts are heuristics for review, not a statement of conformance.

### Subsystem patterns

A pattern rule with `scope: subsystem` and a `domain` is tested only on components of that domain, so the
evidence can be specific. A finding names the component. The starter set covers the UI and comms domains; the
others (storage, power, metering, cross-cutting) can be added with `architecture.patterns` using the same signals.

| Domain | Pattern | Main signals |
| :--- | :--- | :--- |
| ui | `ui_widget_tree` | calls into a widget library (`lv_`, emWin `WM_` and `GUI_`), input events |
| ui | `ui_screen_state_machine` | a state machine in the component, a table of screens or menus |
| ui | `ui_menu_table` | an array of label and handler pairs |
| ui | `ui_model_view_split` | reads two or more globals owned elsewhere and writes none |
| ui | `ui_event_loop` | key, button or touch event functions, a queue or mailbox, a state machine |
| ui | `ui_display_driver_layering` | framebuffer, flush or blit functions, a dependency on the hardware abstraction |
| comms | `comms_protocol_stack` | three or more layers of units inside the component, calls only going down |
| comms | `comms_isr_ring_buffer` | a buffer touched by an interrupt handler and by other code, short interrupt handlers |
| comms | `comms_dma_double_buffer` | DMA half and complete handling |
| comms | `comms_frame_parser` | a state machine and parse, decode or frame functions |
| comms | `comms_command_dispatcher` | a table of command handlers, parser functions |
| comms | `comms_task_per_interface` | two or more RTOS tasks in the component, a queue |
| comms | `comms_gateway` | a receive function of one interface calling the send function of another |

An indexed store such as `buf[i] = x` is counted by the parse as a read, so the buffer signals look at reads and
writes together.

### Exports and the report view

`fwlens architecture export` (or `architecture` in `output.formats`, so `report` writes them too) writes to
`<output.reports_dir>/architecture/`:

- `architecture.puml`: a PlantUML component diagram. Components sit in a package per inferred level (top first),
  a component with a dispatch table or ops struct gets an interface, dependencies are labelled by kind, and the
  upward dependencies inside a cycle are drawn in red (`<<violation: cycle>>`). A dependency the configured layer
  order calls upward is drawn in orange.
- `architecture.dsl`: a Structurizr DSL workspace (C4). Subsystem domains are containers and components are
  components, with a container view and a component view per domain.

The HTML report has a **Recovered architecture** section in the Architecture tab: the patterns and their evidence,
the inferred layers, the components and subsystems with their confidence, directory drift and encapsulation leaks.
The whole model is in the JSON export under `architecture`. With `architecture.enabled: false` there is nothing to
export, and the command says so.

### Intended architecture and rules

State the architecture you intend and FWLens checks the recovered one against it.

```yaml
architecture:
  intended_layers: [App, Services, HAL]      # top to bottom
  strict_layers: false                       # true also reports a dependency that skips a layer
  forbid_cycles: false                       # true reports every upward dependency inside a cycle
  rules:
    - {id: ui-no-metering, from: {domain: ui}, to: {domain: metering}}
    - {id: hal-only-registers, from: {not: {layer: HAL}}, to: {symbol: "*_REG_*"}}
    - {id: app-only-services, from: {component: App}, to: {layer: Services}, allow: true}
```

- **`intended_layers`** lists layers top to bottom. A component may depend on its own layer and on lower ones; a
  dependency on a higher layer is reported. A name is matched to a component by its configured layer, its name or
  its domain. An item can also be a mapping, `{name, components: [globs], domains: [ids], units: [path globs]}`.
- **`rules`** have an `id`, a `from` and a `to` side, and optionally `allow` and `kinds`. A side matches by
  `component` (glob), `domain`, `layer` (an intended layer) or `unit` (a path glob), several together, and `not`
  inverts them. `allow: false` (the default) forbids the dependency. `allow: true` says the `from` units may depend
  on nothing outside `to`. `kinds` limits the rule to some dependency kinds (`call`, `callback`, `state`, `type`,
  `include`). `to: {symbol: "*_REG_*"}` matches identifiers used in the `from` units (not with `allow: true`).
- A bad rule (unknown key, missing side, duplicate id) stops the run with a message naming it.

Each violation (`architecture.violations` in the JSON) has the rule, the two components, the dependency kinds and a
file and line. They also become **findings**: metric `arch-<rule id>`, category `architecture`, one per violating
pair, with stable ids. They go through the baseline, the ratchet, SARIF and `--fail-on-breach` like any other breach,
so a new layer breach, forbidden dependency or cycle fails CI while the existing ones stay recorded.

`fwlens architecture adopt` writes the recovered components (pinned by file), domains and inferred layers, top
first, to `architecture.adopted.yaml` (`--output` changes it). Merge it under `architecture:` in `config.yaml`: the first run then
reports nothing the code does not already do, and you tighten the layers and add rules from there.

### Drift against a baseline or an earlier revision

```powershell
fwlens architecture save --config config.yaml --output architecture.snapshot.json
fwlens architecture diff --config config.yaml --baseline architecture.snapshot.json
fwlens architecture diff --config config.yaml --revision origin/main --fail-on-new
```

`architecture save` writes the model with repo-relative paths, so snapshots from different checkouts compare.
`architecture diff` compares this run with a snapshot (`--baseline`, or `architecture.baseline` from the config) or
with the code at a git revision (`--revision`, analysed in a temporary worktree with the installed FWLens). It lists,
worst first: new cycles, new rule and layer violations, new encapsulation leaks, dependencies added and removed
between components, components added, removed or renamed, files that moved to another component, level changes, the
coupling trend per component, and patterns that appeared, disappeared or changed confidence, then what was resolved.
`--output FILE` also writes the differences as JSON, and `--fail-on-new` exits 1 when there is a new cycle,
violation or leak.

Components are matched by the files they hold (an overlap of at least half), not by name, because an inferred name
can change between runs; a renamed component is reported as renamed, not as one removed and one added.

With `architecture.baseline` set, every `analyze`, `report` and `export` run also compares with the snapshot: the
differences are in the JSON export (`architecture.since_baseline`) and in the **Recovered architecture** section of the
report. A baseline file that is missing or not a snapshot is shown as an error there and does not stop the run.

### Variants

Conditional compilation can change the structure, so one combined view of a product line is misleading. Build the
model per variant and compare them:

```powershell
fwlens architecture variants --config config.yaml --configuration G460 --configuration G480
fwlens architecture variants --config g460.yaml --config g480.yaml
```

With one `--config` and two `--configuration` names, each run sets `project.configuration` to the name (the build
configuration or target in the IAR, Keil or Eclipse project file). With two `--config` files, each is analysed as it
is (for example two `compile_commands.json`); a `--configuration` per file overrides its configuration. The result
lists what only one variant has, in the same terms as `architecture diff`: components, files, dependencies between
components, cycles, files in a different component, and differences in domain and patterns. It is printed and written
to `<output.exports_dir>/architecture_variants.json` (`--output FILE` changes it).

### Publish and subscribe

FWLens maps events from publisher to broker to subscriber (`architecture.events` in the JSON, and the **Events** table
in the report):

- A call is a **registration** when its name has a word like `subscribe`, `register`, `attach`, `listen` or `install`
  and one argument is a function defined in the project (the callback, `&handler` or `handler`). The event is the
  first other argument.
- A call is a **publication** when its name has a word like `publish`, `post`, `emit`, `notify` or `raise`. The event
  is its first argument.
- For a broker whose names say nothing, list it exactly. Argument positions start at 0:

```yaml
architecture:
  register_calls: [{function: EventBus_Hook, id_arg: 0, callback_arg: 1}]
  publish_calls:  [{function: EventBus_Kick, id_arg: 0}]
```

Each event lists its publishers (function, file, line), the registration function that connects it (the broker) and
the subscribers (the callback, the function that registered it, and the callback's component). An event that has both
sides across two components is drawn in the PlantUML diagram as a blue dependency labelled `<<event NAME>>`, and in the
Structurizr model as "publishes NAME via BROKER". These flows are runtime coupling, so they are **not** added to the
dependency edges that the layers, cycles and rules use. They do feed the `event_driven` pattern. The mapping is
lexical: a registration through a macro, or an event identifier built at run time, is not seen.

### Activity by component

With git history, FWLens groups what it already knows per file by component (`architecture.activity` in the JSON,
and the **Activity** tables in the report):

- **Hotspots**: commits, fix commits and the worst function hotspot score in each component.
- **Ownership**: the main authors of the component's files and how fragmented the rest is. List teams to see which
  components are edited by several of them; patterns match author names, case-insensitively:

```yaml
architecture:
  teams: {web: ["ann*", "cy *"], backend: ["bob *"]}
```

- **Hidden coupling**: components whose files change together with no dependency between them.
- **Structural only**: components with a strong dependency (weight 5 or more, both with 5 or more commits) whose
  files never change together.
- **Shared state**: globals used from more than one component, ranked by interrupt access, missing `volatile`, and
  whether the components belong to different domains.

Every row is a place to look, not a verdict. Ownership uses each file's main author. Without git history only the
shared state table is filled.

### Trust boundary paths

`architecture.trust_paths` (the **Trust boundaries** table in the report) shows how data that enters through a
communication interface can reach sensitive code. For each entry point and each kind of sink, FWLens reports the
shortest chain of calls that leaves the entry point's component, function by function, with the components it crosses.

- **Entry points**: by default the functions nothing in the project calls (interrupt handlers, task bodies) inside a
  `comms` component.
- **Sinks**: by default any function in a `security` component (kind `crypto`), a `storage` component (`storage`) or a
  `boot_update` component (`update`).
- **CBOM link**: if a function on the path calls an API in the CBOM catalogue, the path lists the API, its library and
  the catalogue entry, so it can be matched with the entries in the CBOM.

To choose your own, give each item exactly one of `domain`, `component` or `function` (a name pattern). A `function`
entry is always an entry point; a sink also has a `kind` label:

```yaml
architecture:
  trust_entries: [{domain: comms}, {function: "*_rx_isr"}]
  trust_sinks:
    - {kind: crypto, domain: security}
    - {kind: config, function: "cfg_write_*"}
```

Only direct calls are followed, up to ten calls deep. A path through a function pointer or a dispatch table is not seen.

### Footprint by component

With `project.map_file` set, `architecture.footprint` (and the **Footprint by component** table in the report) adds up
each component's flash and RAM from the linker map, using the sizes the map support already attaches to each file,
with its share of the whole map. A component none of whose files appear in the map is shown as having no map data,
not as zero bytes; `mapped` of `units` says how many of its files were found. Sizes are per object, so a file that
the linker did not name by its stem, or a library object, is not counted. Without a map file there is no table.

### Advice: breaking cycles and the interface catalogue

Two tables are advice only. They change nothing and add no findings.

- **Cycle suggestions** (`architecture.cycle_suggestions`): for each cycle of components, the dependencies whose removal
  makes it acyclic at the fewest call sites, with a few examples of where they are. A cycle of up to 12 components is
  solved exactly (fewest call sites, then fewest dependencies); a larger one uses a greedy cut that is not guaranteed
  to be the smallest, and says so (`exact: false`).
- **Interface catalogue** (`architecture.interface_catalogue`): each component's public functions (declared in a
  non-private header) with the components that call them (fan-in), and the exports no other component uses. An
  interrupt handler, entry point, `main`, event callback or function stored in a dispatch table is never listed as
  unused, because the call graph does not show how it is reached.

