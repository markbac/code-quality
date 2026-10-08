# RTOS, state machines and diagrams

[Back to the guide contents](../../FWLENS_GUIDE.md)

## RTOS task/synchronisation analysis

Extracts tasks, semaphores, mutexes, mailboxes, queues, events, and reader/writer locks
from RTOS API call sites, cross-referenced through the existing call graph to work out
which task each sync-object usage belongs to. Currently implements embOS; disabled by
default.

```yaml
rtos:
  kind: embos
```

That alone is enough -- the defaults are verified against the real embOS V5.18.3.0
`RTOS.h` (SEGGER), current (non-deprecated) function names only. embOS's older
`OS_CreateCSema`/`OS_WaitCSema`/`OS_Use`/... style aliases are plain object-like
`#define`s with no argument reordering, so a call site using them resolves to these same
canonical names by the time libclang builds the AST (macro expansion happens during
parsing) -- they don't need separate config entries.

> **Task descriptor tables need a second config block.** A very common pattern is a
> `static const` array of task-descriptor structs (designated initializers: `.tcb = ...,
> .name = ..., .priority = ...`) created generically in a loop -- one `OS_TASK_Create`
> call site whose arguments are all `pTask->field` (runtime struct access), not one
> literal call per task. `task_functions` can't recover per-task data from that (there's
> nothing but a struct pointer at the call site); fwlens reads the array's initializer
> directly instead, via a second config block:
> ```yaml
> rtos:
>   kind: embos
>   task_table_types:
>     TaskEntry_t:                # your struct type name
>       tcb: tcb                  # struct member -> semantic field
>       name: name
>       priority: priority
>       routine: taskFn
>       stack: stack
>       stack_size: stackSize
> ```
> Both detection paths run and merge into the same task list; a call-site match that's
> obviously just the generic creation-loop call (runtime struct-member access on both
> the TCB and routine fields, not a resolvable identifier) is filtered out rather than
> shown as a confusing extra "task" once the real per-entry data is available from the
> table. If you don't use a task table, only `task_functions` applies and this block can
> stay unset.

> **Return-value handle APIs (FreeRTOS and similar) need one more config key.** embOS's
> creation functions write the handle to an output-pointer argument --
> `OS_MUTEX_Create(&mutex, ...)` -- so the object's variable name is always `args[0]`.
> FreeRTOS's are the opposite: `q = xQueueCreate(10, sizeof(int))` returns the handle,
> with nothing object-shaped in the arguments at all (`args[0]` there is the queue
> length, an integer -- reading it as the object name would silently produce garbage).
> List any creation function that works this way under `rtos.return_value_functions`,
> and fwlens reads the assignment target captured during the AST walk instead:
> ```yaml
> rtos:
>   kind: freertos
>   queue_functions: [xQueueCreate]
>   mutex_functions: [xSemaphoreCreateMutex]
>   return_value_functions: [xQueueCreate, xSemaphoreCreateMutex]
> ```
> Only the *creation* call needs this -- usage functions (`xQueueSend`, `xSemaphoreTake`,
> etc.) still take the handle as `args[0]` the same way on both RTOSes, so
> `usage_functions` doesn't need any special handling. The assignment-target capture only
> looks at the *direct* parent of the call (a plain `x = call(...)` or `Type x = call(...)`)
> -- a handle threaded through an intermediate helper function or a more complex expression
> (e.g. `arr[i] = xQueueCreate(...)`) won't be picked up.

> **One real difference to know about:** embOS's older convenience macros for task
> creation (`OS_TASK_CREATE`, `OS_CREATETASK`) synthesise the `StackSize` and
> `TimeSlice` arguments and, in one case, swap the priority/routine argument order
> relative to the modern `OS_TASK_Create`/`OS_TASK_CreateEx` functions they expand into.
> Since libclang expands macros before fwlens ever sees the AST, this doesn't matter for
> detection -- the call is recorded under the expanded function name with the expanded
> argument list either way -- but it does mean a stack-size argument synthesised as
> `sizeof(pStack)` by the macro shows up as unresolved raw text (correctly -- there's no
> literal there to resolve), and very occasionally the raw-text reconstruction for a
> macro-expanded argument loses a wrapping operator like `sizeof(...)` even when it
> correctly finds the underlying variable name inside it. The resolved *value* fields
> are never affected by this -- they only ever populate from something that parsed
> cleanly as a literal, cast-stripped where necessary (a plain priority literal passed
> through a macro often arrives wrapped as `(OS_PRIO)(5)`; that's handled).

Three analyses run automatically once tasks/objects are extracted:

- **Priority collisions** -- two or more tasks created at the same resolved priority.
  Not necessarily wrong (embOS round-robins same-priority tasks), but worth confirming
  it's intentional.
- **Priority inversion candidates** -- a plain counting semaphore (`OS_SEMAPHORE_Create`,
  no priority inheritance in embOS) waited on by tasks of different priority. A
  lower-priority task holding it can block a higher-priority waiter indefinitely if a
  medium-priority task preempts it -- the classic priority-inversion problem (Sha,
  Rajkumar, Lehoczky 1990). embOS's mutex (`OS_MUTEX_Create`, priority-inheriting) and
  reader/writer lock are not flagged -- only plain counting semaphores lack inheritance.
- **Unused objects** -- created but never touched by any configured usage function --
  either dead code, or a usage function name missing from `rtos.usage_functions`.

Surfaced in the console summary, `rtos_tasks.csv`/`rtos_sync_objects.csv`/
`rtos_object_usage.csv`, the `rtos` key in the JSON export, and the HTML report's RTOS
tab -- including an inline SVG **RTOS object graph**: tasks (sorted by priority) and
sync objects as separate node types, edges coloured by access kind (amber = wait, green
= signal). This is a genuinely different architecture axis from the file/module
dependency graph -- organised by runtime concurrency structure rather than source
layout, so it can surface a design issue (like a priority-inversion-prone shared
semaphore) invisible to any file-structure-based view.

---

## State machine detection

Detects switch-based state machines: the switch's controlling expression is treated as
the "state variable" (by raw text, not semantic resolution), and any assignment to that
same variable within a case's body is treated as a transition from that case's label to
the assigned value. Runs automatically, no config needed.

> **Heuristic, not semantic analysis.** Doesn't resolve enum/macro values to compare
> across cases, so `STATE_IDLE` and `0` would be treated as different states even if
> they're the same enum constant under the hood. Doesn't track control flow precisely
> either -- an assignment inside an `if` inside a case is still attributed to that case,
> correctly for most real state-machine code but not guaranteed. Needs 2+ cases and at
> least one detected transition to be reported; most switches aren't state machines.

Surfaced in the console summary, `state_machines.csv`, `state_machines` in the JSON
export, and the HTML report's State Machines tab -- each with an inline SVG diagram
(states in a circular layout, directed edges for transitions, self-loops as a small loop
above the node).

---

## Source viewer & report file size

`fwlens_report.html`'s in-browser source viewer (click any function/file name to jump
to source) embeds every first-party file's content directly in the HTML, so the report
stays a single self-contained file -- no companion files, works from a USB stick or an
email attachment, nothing to keep in sync. That embedded text is compressed (raw
deflate) before being written into the file and decompressed once, synchronously, when
the report first loads, using a small vendored pure-JS inflate implementation
(`tinyinflate`, ~3KB, MIT licensed -- `fwlens/output/vendor/`) rather than a full
gzip/zlib-in-JS library, to keep the amount of extra bundle weight added for the
decompressor itself minimal. Real C source compresses roughly 85-90% with this
approach, which matters increasingly as a codebase grows -- the embedded source text is
by far the largest contributor to the report's file size once a project reaches
hundreds of files.

`output.source_embed_loc_limit` (default 10000 lines) still applies the same as before
-- files longer than this are skipped from embedding entirely (their entries in the
report show "Source not available" rather than jumping to source) since a single
enormous generated/vendored file isn't worth the size cost either way, compressed or not.

---

## Architecture & call-graph diagrams

Add `diagrams` to `output.formats` and run `report` to generate two whole-codebase views in
`<reports_dir>/diagrams/`:

```yaml
output:
  formats: [html, csv, json, diagrams]
```

- **`architecture.md`** -- a Mermaid flowchart, modules grouped into subgraphs by architecture
  layer, coloured by zone (red = zone of pain, yellow = zone of uselessness/warning, green =
  main sequence). Generated directly from the module dependency graph fwlens already builds,
  so it can't drift out of sync with the codebase the way a hand-maintained diagram can.
- **`dependency_graph.svg`** -- the same graph rendered with matplotlib/networkx, node size
  proportional to LOC, colour by zone.

For a scoped, on-demand view of one function instead of the whole codebase:

```powershell
.\Run-FwLens.ps1 call-graph --function sarReturnDataPacket --direction callers --depth 4
```

- `--direction callers` -- blast radius: what would be affected if this function changes
- `--direction callees` -- dispatch chain: everything this function reaches
- `--direction both` -- both directions in one diagram (default)
- `--depth N` -- max hops from the root function (default 4)

Writes a Mermaid diagram to `<reports_dir>/diagrams/call_graph_<function>_<direction>.md`, root
function highlighted in blue, high-structural-debt functions in red.

> **Note:** the module dependency graph is also embedded directly in `fwlens_report.html`'s
> Architecture tab as inline SVG -- boxes grouped by layer, coloured by zone, clickable
> through to source, no external file needed. It's a hand-rolled look-alike (same layout
> idea: layer bands, zone colours, dependency arrows) rather than literally Mermaid's
> renderer, since embedding the real Mermaid.js bundle would add roughly 1-2MB to every
> report for a report that's otherwise ~150KB, and the priority was keeping
> `fwlens_report.html` a single self-contained file with no external CDN and no bundle
> weight. The separate `architecture.md`/`dependency_graph.svg` files remain available if
> you specifically want Mermaid's own rendering (e.g. to paste into other docs-as-code
> tooling) or the matplotlib/networkx force-directed layout.

