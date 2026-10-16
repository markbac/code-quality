## Architecture brief

`fwlens architecture brief` writes one JSON file, `fwlens_brief.json`, that describes the code base for a reader who has not seen it: a person new to the project, or an LLM asked to explain or change the code. Add `brief` to `output.formats` to have `report` write it too.

```bash
fwlens architecture brief --config config.yaml                      # exports/fwlens_brief.json
fwlens architecture brief --config config.yaml --output brief.json
```

`fwlens_results.json` holds every metric for tools and dashboards. The brief is organised by the questions a reader asks instead: what runs when, where time is handled, how an update reaches flash. It adds facts the other exports do not carry, such as comments, types, constants, the start-up order and log strings. Every finding names the file and line it came from, with paths relative to the repository root.

### What the file contains

| Key | Contents |
| :--- | :--- |
| `schema`, `how_to_read` | The format version (`fwlens-brief/1`) and notes on how far to trust each section |
| `meta` | FWLens version, project, build configuration, git revision, RTOS and counts |
| `build` | Defines common to every file, defines that differ per file, include paths and compiler flags |
| `files`, `directories` | Every first-party source and header with its header comment, component, domain, layer, size, functions, includes, footprint, churn and owner |
| `architecture` | Components, dependencies between them, inferred layers, cycles, system and subsystem patterns, rule violations, leaks, events and drift |
| `execution` | Entry points (reset, `main`, RTOS tasks, ISRs) with what each reaches and which concerns it touches; the start-up sequence from `main` up to the scheduler start or the main loop, with each init function's own calls; the main loop body; RTOS tasks, objects and risks |
| `interrupts` | Handlers with their calls, shared globals and stack estimate, `NVIC_SetPriority` priorities, and ISR risks |
| `peripherals` | Peripherals used through HAL or LL calls (`HAL_UART_*`) and register access (`USART1->`), by function |
| `state_machines` | Switch-based machines with their states resolved against the enum that declares them and the enum constants no transition reaches; and state-as-function-pointer machines (`s_state = st_idle;`) |
| `concerns` | Clock and time, firmware update and boot, power, watchdog and faults, persistent storage, comms, security, and logging (see below) |
| `memory` | Linker script memory regions (GNU `MEMORY`, IAR `.icf` regions), the map file totals and flash and RAM per component |
| `interfaces` | Dispatch and command tables with their handlers, public and internal functions per unit, and operations-struct headers |
| `types`, `constants` | Enums with their values, structs with their fields, each with its comment; `#define` constants grouped as time, clock, comms, memory, size, version or priority |
| `globals` | Every global with its readers, writers, ISR access, volatile risk and the concerns that use it |
| `symbols` | Every first-party function: signature, comment, callers, callees, globals read and written, the entry points that reach it, its concerns and its metrics |
| `log_messages` | The text of log, trace and print calls, by function |
| `quality`, `history` | The most complex functions, composite risk, hotspots, dead code, clones, TODO markers, stack risks, include problems; ownership, change coupling and activity from git |
| `tests`, `documents`, `vocabulary` | Test files and which functions they call; Markdown and text documents in the repository with their titles and first paragraphs; the most common words in identifiers |
| `gaps` | What was looked for and not found, and files that parsed with errors |

### Concerns

Each concern has roles, and a function takes a role when it calls a known API, has a known name, holds certain words in its name, or uses a register. The catalogue is `fwlens/brief/concerns.yaml`. For every role the brief lists the functions, the evidence, whether they run in an ISR and which entry points reach them; `not_found` lists the roles nothing matched.

- **Clock and time**: clock tree set-up, tick sources, time reads, the RTC, calendar conversion, time synchronisation (SNTP, GPS), software timers and delays. `findings` adds tick comparisons that break when the counter wraps (`now > deadline` instead of comparing the difference), blocking delays reached from an interrupt, and the tick counters with who reads and writes them.
- **Firmware update and boot**: bootloader jumps and vector table relocation, receiving an image, flash erase and write, CRC, hash and signature checks, version checks, bank activation, confirm and rollback, and reset. `flow` puts these in order, traces the call chains from receiving an image to writing flash with the checks on each chain, and lists the gaps, such as no signature check found.
- **Power, watchdog, storage, comms, security and logging**: the functions that sleep or wake, kick the watchdog or handle faults, read and write non-volatile memory or parameters, drive a bus or a network stack, use cryptography or authentication, and log or assert.

### Limits

The brief is built from a static analysis. Concerns, state machines, the start-up sequence, types, constants and log strings are read from names, calls and text, so they are leads to check rather than proof; "not found" means not detected. Code behind `#if` branches that the build configuration does not compile is not seen. Calls through function pointers are followed only through the dispatch tables FWLens recognises.
