# Reference

[Back to the guide contents](../../FWLENS_GUIDE.md)

## Configuration reference

All settings live in `config.yaml` next to `Run-FwLens.ps1`.

### `tool`

```yaml
tool:
  libclang_path: C:\Program Files\LLVM\bin\libclang.dll
```

Path to `libclang.dll`. Install LLVM from the official releases and point here. Optional: without
it FWLens uses `LIBCLANG_PATH` or the libclang bundled with the package.

Other `tool` keys, all optional:

| Key | Meaning |
|---|---|
| `target` | clang target; default `arm-none-eabi`, `native` for host builds |
| `sysroot`, `system_include_dirs` | where the compiler's headers are; setting `system_include_dirs` skips auto-detection |
| `clang_args` | extra arguments for every translation unit, e.g. `["-std=c11"]` |
| `auto_detect_includes` | ask the compiler for its include paths (default `true`) |
| `parse_error_threshold` | share of files with fatal or error diagnostics tolerated by `--fail-on-parse-error` (default `0.0`) |
| `jobs`, `parse_timeout`, `parse_cache` | parallel parse workers, seconds per file, parse cache -- see [Commands](getting-started.md#commands) |

### `project`

```yaml
project:
  ewp: ..\EWARM\Project.ewp        # path to IAR .ewp (relative to config.yaml)
  configuration: Release         # IAR build configuration name -- must match exactly
  proj_dir: C:\...\App\EWARM    # $PROJ_DIR$ in the .ewp -- usually the EWARM directory
  toolkit_dir: C:\...\arm       # $TOOLKIT_DIR$ for resolving IAR include paths
```

> **Important:** `proj_dir` must be the directory *containing* the `.ewp` file (the EWARM
> directory), not the project root. The `.ewp` uses `$PROJ_DIR$\..\Src\...` to navigate
> from `EWARM` up to the source tree.

### `scope`

```yaml
scope:
  first_party: [Src, Inc]       # path fragments classified as your code
  sdk:         [sdk]            # Silicon Labs / third-party SDK
  third_party_lib: [Lib]        # compiled libraries
  analyse:     [first_party]    # which classes to run full analysis on
```

Only files under `first_party` paths appear in function metrics, dead code, and coupling
tables. SDK and Lib files are registered as boundary stubs for type resolution and call
graph edges.

### `iar_compat_defines`

Preprocessor defines injected into every libclang translation unit to paper over IAR-specific
syntax that the Clang front-end does not natively understand.

```yaml
iar_compat_defines:
  - __ICCARM__=1
  - -U__GNUC__                  # undefine clang's built-in __GNUC__ so CMSIS picks IAR path
  - __ARM_ARCH_7EM__=1
  - __ARM7EM__=1                # required by some RTOS headers
  - __ICCARM_INTRINSICS_VERSION__=2   # stops cmsis_iccarm.h including intrinsics.h
  - "static_assert(e,m)="       # C11 static_assert as a no-op
  - __intrinsic=
  - __weak=
  # ... etc
```

Run `.\Run-FwLens.ps1 debug-parse` to auto-detect and fix missing headers or undeclared
built-in functions. The tool will create stub header files in `iar_stubs\` automatically.

### `layers`

Defines the architecture layer stack. Order matters: index 0 is the lowest layer.

```yaml
layers:
  - name: SDK
    paths: [sdk]
  - name: BSP
    groups: [drivers, isr]
  - name: RTOS
    groups: [rtos]
  - name: Middleware
    groups: [LwM2MClient, ModemMgr]
  - name: Services
    groups: [Prepayment, ValveControl]
  - name: Application
    groups: [BaseMeter, UiFSM]
  - name: Product
    groups: [Autotest]
```

A module is assigned to a layer by matching its IAR group name against `groups`, or its
file path against `paths`. The first matching rule wins. Unmatched modules are `Unknown`.

### `assert_names`

Function names treated as assertion calls for the assert-coverage metric:

```yaml
assert_names: [assert, ASSERT, MyProjectAssert]
```

Optional -- defaults to `assert`/`ASSERT`/`PSP_ASSERT`/`STATIC_ASSERT`/`_Static_assert`/
`static_assert`, plus `OS_Error` automatically when `rtos.kind: embos` is set (embOS's
`OS_ASSERT` is a macro that expands to `if (!cond) OS_Error(code)` -- it never appears as
its own call in the AST after preprocessing, so detecting the call it expands into is the
only way to see it; see [RTOS task/synchronisation analysis](rtos-and-diagrams.md#rtos-tasksynchronisation-analysis)).
If your codebase uses a different assert or error-report macro, list its expanded call
target here the same way, or fwlens will silently undercount assert coverage.

### `entry_points`

Functions listed here are excluded from dead code detection. Add your RTOS task entry
functions so they are not reported as dead:

```yaml
entry_points:
  - main
  - AppTask
  - ModemTask
  - PrepaymentTask
```

### `thresholds`

Breach thresholds used in the console summary and HTML report. Highlighted in red/yellow
when exceeded.

```yaml
thresholds:
  cyclomatic_complexity: 15
  cognitive_complexity: 20
  halstead_effort: 1000000
  halstead_volume: 8000
  block_depth: 5
  function_loc: 100
  parameter_count: 6
  return_path_count: 5
  magic_number_density: 0.15
  fan_out: 10
  instability_zone_of_pain: 0.3
  instability_zone_of_uselessness: 0.7
  main_sequence_distance: 0.5
  cohesion_min: 0.3                 # internal call cohesion below this = low cohesion
```

### `output`

```yaml
output:
  reports_dir: output/reports
  exports_dir: output/exports
  cache_dir: output/.cache
  db_path: output/fwlens.db
  formats: [html, csv, json]        # also plots, diagrams, sarif, sbom, cbom
  top_n: 20
  source_embed_loc_limit: 10000
  show_timing: true                  # print where the run time went when a command ends
```

Listing `sbom`, `cbom` or `sarif` in `formats` also adds a readable **SBOM**, **CBOM** or **SARIF**
tab to the HTML report: components with licences, versions and gaps; algorithms, protocols and weak
items with where they appear; and the SARIF results with the key metrics. The tabs read the same
documents the files contain.

The **SARIF** tab lists every result, not a top-N, and filters them in the page: by ruleset
(`misra-c-2012`, `barr-c-2018`, `fwlens` ...), by rule, by CWE, by level and by text in the file
name or message. Choosing a rule shows its help: what it checks, how it is checked (native, imported
or manual, and whether coverage is partial), how to fix it for the FWLens rules, the related CWEs
and where the standard is published. **By rule** and **By CWE** group the results that match the
filters, and a click on a rule or CWE filters to it. The **Show SDK and third-party code** box hides
results in those files. They appear only when `scope.analyse` includes `sdk` or `third_party_lib`:
the coding-standard checks then run on that code too.

An **Inputs** tab is always present. It shows the config as read (with its hash), the project
description and whether each file exists, the CMake, Make, IDE project, linker script and map files
found within three folders of the project (CMake targets and Make targets are listed), the
translation units by boundary class, group, extension, include path and define, and the settings
that shaped the run.

`reports_dir` holds the HTML report, `exports_dir` the CSV, JSON, SARIF, SBOM and CBOM files,
`cache_dir` the parse cache and `db_path` the [run history](gating-and-ci.md#run-history-trends-and-the-ratchet).
These paths are relative to the directory you run `fwlens` from. `top_n` is the number of top
offenders in the console summary. A source file longer than `source_embed_loc_limit` lines is not
embedded in the HTML source viewer.

### `cost_benefit`

```yaml
cost_benefit:
  cost_per_defect_static_usd: 100    # cost to fix a defect found by static analysis
  cost_per_defect_field_usd: 1000    # cost to fix the same defect after release
```

The unit costs behind the cost-benefit estimate. Set them to your own figures.

### `rtos`

The task, semaphore, mutex, mailbox, queue, event and read-write lock creation functions
(`task_functions`, `semaphore_functions`, `mutex_functions`, `mailbox_functions`,
`queue_functions`, `event_functions`, `rwlock_functions`) are described in
[RTOS task/synchronisation analysis](rtos-and-diagrams.md#rtos-tasksynchronisation-analysis). `wait_keywords`
(default `Wait`, `Get`, `Receive`, `Take`, `Lock`, `Blocked`) and `signal_keywords` (default
`Give`, `Put`, `Send`, `Unlock`, `Set`, `Pulse`) classify a called function as a wait or a signal
when its name contains one of them, case-insensitively; signal is checked first.

### Run timing

Every command that analyses a project ends with a table of where the time went: the phases in
order (nested ones indented, such as `Read project description` and `Parse source files` inside
`Parse project`), each phase's seconds and its share of the run, and the slowest files to parse.
Phases under 0.05 seconds are summed on one line, and files under a second are left out.

The same rows are written to `fwlens_results.json` under `meta.timing` (`total_seconds`, `phases`,
`slowest_files`) so two runs can be compared, and appear in the report's **Inputs** tab up to the
moment the report is built. Files restored from the parse cache cost nothing and are not listed.
`output.show_timing: false` removes the console table only.

### `sbom` and `cbom`

See [Software bill of materials](bills-of-materials.md#software-bill-of-materials-sbom) and
[Cryptography bill of materials](bills-of-materials.md#cryptography-bill-of-materials-cbom).

`pr_check`, `match`, `standards`, `git` and `estimation` are described in their own sections:
[PR / MR quality check](gating-and-ci.md#pr--mr-quality-check), [Moved and renamed code](gating-and-ci.md#moved-and-renamed-code),
[Coding standards](standards.md#coding-standards-misra-c-cert-c-barr-c-power-of-10), [Git history warnings](metrics-and-history.md#git-history-warnings)
and [COCOMO effort estimate](metrics-and-history.md#cocomo-effort-estimate).

---

## Metric reference

### Function-level metrics

#### Cyclomatic Complexity (CC)

The number of linearly independent paths through a function. Counts +1 for each:
`if`, `else if`, `while`, `for`, `do`, `case`, `&&`, `||`, `?:` (ternary).
Base value is 1. Threshold: **15**.

A CC of 1-5 is low risk. 6-15 is moderate. Above 15 is high risk -- difficult to test
exhaustively and statistically more likely to contain defects.

#### Cognitive Complexity

A measure of *how hard the code is to understand*, proposed by SonarSource. Unlike CC
which counts paths, cognitive complexity penalises structural nesting: a branch at depth 3
costs more than the same branch at depth 1. This better reflects the mental load on a
reader. Threshold: **20**.

#### Lines of Code (LOC)

Physical lines spanned by the function body (end line minus start line + 1). Does not
strip comments or blank lines -- this is a deliberate choice so the metric reflects the
actual volume of text a reviewer must read. Threshold: **100**.

#### Block Depth

Maximum nesting depth of `{}` compound statements within the function body. A depth of 1
is a single `if` block. Depth 5+ typically indicates overly nested control flow that should
be refactored into smaller functions. Threshold: **5**.

#### Parameter Count

Number of formal parameters. High parameter counts make functions harder to call correctly,
test, and mock. Threshold: **6**.

#### Return Path Count

Number of `return` statements. Multiple return points are not inherently wrong, but high
counts can make control flow hard to follow. Threshold: **5**.

#### Magic Number Density

`magic_number_count / LOC`. A magic number is any integer literal that is not 0 or 1
(which are structurally meaningful). High magic number density indicates values that should
be named constants. Threshold: **0.15** (more than 15 magic numbers per 100 lines).

#### Fan-out

Number of distinct functions called by this function. A high fan-out means a function
orchestrates many collaborators, making it difficult to test in isolation. Threshold: **10**.

#### Fan-in

Number of distinct callers of this function (within the analysed scope). A high fan-in
means a function is heavily depended upon and must be changed carefully.

#### Halstead Metrics

Halstead metrics treat source code as a sequence of operators and operands.

- `n1` -- number of distinct operators (`if`, `while`, `+`, `=`, function calls, etc.)
- `n2` -- number of distinct operands (variable names, literals)
- `N1` -- total operator occurrences
- `N2` -- total operand occurrences
- **Vocabulary** = `n1 + n2`
- **Length** = `N1 + N2`
- **Volume** = `Length × log2(Vocabulary)` -- information content of the function
- **Difficulty** = `(n1/2) × (N2/n2)` -- effort to write or understand
- **Effort** = `Volume × Difficulty` -- total cognitive work required; threshold **1,000,000**
- **Bugs** = `Volume / 3000` -- estimated number of latent bugs delivered

> **Implementation note:** fwlens computes Halstead by classifying AST cursor kinds
> rather than lexical token scanning. Operators include structural nodes
> (`if`, `while`, `+`, `=`, function calls, array subscripts, member access).
> Operands are identifiers and literals. This gives consistent cross-file results but
> may differ from line-counting tools such as lizard.

#### Maintainability Index (MI)

A composite score indicating how maintainable a function is, on a 0-100 scale. Higher
is better. Formula (MIwoc -- without comments):

```
MI = max(0, (171 - 5.2·ln(V) - 0.23·CC - 16.2·ln(LOC)) × 100/171)
```

Where `V` is Halstead volume, `CC` is cyclomatic complexity, `LOC` is lines of code.
A score below 20 indicates poor maintainability. Above 80 is considered good.

> Because Halstead volume feeds into MI, MI will be 100 for any function where Halstead
> collection fails (e.g. parse errors). Treat MI=100 on large/complex functions with
> suspicion.

#### Structural Debt Index (SDI)

A composite 0-1 score that ranks a function's technical debt relative to the rest of the
codebase. It is a weighted sum of percentile ranks across five metrics:

| Metric | Weight |
|---|---|
| Cyclomatic complexity | 30% |
| Halstead difficulty | 25% |
| Block depth | 20% |
| Fan-out | 15% |
| MI (inverted) | 10% |

A function with SDI=0.8 is in the top 20% most indebted functions in the codebase. The
score is relative -- it changes as the population changes. Use it to prioritise refactoring
effort rather than as an absolute quality gate.

#### Param Mutation Rate

Fraction of non-const pointer parameters that are written through (mutated) inside the
function body. A value of 1.0 means all pointer parameters are output parameters. This
metric helps identify whether a function's intent is to transform data (high mutation)
or read it (low mutation), and can surface accidental writes through pointer arguments.

---

### Module-level metrics

#### Instability (I)

Martin's instability: `I = Ce / (Ca + Ce)` where:

- `Ca` (afferent coupling) = number of other modules that call into this module
- `Ce` (efferent coupling) = number of other modules this module calls into

`I = 0` means fully stable (nothing it depends on can change without impact on it).
`I = 1` means fully unstable (depends on many others, nothing depends on it).

Instability is computed from the call graph, not the include graph. An edge exists between
module A and module B if any function in A calls any function defined in B.

#### Abstractness (A)

`A = type_decl_count / (type_decl_count + function_count)` where `type_decl_count` is the
number of `struct`, `enum`, `typedef`, and `union` *definitions* in the file.

A file that only defines functions is fully concrete (`A = 0`). A file that only declares
types is fully abstract (`A = 1`). Most `.c` files in an embedded codebase have low
abstractness because they implement rather than declare.

> **Limitation:** IAR `.ewp` files list only `.c` source files. Header files are not
> separate modules. This means abstractness is computed from type declarations *in the .c
> file only* -- types declared in `.h` files are not counted. As a result, A values tend
> to be lower than they would be in a full source model. Treat A as indicative rather
> than precise.

#### Main Sequence Distance (D)

`D = |A + I - 1|`

This measures how far a module is from the "main sequence" line `A + I = 1`, which
represents the ideal balance between abstractness and instability. A fully concrete stable
module (A=0, I=0) and a fully abstract unstable module (A=1, I=1) both lie exactly on the
main sequence. Threshold: **0.5**.

#### Average CC / Max CC

Average and maximum cyclomatic complexity across all functions in the module.

---

## Analysis sections explained

### Threshold Breaches

A count of how many first-party functions exceed each configured threshold, and what
percentage of the total function population that represents. Use this as a quick
health check -- a high breach percentage indicates systemic issues rather than isolated
hot spots.

### Exceedance Probabilities

For each metric, fwlens fits a log-normal distribution to the population of first-party
functions and computes `P(X > threshold)` -- the probability that a randomly chosen
function exceeds the threshold. This is more informative than raw breach counts because
it accounts for the shape of the distribution. A value of 33% for magic number density
means a third of the codebase is above threshold, not just a handful of outliers.

### Module Coupling (top instability)

The 20 most unstable modules, sorted by `I` descending. For each module:

- **Fan-in / Fan-out** -- afferent and efferent call edges
- **Instability** -- `Ce / (Ca + Ce)`; values near 1.0 mean the module depends on many
  others but nothing depends on it
- **MSD** -- distance from the main sequence; red if > 0.5
- **Zone** -- stable abstractions classification (see next section)
- **Cycle** -- whether this module is part of a circular dependency

### Stable Abstractions Violations

Based on Robert C. Martin's Stable Abstractions Principle: *stable modules should be
abstract; instable modules should be concrete.*

The scatter plot positions each module at `(I, A)`. The diagonal `A + I = 1` is the ideal
main sequence. Two danger zones:

**Zone of Pain** (`I < 0.3` and `A < 0.3`)
The module is concrete (few or no type declarations) and stable (few dependencies on
others). It is hard to change -- anything that depends on it will break if it changes --
but it provides no abstraction to justify that rigidity. Examples in embedded C: a hardware
register map module, a utility string library. These are not necessarily wrong, but they
should be noticed and consciously accepted.

**Zone of Uselessness** (`I > 0.7` and `A > 0.7`)
The module is abstract (many type declarations, few implementations) and unstable (depends
on many others). Nobody depends on it, so its abstractions serve no purpose. This is
uncommon in C codebases and usually indicates dead interface headers.

> **Why is A = 0 for most modules?**
> In a `.c`-only EWP model, abstractness is approximated from type declarations *inside
> the .c file*. Most implementation files define few or no structs/enums/typedefs because
> types are declared in `.h` files which are not visible as separate modules. As a result,
> A is genuinely low for most files and the Zone of Pain contains many modules that are
> simply well-factored concrete implementations with stable interfaces. When the Zone of
> Pain count is high, interpret it as "these modules are stable and concrete" rather than
> "these modules are problematic." Modules that genuinely belong in the zone of pain are
> those that frequently require change but cannot be changed without breaking many callers.

### Architecture Layer Violations

fwlens detects dependency direction violations in the call graph based on the layer stack
defined in `config.yaml` (index 0 = lowest, highest index = highest layer).

A **downward** call (higher layer calls lower layer) is expected and not a violation.
A **upward** call (lower layer calls higher layer) is a violation.

Two subtypes:

| Type | Meaning |
|---|---|
| `upward` | Caller is exactly one layer below the callee. e.g. Services calling Product |
| `skipped` | Caller skips one or more layers. e.g. Connectivity calling Product (skipping Services) |

Skipped violations are considered more severe because they bypass intended mediation layers.

**Common causes in embedded C:**
- State machine modules (Services) reaching directly into UI modules (Product) to trigger
  display updates -- should use an observer/callback pattern instead
- Connectivity layer modules calling into high-level business logic (Product) -- should
  be mediated through a Services layer interface
- RTOS modules calling into Connectivity code -- suggests missing abstraction in the RTOS
  layer

Each violation lists the source module, its layer, the target module, and its layer. Use
these to identify where interface boundaries need to be introduced or tightened.

### Dead Code Candidates

Functions with zero in-project callers, after excluding:
- Functions listed in `entry_points` (RTOS task functions, `main`)
- Functions flagged as ISRs (matched by `_IRQHandler` suffix or IAR `__interrupt` attribute)

**Important caveats:**
- Functions called via function pointers are not detected as called and will appear dead
- Functions registered in jump tables or dispatch arrays appear dead
- Functions called only from SDK/Lib code (which is not analysed) appear dead
- RTOS task entry functions must be added to `entry_points` to be excluded

Do not remove dead code candidates without manual verification. Use the list to identify
candidates for review, not for automatic deletion.

### ISR Latency Risk

For each detected ISR (interrupt service routine), fwlens estimates latency risk as:

```
risk_score = own_CC + sum(transitive_callee_CC) + call_depth × 2
```

Where:
- `own_CC` -- cyclomatic complexity of the ISR itself
- `transitive_callee_CC` -- sum of CC of every function reachable from the ISR via the call graph
- `call_depth` -- maximum call chain length from the ISR

This is not a timing estimate -- it is a structural risk indicator. A high score means the
ISR has a deep, complex call chain which increases the risk of jitter, re-entrancy issues,
and latency violations.

The `~` badge indicates a non-estimable ISR where the call chain contains recursive calls
or indirect calls through function pointers.

**Interpretation:** UART and SPI interrupt handlers sharing the same transitive CC pool
(because they call the same underlying drivers) is expected. Concern arises when an ISR
calls business logic functions with high CC, or when call depth exceeds 5-6 levels.

---

## Known limitations and sanity notes

### Fan-in is lower than expected

fwlens resolves call edges by matching callee names to function definitions in the analysed
scope. Functions called from SDK or Lib code (which is registered as a boundary stub, not
parsed) will show fan_in = 0 even if they are heavily used. Fan-in is therefore a
*lower bound* on actual usage.

### Operators written inside macro bodies

Cyclomatic and cognitive complexity count `&&` and `||`, and write tracking recognises `=`,
`++` and `--`, from the operator token written at the use site. An operator that appears only
inside a macro body (for example `#define BOTH(a, b) ((a) && (b))`) is not visible there and is
not counted, so macro-heavy code can under-report complexity and global writes. Earlier
versions read the whole token range from the macro definition to the use site, which
over-reported and attributed unrelated code to the macro.

On littlefs `lfs.c` and `lfs_util.c` (current master, `tool.target: native`) the complexity of
`lfs_dir_find` is 23, `lfs_file_flushedwrite` 16 and `lfs_dir_commit` 4, unchanged by this
change; parsing took 41 s before and 4.6 s after, mostly from removing the repeated
whole-subtree token scans.

### Halstead metrics vs lizard/ccccc

fwlens uses AST cursor kinds for Halstead collection rather than lexical token scanning.
This is more accurate for complex macro-heavy code but produces different values from
line-counting tools. The relative ranking between functions is reliable; the absolute
values differ from published C benchmarks.

### MI = 100 for functions with Halstead = 0

If Halstead collection fails for a function (parse error in body, function contains only
inline assembly, etc.), volume = 0 and MI defaults to 100. This is technically the formula
result (`log(0)` is avoided) but is misleading for large complex functions. Filter out
`mi_woc = 100` when analysing maintainability across the codebase.

### Cognitive complexity undercount

Cognitive complexity counts structural nesting penalties but does not currently penalise
`break`, `continue`, `goto`, or recursion -- all of which add mental load. The metric is
therefore a lower bound on true cognitive complexity.

### Dead code count of ~939 is high

An embedded RTOS codebase has many legitimately uncalled functions from within the static
analysis scope: functions registered in dispatch tables, called via function pointers,
callback handlers passed to libraries, and protocol handler functions. The dead code list
should be filtered manually against these patterns. Add confirmed entry points to the
`entry_points` list in `config.yaml` to reduce false positives.

### Architecture violations require correct layer config

Layer violation detection is only as good as the layer definitions in `config.yaml`. If
IAR group names or path fragments are wrong or incomplete, modules will land in `Unknown`
and be excluded from violation detection. Run `.\Run-FwLens.ps1 debug` to see how every
module is classified.

---

## Metrics Etiquette

Grady & Caswell (1987) and Grady (1992) devote real space to *how* to use metrics
responsibly, not just how to compute them -- worth stating explicitly here, since
fwlens's output is easy to share more widely than a single engineer's own analysis.

- **Composite risk ranking identifies code to refactor, not developers to blame.**
  `composite_risk`, `hotspots`, and the structural debt index describe the *code's*
  history and structure. A function scoring high on any of these reflects the
  accumulated shape of a codebase, often across many contributors and years -- it is
  not a scorecard for whoever last touched the file.
- **Churn and coupling reflect history, not individual performance.** A file with high
  `commit_count` or `change_coupling` was worked on a lot; that alone says nothing about
  the quality of that work. Combine with structural metrics (as `hotspots` already does)
  before drawing any conclusion, and even then, the conclusion is about the *file*.
- **Don't use any of this for individual performance reviews.** None of fwlens's metrics
  were designed or validated for attributing credit or blame to a person, and Goodhart's
  law applies immediately once a metric is tied to evaluation: people optimise the
  number, not the underlying thing it was a proxy for.
- **Aggregate numbers are approximate -- state them as such.** The `defect_correlations`,
  `reliability_growth`, and `cost_benefit` estimates all say so directly in their own
  output, but it's worth restating: these are directional indicators from limited,
  heuristic data (commit-message keyword matching, small sample counts), not measured
  facts. Report them with the same care Grady describes for "reporting hours" and
  "reporting useless but mandated metrics" -- a number without its confidence and
  method attached invites false precision.
- **Recalibrate before trusting defaults.** COCOMO's constants, the cost/benefit
  placeholder figures, and the textbook complexity thresholds were all calibrated
  elsewhere, not on this codebase. `defect_correlations` exists specifically to let you
  check whether the metrics that are supposed to predict risk actually do so here --
  use it before treating any threshold as gospel.

---

## References

The academic and industry sources behind fwlens's metrics, in the style of an annotated
bibliography -- what each source is, and which fwlens metric it backs.

**Complexity**

- McCabe, T.J. (1976). "A Complexity Measure." *IEEE Transactions on Software
  Engineering*, SE-2(4), 308-320. -- Cyclomatic complexity (`cyclomatic_complexity`).
- Halstead, M.H. (1977). *Elements of Software Science*. Elsevier North-Holland. --
  Halstead software science metrics (`halstead_*`, `mi_woc`/maintainability index).
- Campbell, G.A. (2018). "Cognitive Complexity: A New Way of Measuring
  Understandability." SonarSource whitepaper. -- Cognitive complexity
  (`cognitive_complexity`); a structural-nesting-weighted successor to McCabe's metric
  aimed at matching human perception of how hard code is to follow, not just how many
  paths it has.

**Coupling and structure**

- Henry, S., and Kafura, D. (1981). "Software Structure Metrics Based on Information
  Flow." *IEEE Transactions on Software Engineering*, SE-7(5), 510-518. -- Information
  flow complexity (`information_flow_complexity`, IF4).
- Martin, R.C. (1994). "OO Design Quality Metrics: An Analysis of Dependencies." --
  Instability (I) and abstractness (A), the stable-abstractions model underlying
  `instability`, `abstractness`, `main_sequence_distance`, and the pain/uselessness
  zone classification.

**Software process / hotspot analysis**

- Tornhill, A. (2015). *Your Code as a Crime Scene*. Pragmatic Bookshelf. -- Churn x
  complexity hotspot analysis (`hotspots`, `hotspot_score`, Ch.2-4), change coupling
  ("logical coupling", `change_coupling`, Ch.7-8), architecture-level change coupling
  (`layer_coupling`, Ch.8/10), judging hotspots by name (`vague_name_flag`, Ch.5),
  complexity trend over time (`complexity_trends`, Ch.6), and code ownership / knowledge
  maps (`ownership_risks`, Ch.11-13) -- the actual methodological source for all of these,
  not just a general reference.
- Nagappan, N., Murphy, B., and Basili, V. (2008). "The Influence of Organizational
  Structure on Software Quality." *ICSE '08*. -- Empirical basis for the code-ownership
  chapters above: number of distinct contributors and ownership diffusion correlate with
  defect density independently of complexity, the finding `ownership_fragmentation` and
  `ownership_risk_score` are built to surface.

**Estimation**

- Boehm, B.W. (1981). *Software Engineering Economics*. Prentice-Hall. -- Basic COCOMO
  81 effort/schedule model (`effort_estimate`, COCOMO effort estimate).
- Grady, R.B., and Caswell, D.L. (1987). *Software Metrics: Establishing a Company-Wide
  Program*. Prentice-Hall. -- Predecessor to the 1992 Grady book below; original source
  for the cost/benefit-of-static-analysis framing behind `cost_benefit`, and for much of
  the metrics-etiquette material this guide's [Metrics Etiquette](#metrics-etiquette)
  section draws on.

**Reliability**

- Goel, A.L., and Okumoto, K. (1979). "Time-Dependent Error-Detection Rate Model for
  Software Reliability and Other Performance Measures." *IEEE Transactions on
  Reliability*, R-28(3), 206-211. -- Goel-Okumoto NHPP model (`reliability_growth`).
- Musa, J.D. (1999). *Software Reliability Engineering*. McGraw-Hill. -- Covers the
  Musa-Okumoto logarithmic Poisson NHPP model as an alternative to Goel-Okumoto; fwlens
  only implements the latter, so this is the natural next reference if the exponential
  discovery-rate assumption behind Goel-Okumoto doesn't fit your defect data well (e.g.
  discovery rate that keeps dropping rather than settling).

**RTOS / concurrency**

- Sha, L., Rajkumar, R., and Lehoczky, J.P. (1990). "Priority Inheritance Protocols: An
  Approach to Real-Time Synchronization." *IEEE Transactions on Computers*, 39(9),
  1175-1185. -- The priority-inversion problem and priority-inheritance protocols;
  `rtos_inversion_risks` is a static-analysis proxy for detecting the structural
  precondition (a non-inheriting semaphore shared across priorities), not a
  schedulability proof.

**Defect analysis**

- Grady, R.B. (1992). *Practical Software Metrics for Project Management and Process
  Improvement*, Ch. 6 ("Complexity Increases Costs"). Hewlett-Packard Professional
  Books, Prentice-Hall. -- Complexity-vs-defect correlation (`defect_correlations`) --
  fwlens's coarse, commit-history-based approximation of Grady's complexity/defect-
  density correlation work.

**General reference / further reading**

- Fenton, N., and Bieman, J. (2014). *Software Metrics: A Rigorous and Practical
  Approach*, 3rd ed. CRC Press. -- Broad academic treatment of size, structure, and
  quality measurement; the source for the information-flow and stable-abstractions
  citations above, and a good next read for anything not covered directly by fwlens
  (e.g. Bayesian-network defect prediction, which fwlens deliberately doesn't attempt --
  it needs expert-elicited probability tables to be meaningful, not just derived data).
- Grady, R.B. (1992). *Practical Software Metrics for Project Management and Process
  Improvement*. Hewlett-Packard Professional Books, Prentice-Hall. -- Practitioner-level
  treatment of the same territory from an industrial (HP) measurement programme;
  particularly good on the organisational side (metrics etiquette, public vs private
  data) that fwlens itself has no opinion on -- see also the direct citations for the
  complexity-vs-defect correlation feature above.
- Chidamber, S.R., and Kemerer, C.K. (1994). "A Metrics Suite for Object Oriented
  Design." *IEEE Transactions on Software Engineering*, 20(6), 476-493. -- The CK
  metrics suite (WMC, DIT, NOC, CBO, RFC, LCOM). Not implemented in fwlens -- the G460
  firmware is C, not C++/OO, so class-coupling and inheritance-depth metrics don't
  apply -- but a natural next reference if the codebase ever gains a significant
  C++ component.
