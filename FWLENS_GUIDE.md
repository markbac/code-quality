# fwlens -- Embedded C Architecture & Static Analysis Platform

## Contents

- [Quick start](#quick-start)
- [Commands](#commands)
- [Directory mode (no .ewp)](#directory-mode-no-ewp)
- [Baseline / breach gating](#baseline--breach-gating)
- [GitLab integration](#gitlab-integration)
- [PR / MR quality check](#pr--mr-quality-check)
- [Two-hash comparison](#two-hash-comparison)
- [Project-wide auto-stub](#project-wide-auto-stub)
- [Diagnostic clusters](#diagnostic-clusters)
- [Standalone plots](#standalone-plots)
- [File-level metrics](#file-level-metrics)
- [Hotspot analysis](#hotspot-analysis)
- [Bug-fix-weighted hotspots](#bug-fix-weighted-hotspots)
- [Judge hotspots by name](#judge-hotspots-by-name)
- [Complexity trend over time](#complexity-trend-over-time)
- [Hotspot visualisation](#hotspot-visualisation)
- [ISR / main-loop shared-variable risk](#isr--main-loop-shared-variable-risk)
- [Worst-case stack per entry point](#worst-case-stack-per-entry-point)
- [Tech debt scanning](#tech-debt-scanning)
- [Clone detection](#clone-detection)
- [Change coupling](#change-coupling)
- [Architecture-level change coupling](#architecture-level-change-coupling)
- [Commit heatmaps](#commit-heatmaps)
- [Commit date (activity) heatmap](#commit-date-activity-heatmap)
- [Code ownership / knowledge maps](#code-ownership--knowledge-maps)
- [Information flow complexity](#information-flow-complexity)
- [COCOMO effort estimate](#cocomo-effort-estimate)
- [Reliability growth](#reliability-growth)
- [Composite risk ranking](#composite-risk-ranking)
- [RTOS task/synchronisation analysis](#rtos-tasksynchronisation-analysis)
- [State machine detection](#state-machine-detection)
- [Architecture & call-graph diagrams](#architecture--call-graph-diagrams)
- [Configuration reference](#configuration-reference)
- [Metrics Etiquette](#metrics-etiquette)
- [References](#references)
- [Metric reference](#metric-reference)
- [Analysis sections explained](#analysis-sections-explained)
- [Known limitations and sanity notes](#known-limitations-and-sanity-notes)

---

## Quick start

No separate setup step needed -- the first `Run-FwLens.ps1` command bootstraps the
virtual environment automatically via `setup.ps1` if `.venv` doesn't exist yet.

```powershell
# Run full analysis and print summary to terminal
.\Run-FwLens.ps1 analyze

# Generate HTML report + CSV + JSON exports
.\Run-FwLens.ps1 report

# Export CSV + JSON only (faster, no HTML)
.\Run-FwLens.ps1 export

# Diagnose parse problems on a single file
.\Run-FwLens.ps1 debug-parse
```

Pass `-NoClean` to skip the automatic `.pyc` cache purge (faster re-runs when no files changed):

```powershell
.\Run-FwLens.ps1 analyze -NoClean
```

---

## Commands

| Command | Description |
|---|---|
| `analyze` | Parse EWP, compute all metrics, print console summary |
| `report` | `analyze` + write `output/reports/fwlens_report.html` + CSV + JSON |
| `export` | `analyze` + write CSV + JSON only |
| `debug-parse` | Test libclang on a single in-scope file; auto-creates stub headers for missing IAR toolchain headers |
| `debug` | Show EWP parse results and boundary classification without running analysis |

`analyze` and `report` both accept `--baseline`, `--fail-on-breach`, `--update-baseline`,
`--accept-all`, `--accept-id`, and `--prune` -- see [Baseline / breach gating](#baseline--breach-gating).
`analyze`, `report`, and `export` all accept `--auto-stub` -- see
[Project-wide auto-stub](#project-wide-auto-stub).
`report` also writes standalone PNG plots when `plots` is listed in `output.formats` -- see
[Standalone plots](#standalone-plots) -- and Mermaid/SVG diagrams when `diagrams` is listed --
see [Architecture & call-graph diagrams](#architecture--call-graph-diagrams).
`diff-breach` compares two prior JSON exports -- see [Two-hash comparison](#two-hash-comparison).
`call-graph` generates an on-demand scoped diagram for one function -- see
[Architecture & call-graph diagrams](#architecture--call-graph-diagrams).

---

## Directory mode (no .ewp)

Set `project.source_dir` instead of `project.ewp` to analyse a plain folder of C sources
with no IAR project file -- everything else (`analyze`, `report`, `export`, baselining,
plots) works the same way:

```yaml
project:
  source_dir: C:\Projects\some-library
scope:
  first_party: [Src, Inc]
  third_party_lib: [Lib]
```

```powershell
.\Run-FwLens.ps1 analyze --config config.yaml
```

fwlens recursively globs `*.c` under `source_dir` and adds every directory that contains a
header as an include path for every file -- there's no compile database in this mode, so
this is intentionally blunt rather than per-file precise. Boundary classification
(`first_party`/`sdk`/`third_party_lib`) uses the same `scope` config as EWP mode, matched
against each file's path segments; a file under no configured path defaults to
`first_party`. There's no IAR group tree in directory mode, so architecture layer
assignment falls back to path-based matching only (`layers[].groups` rules never match).

`project.ewp` and `project.source_dir` are mutually exclusive; `debug` and `debug-parse`
are EWP-specific diagnostics and aren't available in directory mode.

---

## Baseline / breach gating

fwlens can gate a CI run on threshold breaches, the same way the older ccccc-based
`code_governance` toolkit did: breaches are given a stable id, checked against a stored
`baseline.json`, and the run only fails on breaches that are **new or have gotten worse**
since the baseline was captured. Breaches already accepted into the baseline at their
current severity do not fail the build.

Breach ids do not contain a line number, so inserting lines above a function never changes
its id. Paths are relative to the repository root with forward slashes, so the same id is
produced on a laptop and on CI:

```text
Src/BaseMeter/BaseMeter.c:sarReturnDataPacket:cyclomatic_complexity   # function-level
Src/BaseMeter/BaseMeter.c:main_sequence_distance                      # module-level
```

A second function with the same name in one file gets `name#2`, numbered in source order.
The line number is stored as a separate field and is used only for locations.

### Moved and renamed code

Each function-level breach also stores a content fingerprint in the baseline. A breach is
matched to its baseline entry in tiers: same id, then same code (the function moved to
another file or was renamed), then same code with identifiers renamed, then similar or
partly overlapping code. Matches in the last group are listed as "matched loosely" and only
gate when the value got worse. A split function is reported as a change, not as a new breach.
Matching is heuristic: a function that is largely rewritten is reported as one resolved and
one new breach. Module-level breaches are matched by file path only.

Baselines written by earlier versions (ids with a line number) are migrated when read. They
have no fingerprints until you re-run with `--update-baseline`.

Function-level breaches are checked against: `cyclomatic_complexity`, `cognitive_complexity`,
`block_depth`, `function_loc`, `parameter_count`, `return_path_count`, `magic_number_density`,
`fan_out`. Module-level breaches are checked against `main_sequence_distance`. These are the
same threshold keys from the [`thresholds`](#thresholds) config section.

### Initial baseline creation

Accept every breach currently in the codebase:

```powershell
.\Run-FwLens.ps1 analyze --baseline baseline.json --update-baseline --accept-all
```

### CI enforcement

```powershell
.\Run-FwLens.ps1 analyze --baseline baseline.json --fail-on-breach
```

Exits with code 1 (propagated by `Run-FwLens.ps1`) if any breach is new or worse than the
baselined value; existing breaches at an unchanged severity are reported but don't fail the run.

### Removing resolved entries

`--update-baseline` only adds or updates entries by default. Add `--prune` to also remove
entries that no longer match any breach:

```powershell
.\Run-FwLens.ps1 analyze --baseline baseline.json --update-baseline --accept-all --prune
```

### Accepting a specific new breach

```powershell
.\Run-FwLens.ps1 analyze --baseline baseline.json --update-baseline `
    --accept-id "Src/BaseMeter/BaseMeter.c:sarReturnDataPacket:cyclomatic_complexity"
```

> **Note:** baselining a breach accepts its *current* value. If the metric gets worse later
> (e.g. cyclomatic complexity rises from 20 to 25), it is reported as a new breach again --
> baselining is not an open-ended exemption for that function/metric.

---

## GitLab integration

`analyze` and `report` write a GitLab **Code Quality** report with `--gitlab-codequality PATH`.
When `GITLAB_CI=true` the report is written automatically to
`$CI_PROJECT_DIR/gl-code-quality-report.json`. GitLab compares it with the report from the
target branch and shows new and fixed findings in the merge request widget.

- Each finding has `description`, `check_name` (`fwlens/<metric>`), `severity`, `fingerprint`
  and `location` (repo-relative path with forward slashes, plus the start line).
- Fingerprints are derived from the stable breach id, which has no line number, so unrelated
  edits do not appear as new findings.
- Severity follows how far the value is over its threshold: under 25 % over is `minor`
  (`info` for note-level metrics such as `fan_out`), under 100 % over is `major`, beyond that
  `critical`. `blocker` is not used.
- Paths are made relative to `CI_PROJECT_DIR` on GitLab, so Windows runners produce the same
  forward-slash paths as Linux.

A reusable job lives in `ci/gitlab/fwlens.gitlab-ci.yml`:

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/markbac/code-quality/main/ci/gitlab/fwlens.gitlab-ci.yml'

fwlens:
  extends: .fwlens
  variables:
    FWLENS_CONFIG: config.yaml
    FWLENS_BASELINE: baseline.json   # optional: gate with --fail-on-breach
```

The template caches pip, keeps the artifact with `when: always` (so the report is published
even when the gate fails the job) and sets `expire_in: 2 weeks`. Set `allow_failure: true` on
the job while you introduce the gate.

Not included yet: a SAST report for coding-standard findings (planned with the MISRA/CERT
work) and an optional merge request summary note (planned with the PR/MR comparison).

---

## PR / MR quality check

`fwlens pr-comment` compares the current checkout with the target branch and posts **one**
comment on the pull request (GitHub) or merge request (GitLab) listing what is new, worse,
resolved or moved. `fwlens compare` does the same comparison without posting.

```text
## FWLens quality check: FAIL
| Findings | 3 -> 7 (+4) |   New 4 | Worsened 0 | Improved 0 | Resolved 0 | Moved or renamed 2 | Matched loosely 0
### New and worsened        (table: where, function, metric, value, threshold, was)
<details> Resolved / Moved or renamed / Matched loosely </details>
```

Findings are matched with the same stable identity as the baseline (see
[Moved and renamed code](#moved-and-renamed-code)), so a function that was moved, renamed or
extracted is listed as moved, not as one fixed plus one new.

### Where the reference results come from

1. `--base findings.json`: a findings file published by the target branch pipeline
   (`fwlens analyze --findings-json findings.json`). Fastest. A `baseline.json` also works.
2. `--base-ref origin/main`: analyses the merge-base of `HEAD` and the ref in a temporary git
   worktree. Slower, needs full git history (`fetch-depth: 0` on GitHub, `GIT_DEPTH: 0` on GitLab).
3. If neither is available the comment says so and the check does not fail.

### Options

| Option | Meaning |
|---|---|
| `--fail-on-new` | exit 1 when there are new or worsened findings (the status check) |
| `--uncertain-gates` | also fail on loosely matched findings, not only worse ones |
| `--current findings.json` | reuse findings from an earlier step instead of analysing again |
| `--post auto\|github\|gitlab\|none` | where to post, `auto` reads the CI environment |
| `--dry-run` | print the Markdown, post nothing |
| `--no-update` | create a new comment each time instead of updating the existing one |
| `--markdown FILE`, `--max-items N`, `--report-url URL` | output controls |

The comment is identified by a hidden marker, so re-running a pipeline updates it instead of
adding another.

### GitHub Actions

```yaml
on: pull_request
permissions:
  contents: read
  pull-requests: write
jobs:
  fwlens:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }
      - run: pip install fwlens
      - run: fwlens pr-comment --config config.yaml --base-ref origin/${{ github.base_ref }} --fail-on-new
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

Pull requests from forks get a read-only token. The post then fails with a warning, the
comment is written to the job summary instead, and the result is still shown.

### GitLab merge requests

```yaml
fwlens-mr:
  extends: .fwlens
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  variables:
    GIT_DEPTH: "0"
  script:
    - fwlens pr-comment --config $FWLENS_CONFIG --base-ref origin/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME --fail-on-new
```

Posting a note needs a token that can write notes: set a masked `GITLAB_TOKEN` variable
(a project access token with `api` scope). `CI_JOB_TOKEN` is used if it is the only token
available, but GitLab usually does not allow it to create notes.

Not included yet: restricting the report to files changed in the PR (issue #35), flash/RAM
growth gates and a `pr_check` section in `config.yaml`. Rule violations from the MISRA/CERT
work will use the same comparison.

---

## Two-hash comparison

`diff-breach` compares breaches between two `fwlens_results.json` exports -- typically one
captured at each of two git hashes -- without touching your working tree itself. You check
out and export each side; fwlens just diffs the two files:

```powershell
git checkout main
.\Run-FwLens.ps1 export --config config.yaml
Copy-Item output\exports\fwlens_results.json main.json

git checkout feature-branch
.\Run-FwLens.ps1 export --config config.yaml
.\Run-FwLens.ps1 diff-breach --from-json main.json --to-json output\exports\fwlens_results.json --fail-on-breach
```

Like `analyze`/`report`'s baseline check, only breaches that are new or worse in
`--to-json` relative to `--from-json` are reported; a breach present at the same severity
on both sides is silent. Thresholds come from `--config`'s `config.yaml`, not from whichever
config produced either JSON file, so both sides are judged against the same bar even if the
two commits' configs differed. This reports breach status only (crossed-threshold-or-not) --
it won't show a function that moved from CC 8 to CC 14 while staying under a CC 15
threshold; for that you'd need to diff the raw metric values in the two JSON files directly.

---

## Project-wide auto-stub

`debug-parse` auto-fixes missing-header, undeclared-function, and missing-arch-define
errors, but only for one file per run -- fine for diagnosing a single failure, tedious for
clearing every stub a whole project needs before its first clean `analyze`/`report`.
`--auto-stub` generalises the same mechanism project-wide:

```powershell
.\Run-FwLens.ps1 report --auto-stub
```

Before the real parse, it parses the whole in-scope file set, aggregates every
missing-header, undeclared-function, and missing-arch-define diagnostic across *all*
modules (not just one), fixes them, writes stubs to `iar_stubs\` (same directory
`debug-parse` uses, resolved next to `config.yaml`), and repeats -- up to 3 rounds -- until
a round finds nothing new to fix. Each round is printed to the console (what got created or
added, why the loop stopped), so nothing changes silently.

EWP mode only -- directory mode has no `$TOOLKIT_DIR$` headers to stub around, so
`--auto-stub` is a no-op there (with a console note) rather than an error.

Three diagnostic shapes are handled:

- **Missing header** (`'X.h' file not found`) -- stubbed. Most get an empty include-guard
  stub, enough when the only thing needed from that header is a function declaration
  (covered separately by the undeclared-function catch-all below). A small curated list of
  headers get real content instead, because code depends on a *macro or keyword* they
  define rather than just a function -- see the assert.h note below. Every generated stub,
  functional or empty, also `#include`s a shared catch-all header
  (`iar_stubs\_iar_builtins_stub.h`) so that whichever header a translation unit reaches
  first still pulls in every undeclared-function prototype discovered so far -- an earlier
  version tried wiring that catch-all in through a single forwarding header (mimicking
  IAR's own `intrinsics.h` -> `iccarm_builtin.h` chain), which only works if the *real*
  `intrinsics.h` exists to do the forwarding; once it's itself a stub, that chain goes
  nowhere and every intrinsic looks undeclared regardless of the catch-all having the
  right prototypes. The catch-all itself is created (empty, correctly guarded) before the
  first parse even runs, not on demand -- creating it lazily meant the very first round
  that referenced it from another stub hit its own "file not found", burning a whole
  extra round before real undeclared-function detection could start.
- **Undeclared function** (`call to undeclared function 'X'`) -- a prototype gets appended
  to the catch-all. A small curated list of well-known standard-library and CMSIS-intrinsic
  functions (`memcpy`, `strlen`, `__DSB`, `__CLZ`, ...) get their real signature; anything
  else gets an old-style, unprototyped declaration (`int fn();`) rather than a guessed
  fixed-arity one. A guessed prototype is worse than none: clang treats a *wrong*
  prototype as authoritative once it's visible, so a fixed 4-parameter guess made a real
  3-argument `memcpy(dest, src, n)` call site fail with "too few arguments, expected 4,
  have 3" the moment the catch-all actually got included anywhere (which it didn't,
  before the forwarding-chain fix above -- so this was invisible until that got fixed,
  then broke over a thousand call sites in one project). `int fn();` has no fixed
  parameter list at all, so clang accepts any call shape without complaint.
- **Missing arch define** (a codebase's own `#error "Please check that ... is defined!"`
  guard) -- the needed define is written to `iar_stubs\_auto_detected_defines.txt` and
  read back by `fwlens.config.load_config` on every subsequent load, in *any* process
  (never written to `config.yaml` itself), with a console tip to add it permanently so
  future runs don't repeat the same detection rounds. It has to go through a file rather
  than an in-memory config mutation: parsing runs in subprocess workers that only receive
  a config *path*, not the live Python object, and independently reload `config.yaml`
  fresh in each subprocess -- an in-memory-only mutation in the main process would be
  invisible to them (an earlier version of this feature had exactly that bug: the console
  correctly reported the define as "added", but the actual parse workers never saw it,
  since they'd already reloaded a config that never changed on disk).

  When the `#error` lists several candidate macros (e.g. `__ARM6M__, __ARM7M__,
  __ARM7EM__, __ARM8M_BASELINE__, __ARM8M_MAINLINE__ or __ARM8EM_MAINLINE__`), fwlens
  defines *every* candidate named, not just one guessed as most likely. These messages
  are almost always the fallback branch of an `#if defined(A) || defined(B) || ... /
  #error` chain, so defining several of them can't make that condition any less true --
  only a genuinely mutually-exclusive `#elif` chain would end up resolving to whichever
  candidate the header itself checks first, not whichever fwlens listed first. An
  earlier version picked a single "most likely" candidate (preferring `ARM7EM` over
  `ARM7M` for a Cortex-M4F target) and left the problem permanently unresolved whenever
  that guess was wrong, with no way to tell short of reading the header by hand.
  Candidates are comma-separated except the last, which is joined to the previous one
  with " or "/" and " (English list conventions) -- splitting on comma alone leaves that
  last pair stuck together as one malformed token, so that join is handled separately.

  If a persisting arch-define warning still appears after every named candidate has been
  defined, that's a strong signal the header's real condition isn't "is one of these
  defined" at all -- it likely checks a specific value, an entirely different macro, or
  the message text is generic boilerplate not tied to the actual `#if`. At that point
  `debug-parse --file <name>` on a specific affected file, then reading the header the
  `#error` actually comes from, is the only way forward -- guessing further from the
  message text alone won't resolve it.

**Every round prints its diagnostic counts** (total, plus how many distinct missing
headers / undeclared functions / arch-define messages), not just what changed -- this is
what makes it possible to tell "genuinely nothing left to fix" apart from "found the same
problem again but didn't recognise it as new." If a round finds an arch-define message
that already has a define on record from an earlier round, but the diagnostic is still
occurring, that's printed as an explicit warning rather than silently treated as
converged -- an earlier version of this loop only checked whether a round added something
*new*, so a persisting diagnostic whose fix had already been recorded (but wasn't actually
taking effect) caused the loop to declare "nothing new to fix" and stop, while the same
diagnostic kept showing up in the final report. If you see that warning, the define this
code guessed usually isn't the one the specific header actually checks -- `debug-parse
--file <one affected file>` on a representative file, then reading the header the `#error`
actually comes from, is the fastest way to find the real one.

**Stale stubs from a previous version of this feature are actively repaired, not just
left alone.** Every run rewrites the whole catchall header from a freshly parsed set of
existing declarations, replacing anything matching the specific broken pattern an earlier
version of this code used to write (a guessed fixed 4-parameter signature for every
unknown function, regardless of its real arity) with either the correct signature (for
the curated well-known functions) or a safe unprototyped one. Skipping repair for a name
that "already appears somewhere in the file" was itself a bug in an earlier version: it
meant a bug fix to the *generator* never reached stubs already sitting on disk from before
the fix existed, so `iar_stubs\` populated by an older fwlens kept regenerating the same
broken content on every subsequent run, no matter how many times the underlying code got
fixed. If you're upgrading from a version predating this, one run should self-heal
everything already in `iar_stubs\` -- deleting the directory first isn't required, but is
a reasonable "start clean" option if you want to confirm there's no other leftover cruft.

> **Important -- `assert.h`:** fwlens doesn't pass a `-std=` flag, so clang defaults to
> gnu17, where `_Static_assert` is a builtin keyword but lowercase `static_assert` only
> exists as a macro from `<assert.h>`. An empty stub clears the "file not found" fatal but
> leaves any `static_assert(...)` line unparseable, cascading into corrupted parsing of
> everything after it in that header -- so `assert.h`'s stub gets real content
> (`#define assert(x) ((void)0)` / `#define static_assert _Static_assert`) instead of an
> empty guard. That only helps translation units that actually `#include <assert.h>`
> themselves, though -- if a *header* uses `static_assert` without including `<assert.h>`
> itself (relying on the real IAR compiler treating it as an always-available keyword,
> which clang doesn't), no header stub fixes it for files that reach that header without
> `<assert.h>` anywhere in their own chain. That needs a global fix instead:
> `static_assert=_Static_assert` in `iar_compat_defines` (already in
> `config.example.yaml`'s default list, but has to be copied into your own `config.yaml`
> -- `--auto-stub` can't add this one for you automatically the way it does arch defines,
> since the failure is a raw parse error with no `#error` directive to detect) makes it
> available everywhere regardless of which translation unit includes what.

**`time.h`** gets the same treatment for the same reason: an empty stub clears "file not
found" but leaves `time_t` undefined for any code that uses it, so it gets a minimal
`typedef long time_t;` instead. Curated function signatures beyond the standard set noted
above also include `__LDREX`/`__STREX` (IAR's raw compiler intrinsics declare these with
`unsigned long *`, not `unsigned int *` -- a mismatch here doesn't fail loudly like a
missing prototype does, it just produces "incompatible pointer types" at every real call
site) and a handful of `<string.h>` functions clang has its own builtin awareness of
(`strtok`, `strnlen`, `strcasecmp`, `strncasecmp`) that need a real signature for the same
reason `memcpy` does -- an unprototyped fallback for a function clang already knows about
still triggers a warning, just a different one ("incompatible redeclaration" or "without
a prototype is deprecated") than a wrong-arity guess would.

**Every parse also runs with `-fno-builtin`**, not just the ones through `--auto-stub`.
Without it, clang treats well-known library function names as builtins with their own
hardcoded signature baked into the compiler, entirely independent of whatever prototype a
stub provides -- so even a textbook-correct curated signature can still be reported as an
"incompatible redeclaration" if it doesn't match clang's *internal* one exactly for this
specific target (down to the precise spelling of a size/type parameter). `-fno-builtin`
disables that recognition, making our own stub declarations authoritative regardless.
This eliminates the whole class of problem at the source rather than chasing individual
mismatched signatures one at a time.

**The console summary also runs two of these detectors on every `analyze`/`report`/
`export`, not only when `--auto-stub` is used.** A high volume of "type specifier
missing... implicit int" is called out by name as the `static_assert`-without-`assert.h`
signature (since that fix has to go in your own `config.yaml` and there's no diagnostic
shape for fwlens to detect and patch automatically), and a persisting "Please check that
... is defined!" volume gets the same explicit callout pointing at `--auto-stub` and, if
that's already been tried, `debug-parse`. Both print directly under the Parse Diagnostics
table rather than only in `--auto-stub`'s own round-by-round output, since a real cause
buried in prose across several tool responses is easy to miss -- the tool should say it
plainly in the one place everyone actually looks first.

**Already-existing stubs get checked against the curated lists on every run, not just new
ones.** A header or function stub written before a later addition to `_KNOWN_HEADER_STUBS`
or `_KNOWN_FUNCTION_SIGNATURES` (e.g. `time.h` before the `time_t` typedef was added, or
`__LDREX` before its parameter type was corrected) doesn't get silently left behind --
every curated header already on disk is checked at the start of each `--auto-stub` run,
and every function still showing up as undeclared gets checked against the current
signature regardless of whether it's a brand-new name. Upgrading fwlens and re-running
`--auto-stub` is enough to pick up improvements to these lists; deleting `iar_stubs\`
first is never required, only ever a "start clean" option.

If you hit the same empty-stub-then-new-error shape with a different header, it needs the
same treatment as `assert.h` -- add it to `_KNOWN_HEADER_STUBS` in `fwlens/autostub.py`.

Each round does a full parallel parse purely to re-read diagnostics, so this isn't free on
a large project -- that's why it's capped at 3 rounds and opt-in rather than automatic. A
project still finding new missing headers after 3 rounds likely has something an empty or
generic stub can't paper over (commonly: a header gated behind a `#define` not yet in
`iar_compat_defines`) -- `debug-parse --file <name>` on a specific remaining failure is the
better next step at that point.

---

## Diagnostic clusters

When many unrelated files hit the exact same parse diagnostic at the exact same line
number, that's not N independent problems -- it's one shared root cause (a missing
compiler-compat define, a broken header, an unresolved macro) whose parse-failure recovery
point happens to land at the same spot in every affected file. The diagnostic text itself
rarely names the real cause, only where the parser gave up and resynchronised -- "unknown
type name 'FI_NUM_FILES'" doesn't mention `static_assert` anywhere, even though that's
what's actually broken three lines earlier.

fwlens groups diagnostics by (message shape, **the file the diagnostic actually occurred
in**, line number) -- not just line number. libclang tracks the true physical location of
every diagnostic precisely, including inside an `#include`d header, and the file a
diagnostic is *reported against* (the `.c` translation unit fwlens was parsing) is very
often not the file it actually happened in at all. A shared header pulled in by dozens of
otherwise-unrelated `.c` files is exactly the shape a real cascading cause takes: same
message, same line, but only because every affected file reads the same header's same
broken line, not because of anything in the `.c` files' own content. Grouping by line
number alone risks two different failures: merging genuinely unrelated diagnostics whose
`.c` files coincidentally share a line number in their own code, and -- worse -- reading
and displaying the wrong source entirely, since a `.c` file's own line 158 has nothing to
do with a header's line 158. Quoted identifiers in the message are collapsed so "unknown
type name 'FOO'" and "unknown type name 'BAR'" still count as the same pattern, and any
pattern shared across 5+ distinct translation units gets pulled out as a cluster, sorted
by file count descending. For each cluster, fwlens reads the actual source around that
line from wherever it truly occurred and shows it directly -- turning "108 files hit this"
into "108 files hit this, and here's the header it's really in" without needing to export
a CSV, grep it, and paste a section back to figure out why.

Surfaced in the console summary (top 5 clusters, with `+/-3` lines of source context, and
an explicit `in header: ...` line whenever the real location differs from the `.c` file it
was reported against) and the `diagnostic_clusters` key in the JSON export (every cluster,
full context, `sample_tu` and `sample_file` both included so it's unambiguous which is
which). `parse_diagnostics.csv` carries the same distinction as two separate columns:
`file` (the translation unit) and `in_file` (where it actually happened, blank only in the
rare case libclang couldn't resolve a location at all) -- `line` is always relative to
`in_file`, not `file`, whenever the two differ. Two patterns get their own named detector
on top of this general mechanism, since they're common enough on IAR/embedded codebases to
call out explicitly rather than rely on the person reading a source snippet: `static_assert`
used without `<assert.h>` in scope (see the assert.h note under
[Project-wide auto-stub](#project-wide-auto-stub)), and a persisting arch-define `#error`
after `--auto-stub` has already tried every candidate macro the message names.

---

## Standalone plots

Add `plots` to `output.formats` in `config.yaml` and run `report` to write histogram,
sorted-value bar chart, and heatmap PNGs to `<reports_dir>/plots/`:

```yaml
output:
  formats: [html, csv, json, plots]
```

```powershell
.\Run-FwLens.ps1 report
```

Generated for each first-party function metric (cyclomatic complexity, Halstead volume,
Halstead effort, maintainability index, function length, fan-out, fan-in): a histogram, plus
a sorted-descending bar chart for all but function length. File length (SLOC, from
[file-level metrics](#file-level-metrics)) gets the same pair. Three heatmaps cover
effort-vs-complexity, length-vs-complexity, and volume-vs-maintainability.

---

## File-level metrics

Every module also gets whole-file line counts, independent of the function-level metrics
above: `file_total_lines`, `file_sloc`, `file_comment_lines`, `file_blank_lines`, and
`file_comment_ratio` (comment lines / (code + comment) lines). These are in the module CSV
export and the module section of the JSON export.

This is computed by fwlens itself -- no external tool (`scc`, `ccccc`, or otherwise) is
shelled out to. It's a line classifier, not a full C lexer: `/* */` and `//` comments are
tracked, but a comment-like sequence inside a string or character literal will be
misclassified as the start of a comment. Treat `file_sloc` as indicative rather than exact,
the same trade-off tools like `scc` make.

---

## Hotspot analysis

Ranks first-party functions by churn x structural debt: `hotspot_score` is the percentile
rank of the containing file's git commit count, multiplied by the percentile rank of the
function's structural debt index, both within the current first-party population. A function
in a file that changes often *and* is already structurally risky scores highest -- a better
prioritisation signal in practice than complexity alone, since it points at where defects
actually cluster rather than just where the code is hardest to read.

Runs automatically as part of `analyze`/`report`/`export` if the project root (`proj_dir` in
EWP mode, `source_dir` in directory mode) is inside a git repository and `git` is on PATH;
skipped with a console note otherwise. Optionally restrict the commit window:

```yaml
git:
  since: "180 days ago"   # default: full history
```

Surfaced in the console summary (top N by score), `hotspots.csv`, and the `hotspots` key in
the JSON export. With very few first-party files, scores can legitimately come out as 0 --
percentile rank against a population of one has nothing to rank against; this becomes
meaningful once the codebase has enough files for churn/debt to vary across them.

---

## Bug-fix-weighted hotspots

Same churn x structural-debt formula as [Hotspot analysis](#hotspot-analysis), but churn is
restricted to commits classified as a "fix" -- a commit-message keyword match, not a linked
issue tracker. A file rewritten often as new features land isn't necessarily the same file
that keeps needing bug fixes; the plain hotspot list answers "what changes a lot", this one
answers "what actually breaks a lot" (the same distinction Code Maat, Tornhill's companion
tool, makes). Reuses the exact same fix-commit classification as
[Reliability growth](#reliability-growth) and defect correlation -- all three draw
from one shared `fetch_fix_commits` pass so they can't disagree about which commits count.

Keywords are configurable (case-insensitive, matched via `git log --grep`):

```yaml
git:
  fix_keywords: [fix, bug, defect, issue, resolve, patch, hotfix]   # default
```

Override this if your commit conventions differ from the English default -- e.g. a
ticket-only convention (`JIRA-1234`), a non-English team, or a stricter Conventional Commits
`fix:` prefix (in which case you'd narrow the list to just `["fix"]` to avoid the generic
`bug` keyword matching a commit that merely *mentions* a bug in passing).

Surfaced in the console summary (top N by score), `bugfix_hotspots.csv`, and the
`bugfix_hotspots` key in the JSON export. Runs automatically as part of
`analyze`/`report`/`export`; skipped gracefully outside a git repo, same as the plain hotspot
list.

---

## Judge hotspots by name

A hotspot named `utils`, `misc`, or `handler` tells the reader nothing about what it's
responsible for, independent of whatever its complexity or churn numbers say -- Tornhill's
Chapter 5 argument is that a name that can't be judged is itself worth flagging, since it
usually means the file is a dumping ground rather than one coherent responsibility. Checks
both the function name and its containing file's stem (a well-named function inside a
vaguely-named file, e.g. `processData` in `Utils.c`, is still flagged) against a small,
generic vague-word list (`utils`, `handler`, `manager`, `misc`, `common`, `helper`, ...);
flagged only if *every* token in the name is on that list, so `parseATCommand` isn't flagged
just because `parse` alone might be considered generic.

This is a pure string heuristic, no config surface -- project-specific naming conventions
vary too much for a one-size default word list to be worth tuning via YAML.

Surfaced as a "Name" column on the hotspot table in the console summary and HTML report,
and as `vague_name_flag` in `functions.csv`/the JSON export (empty string if the name passed
judgement). Only computed for functions already in `model.hotspots`.

---

## Complexity trend over time

Two hotspot files can have identical *current* structural debt and mean very different
things: one spiked once (a feature landed) and has been flat since, the other has climbed on
every commit. Only the second is an active, worsening problem -- Tornhill's Chapter 6.
fwlens samples up to 12 evenly-spaced historical commits (bounding cost regardless of how
long-lived the file is) for the top 10 hotspot files, extracts each snapshot via
`git show <hash>:<path>`, and computes a lightweight complexity proxy: a regex count of
decision keywords (`if`/`else if`/`for`/`while`/`case`/`do`/`&&`/`||`/`?`) summed over the
whole file, the same "no external tool" text-based philosophy as
[Tech debt scanning](#tech-debt-scanning) -- not a re-parse with libclang, since re-parsing
every historical revision of every hotspot would be prohibitively expensive and older
revisions aren't always individually parseable in isolation anyway.

A linear fit over the sampled points classifies the trend as `worsening`, `improving`,
`stable` (slope below a small threshold), or `insufficient_data` (fewer than 4 usable
points). Needs at least 4 sampled commits to attempt a fit -- fewer than that and a trend
line is fitting noise.

> **Note:** this is a directional proxy, not the AST-derived `cyclomatic_complexity` used
> everywhere else in fwlens for the current snapshot. Treat the trend classification (is it
> getting better or worse) as the useful signal, not the absolute proxy values themselves.

Surfaced in the console summary and HTML report (skips files with `insufficient_data`),
`complexity_trends.csv` (one row per sampled point), the `complexity_trends` key in the JSON
export, and `plots/complexity_trend.png` when `plots` is in `output.formats`. Runs
automatically as part of `analyze`/`report`/`export` after hotspot analysis; skipped
gracefully outside a git repo.

---

## Hotspot visualisation

`plots/hotspot_map.png` (written when `plots` is in `output.formats`) is a file-level
scatter: x = commit count, y = structural debt summed per file, point size = file SLOC,
colour = the file's highest function hotspot score. This is the same idea as Tornhill's
Chapter 4 circle-packing hotspot visualisation (drawn here as a scatter rather than nested
circles) -- the point is to make the *distribution* visible at a glance, since real
codebases are typically skewed, with most of the risk concentrated in a handful of extreme
outliers rather than spread evenly. It also makes false positives easy to spot on sight: a
large-but-simple file sits low on the y-axis despite a big point size, and a genuinely
complex file that's barely ever touched sits far left despite a high y-value -- neither is a
true hotspot, which only shows up as a point far out on *both* axes. The top 10 (or
`output.top_n` if smaller) hotspots by score are labelled directly on the plot.

---

## ISR / main-loop shared-variable risk

Every global variable's readers and writers are already known from the AST walk
(`FunctionMetrics.global_reads`/`global_writes`, tracked through plain assignment, compound
assignment, and increment/decrement); this cross-references that against each variable's
declaration and each accessing function's `is_isr` flag to flag variables touched from *both*
an ISR and normal (main-loop) code without a `volatile` qualifier -- non-atomic shared-state
risk: the main loop can observe a torn read, or the compiler is free to reorder or cache an
access it would have to treat carefully if the variable were volatile-qualified.

Surfaced in the console summary (flagged variables only), `global_access.csv` (every global,
`volatile_risk` column lets you filter either way), and the `globals` key in the JSON export.

> **Note:** this flags variables that are structurally at risk (dual-context, non-volatile).
> It doesn't verify the access is actually unsafe for the specific hardware/compiler (e.g. a
> single-word read on some architectures is atomic regardless of the qualifier) -- treat it as
> a worklist for review, not a definitive defect list.

---

## Worst-case stack per entry point

`compute_stack_depth` already estimates worst-case stack usage for every function (frame size
estimate, from LOC, plus the deepest reachable callee chain); this collects that figure for
every entry point specifically -- both ISRs and the task/main entry points listed in
`entry_points` in config.yaml -- rather than leaving it buried in the full function list.
Sorted deepest-first; functions with recursion or unresolvable indirect calls in their
reachable call tree are marked non-estimable and sorted last.

Surfaced in the console summary, `entry_point_stack_risk.csv`, and the
`entry_point_stack_risks` key in the JSON export.

> **Note:** the frame-size estimate (LOC / 4) is a rough proxy, not linker-accurate. For a
> byte-accurate figure, correlate against the compiler's own stack usage reports (e.g. IAR's
> `--stack_usage` / `.su` files) if you need one for a certification or safety case.

---

## Tech debt scanning

Runs automatically as part of `analyze`/`report`/`export`, no config needed. All three are
text-based (regex over raw source), same "no external tool" philosophy as file-level metrics.

- **TODO/FIXME/HACK/XXX markers** -- every `//` or `/*` comment starting with one of those
  tags, collected with file/line/text. `todo_markers.csv`, `todo_markers` in JSON.
- **Commented-out code** -- runs of 3+ consecutive comment-only lines that are code-shaped
  (semicolons, braces, comparison/assignment operators) rather than prose. A `/* */` block
  and a run of `//` line comments are evaluated separately even when adjacent, so unrelated
  trailing comments don't dilute a genuine commented-out block below the flag threshold.
  `commented_code.csv`, `commented_code_blocks` in JSON.
- **Preprocessor complexity** -- max `#ifdef`/`#ifndef`/`#if` nesting depth, total conditional
  directive count, and count of distinct feature-flag macro names, per file. Surfaced as
  module fields (`max_ifdef_depth`, `ifdef_directive_count`, `distinct_feature_flags`) in the
  module CSV/JSON and a dedicated console table.

---

## Clone detection

Flags near-duplicate first-party functions (type-2 clones: same structure, renamed
identifiers/literals/comments) via normalised-token k-shingling and Jaccard similarity --
functions are tokenised, identifiers collapse to `ID` and literals to `LIT`, comments are
stripped, and 8-token shingles are compared. An inverted shingle index means only functions
that already share a shingle become candidate pairs, so this scales with actual duplication
rather than codebase size (no O(n^2) all-pairs comparison).

Functions under 30 normalised tokens are skipped as too small to be a meaningful signal;
pairs at or above 75% similarity are reported. Each pair also carries `is_dead_a`/`is_dead_b`
-- whether that side is separately flagged by dead-code detection (`fwlens.graph.engines`,
which runs before clone detection) -- and pairs with either flag set sort first, since
duplication that's also unreachable is a stronger, safer removal signal than either metric
alone: it can be deleted outright rather than merged with its live counterpart.

Surfaced in the console summary (dead-flagged pairs listed first with a `[dead]` marker),
`clones.csv`, and `clone_pairs` in the JSON export.

---

## Change coupling

Reuses the same git-log pass as [hotspot analysis](#hotspot-analysis) to find first-party
file pairs that repeatedly change together in the same commit -- logical coupling the static
call/include graph can miss entirely (e.g. two files that always change together probably
belong together, or are missing a shared abstraction). Commits touching more than 20
first-party files are excluded as noise (repo-wide reformats, branch merges); pairs need at
least 3 co-changes and a Jaccard coupling of at least 30% to be reported.

Surfaced in the console summary, `change_coupling.csv`, and `change_coupling` in the JSON
export. Skipped gracefully alongside hotspot analysis if the project isn't a git repo.

---

## Change coupling

Reuses the same git-log pass as [hotspot analysis](#hotspot-analysis) to find first-party
file pairs that repeatedly change together in the same commit -- logical coupling the static
call/include graph can miss entirely (e.g. two files that always change together probably
belong together, or are missing a shared abstraction). Commits touching more than 20
first-party files are excluded as noise (repo-wide reformats, branch merges); pairs need at
least 3 co-changes and a Jaccard coupling of at least 30% to be reported.

Surfaced in the console summary, `change_coupling.csv`, and `change_coupling` in the JSON
export. Skipped gracefully alongside hotspot analysis if the project isn't a git repo.

When `plots` is in `output.formats`, also rendered as `change_coupling_heatmap.png` -- a
file x file grid, colour = coupling strength, symmetric about the diagonal.

---

## Architecture-level change coupling

Rolls [change coupling](#change-coupling) up to the architecture-layer level (`layers` in
config.yaml) -- Tornhill's Chapter 8/10 "architectural decay" and "surprising change
patterns". A file-pair co-change that crosses layers is exactly the kind of coupling the
static layer-violation check ([Architecture Layer Violations](#architecture-layer-violations))
can't see, since that check only looks at the call graph, not git history: two files can
co-change constantly with no call or include relationship between them at all.

Each cross-layer `CouplingPair` gets `layer_a`/`layer_b`/`cross_layer` fields, plus a
`surprising` flag: `surprising` means neither file directly `#include`s the other. That's a
best-effort, direct-includes-only check (not transitive, not call-graph-aware), so treat
`surprising` as a worklist signal -- "worth a look" -- rather than a definitive verdict that
the coupling is unjustified; a real but indirect relationship (e.g. through a third file, or
a runtime message-passing contract with no compile-time trace at all) won't be caught.

Aggregated per layer pair into `LayerCouplingPair` (file pair count, total co-changes,
average coupling, count of surprising pairs), sorted by surprising-pair-count then average
coupling. Requires both files' `layer` to be assigned (not `Unknown`) and different from each
other; pairs within the same layer, or where either file's layer is unassigned, aren't
counted.

Surfaced in the console summary, `layer_coupling.csv` (aggregated) and the `cross_layer`/
`surprising` columns added to `change_coupling.csv` (file-pair detail), and the
`layer_coupling` key in the JSON export. Runs automatically as part of
`analyze`/`report`/`export` after change coupling and layer assignment; empty (not run) if
either produced nothing.

---

## Commit heatmaps

Two matplotlib heatmaps, written to `<reports_dir>/plots/` when `plots` is in
`output.formats`:

- **`churn_heatmap.png`** -- file x time-bin commit counts for the top `output.top_n` files
  by total commits. Shows *when* a file was hot, not just that its aggregate commit count is
  high -- a file with heavy churn two years ago and nothing since reads very differently from
  one under active rework right now, but both look identical in a single aggregate number.
  Bin size is `month` by default; set `git.heatmap_bin: week` for finer granularity on a
  shorter history.
- **`change_coupling_heatmap.png`** -- the [change coupling](#change-coupling) data as a
  file x file grid instead of a table, making coupling clusters easier to spot at a glance.

Raw churn-heatmap data (every file/bin/count triple, not just the top N shown in the PNG) is
in `churn_heatmap.csv` regardless of whether `plots` is enabled.

---

## Commit date (activity) heatmap

The commit heatmaps above are all *per file*; this one is a single GitHub-style calendar
heatmap of total commit activity per calendar day across the whole first-party codebase --
a commit touching several files counts once here, not once per file, so it answers "when did
work happen" rather than "which files were busy". Reuses the same `_commits_with_dates`
git-log pass as [Commit heatmaps](#commit-heatmaps) above; a commit counts if it touches at
least one first-party file, matching that function's filtering.

Rendered two ways:

- **In the HTML report**, as an HTML/CSS grid on the Change History tab (like
  `churn_heatmap_grid`) -- no PNG dependency, capped to the most recent 52 weeks for a
  readable width.
- **As `plots/commit_activity_calendar.png`** when `plots` is in `output.formats` -- the same
  data, same 52-week cap, as a standalone matplotlib figure.

The console summary prints a one-line total (commit count, active-day count, date range,
busiest day) rather than the full grid. The full, uncapped daily series -- every day with at
least one commit, regardless of how far back -- is in `commit_activity.csv` and the
`commit_activity` key in the JSON export either way.

> **Note:** the 52-week cap is a display convention (matching GitHub's own contribution
> graph), not a data limitation -- a project with several years of history will still have
> its full daily series in the CSV/JSON export; only the rendered grid is windowed.

Runs automatically as part of `analyze`/`report`/`export` alongside the other git-history
analyses; skipped gracefully outside a git repo.

---

## Code ownership / knowledge maps

Tornhill's Chapters 11-13: diffuse ownership -- many contributors, no clear main author --
correlates with defects independently of complexity, since nobody holds the full context
needed to change the file safely, and coordination overhead between authors introduces its
own errors. Reuses a `git log --name-only` pass (parallel to the one behind
[hotspot analysis](#hotspot-analysis), but tracking author identity per commit instead of
just counting commits) to compute, per first-party file:

- `main_author` / `main_author_share` -- the largest single contributor and their fraction
  of commits touching the file
- `distinct_author_count` -- total distinct authors
- `ownership_fragmentation` -- `1 - main_author_share`: 0 means one person wrote every commit
  touching the file, ->1 means authorship is split roughly evenly across many people
- `ownership_risk_score` -- percentile-rank(commit count) x ownership_fragmentation, the same
  "churn x signal" shape as `hotspot_score`; a file that's both frequently changed and
  diffusely owned is the bystander-effect risk case, and doesn't necessarily overlap with the
  structural-debt-driven hotspot list at all

> **Note:** a high fragmentation score is a coordination/context signal about the *file*, not
> a judgement of the people who worked on it -- see [Metrics Etiquette](#metrics-etiquette).
> Don't use this list to evaluate individual contributors.

Surfaced in the console summary (top N by `ownership_risk_score`), `ownership.csv`, and the
`ownership_risks` key in the JSON export. Runs automatically as part of
`analyze`/`report`/`export` after hotspot analysis (reuses `commit_count` for the churn side
of the risk score); skipped gracefully outside a git repo, same as hotspot analysis.

---

## Information flow complexity

Henry & Kafura's IF4 metric: `length x (fan_in x fan_out)^2`, using LOC as the length
proxy. Computed for every function automatically, no config needed. Penalises functions
that are both internally long *and* heavily coupled through the call graph -- a different
signal from cyclomatic complexity, which only measures internal branching and says nothing
about how coupled a function is to the rest of the codebase. A function needs nonzero
fan-in *and* nonzero fan-out to score above zero -- pure leaf functions and pure entry
points always score 0 regardless of how complex they are internally, by construction of
the metric.

Surfaced in the console summary (top N) and as `information_flow_complexity` in the
function CSV/JSON export.

---

## COCOMO effort estimate

A Basic COCOMO 81 effort/schedule estimate derived from total first-party SLOC
(`fwlens.metrics.file_metrics`). Runs automatically as part of `analyze`/`report`/`export`.

```yaml
estimation:
  cocomo_mode: embedded   # organic | semidetached | embedded (default)
```

`embedded` mode (tight hardware/timing/interface constraints) is COCOMO's closest built-in
category to firmware -- a reasonable qualitative fit -- but the underlying a/b/c/d constants
were empirically fitted to a dataset of ~60 1970s-80s business and systems-software
projects. They are **not** calibrated to this codebase, this team, or embedded firmware
specifically. Treat the output as a rough historical-baseline estimate, not a committed
schedule. If you have your own historical effort data for comparable projects, calibrating
your own constants against it (linear regression of `ln(effort)` vs `ln(KLOC)`) will be far
more meaningful than the textbook defaults.

Surfaced in the console summary, `estimation_summary.csv`, and `effort_estimate` in the
JSON export.

---

## Reliability growth

Fits the Goel-Okumoto NHPP (non-homogeneous Poisson process) model,
`mu(t) = a * (1 - exp(-b*t))`, to the cumulative count of "fix"-flavoured commits over
time -- `a` is the asymptotic expected total defects, `b` is the discovery rate. Commits
are classified as fix-flavoured by a case-insensitive commit-message keyword match (`fix`,
`bug`, `defect`, `issue`, `resolve`, `patch`, `hotfix`) -- a coarse heuristic, not a linked
issue tracker. Needs at least 8 matching commits to attempt a fit; below that, reports
`insufficient_data` rather than fitting noise.

Trend is classified from how far the current cumulative count is toward the fitted
asymptote: below 70% is `climbing`, 70-90% is `flattening`, above 90% is `plateaued`.

> **Note:** this is a defect-*discovery* curve, not a defect count. Fewer fix commits than
> actual bugs (some bugs never get a dedicated fix commit; some fix commits address more
> than one bug) and fewer fix commits than total commits (most commits aren't bug fixes)
> both apply -- treat `a` and `estimated_remaining` as order-of-magnitude discovery-trend
> indicators, not precise defect counts.

Surfaced in the console summary, `estimation_summary.csv`, and `reliability_growth` in the
JSON export. Skipped gracefully if the project isn't a git repo, same as the other
git-based features.

---

## Composite risk ranking

Fuses structural debt index, hotspot score, containing module's pain score, ISR latency risk,
and entry-point stack depth into a single ranked "riskiest functions" list, so you don't have
to mentally combine four separate tables. Every component is a percentile rank within the
first-party population before weighting (same self-calibrating approach the zone-of-pain
score uses), weighted 35% SDI / 25% hotspot / 20% module pain / 10% ISR / 10% stack -- SDI and
hotspot dominate since they apply to every function, while ISR/stack risk only apply to entry
points and act as additive bonuses rather than being weighted as heavily.

Surfaced in the console summary, `composite_risk.csv`, and `composite_risk` in the JSON export.

---

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

---

## Configuration reference

All settings live in `config.yaml` next to `Run-FwLens.ps1`.

### `tool`

```yaml
tool:
  libclang_path: C:\Program Files\LLVM\bin\libclang.dll
```

Path to `libclang.dll`. Install LLVM from the official releases and point here.

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
only way to see it; see [RTOS task/synchronisation analysis](#rtos-tasksynchronisation-analysis)).
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
```

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
