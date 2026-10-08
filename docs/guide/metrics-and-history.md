# Metrics, hotspots and git history

[Back to the guide contents](../../FWLENS_GUIDE.md)

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

## Git history warnings

History-based metrics (hotspots, churn and change coupling, ownership, bug-fix hotspots, trends)
read the repository once with `git log -z` and share that result. If git times out, fails, or the
clone is shallow, FWLens prints a warning, lists it in a banner on the HTML overview and in
`meta.history_warnings` of the JSON export, and the affected metrics may be empty or partial.
CI jobs should fetch full history (for example `actions/checkout` with `fetch-depth: 0`). Hotspot
churn counts every commit; change coupling leaves out commits touching more than 20 first-party
files, and counts solo commits in each file's change total so the ratio is a true Jaccard value.

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

When `plots` is in `output.formats`, also rendered as `change_coupling_heatmap.png` -- a
file x file grid, colour = coupling strength, symmetric about the diagonal.

---

## Architecture-level change coupling

Rolls [change coupling](#change-coupling) up to the architecture-layer level (`layers` in
config.yaml) -- Tornhill's Chapter 8/10 "architectural decay" and "surprising change
patterns". A file-pair co-change that crosses layers is exactly the kind of coupling the
static layer-violation check ([Architecture Layer Violations](reference.md#architecture-layer-violations))
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
> a judgement of the people who worked on it -- see [Metrics Etiquette](reference.md#metrics-etiquette).
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

