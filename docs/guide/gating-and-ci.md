# Gating, history and CI integration

[Back to the guide contents](../../FWLENS_GUIDE.md)

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

### Judging only the code a pull request touches

`--changed-since REF` on `analyze` and `report` restricts findings (console gate, `--fail-on-breach`,
annotations, SARIF, GitLab Code Quality, findings JSON) to files changed since the merge base with
`REF`. `--changed-scope function` narrows that to functions that overlap a changed hunk (a function's
extent is its start line plus its line count). The whole project is still parsed, so totals and
cross-file metrics are unchanged. With no option, the base comes from `CI_MERGE_REQUEST_DIFF_BASE_SHA`
(GitLab) or `GITHUB_BASE_REF` (GitHub, as `origin/<branch>`). If the base cannot be found, typically
in a shallow clone, FWLens says so and reports everything. `--update-baseline` is refused in diff
mode because the baseline would lose findings outside the diff. `pr-comment` is not affected.

### Moved and renamed code

Each function-level breach also stores a content fingerprint in the baseline. A breach is
matched to its baseline entry in tiers: same id, then same code (the function moved to
another file or was renamed), then same code with identifiers renamed, then similar or
partly overlapping code. Matches in the last group are listed as "matched loosely" and only
gate when the value got worse. A split function is reported as a change, not as a new breach.
Matching is heuristic: a function that is largely rewritten is reported as one resolved and
one new breach.

Module-level breaches follow their file. A rename is taken from the functions: when a file's
matched functions turn up in another file, that file is its successor. `pr-comment` and
`compare` with `--base-ref` (or `pr_check.base_ref`) also read `git diff -M` between the
merge-base and HEAD, which covers files with no matched functions. Without git, only the
function evidence is used, so a renamed file whose functions all changed is reported as new.
`diff-breach` works from exports, and an export without fingerprints can only be matched by key.

```yaml
match:
  similarity: 0.85        # body similarity needed for a loose match, above 0 and at most 1
  report_uncertain: true  # false: no loose matching; edited code is one resolved plus one new
```

Lower `similarity` to follow more heavily edited code at the cost of more wrong matches. Loose
matches only fail the check when the value got worse, unless `uncertain_gates` is set.

Baselines written by earlier versions (ids with a line number) are migrated when read. They
have no fingerprints until you re-run with `--update-baseline`.

Function-level breaches are checked against: `cyclomatic_complexity`, `cognitive_complexity`,
`block_depth`, `function_loc`, `parameter_count`, `return_path_count`, `magic_number_density`,
`fan_out`. Module-level breaches are checked against `main_sequence_distance`. These are the
same threshold keys from the [`thresholds`](reference.md#thresholds) config section.

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

## Run history, trends and the ratchet

`analyze` and `report` can keep a history of runs in a SQLite file, `output.db_path`
(default `output/fwlens.db`).

```powershell
fwlens analyze --record-run --run-label v1.4     # store this run
fwlens analyze --ratchet                         # fail if it is worse than the last accepted run
fwlens analyze --record-run --ratchet            # both: the usual CI step
```

Each stored run holds the totals (findings, average cyclomatic complexity, layer violations,
functions, modules, and flash/RAM when `project.map_file` is set), the commit, the label, and
every finding with its stable id and fingerprint, the same identity that baselines and
`compare` use.

- **Ratchet.** The run fails (exit 1) when total findings or layer violations are higher than in
  the previous *accepted* run. Fewer is fine. With `--record-run` a failing run is stored as not
  accepted, so the bar stays where it was. With no earlier run there is nothing to compare, and
  the run passes. Diff mode is not applied to the totals; they cover the whole project.
- **Trend.** When the history has runs, the HTML report's Overview shows a Trend table: the last
  nine stored runs plus the current one, each compared with the one before.
- **CI.** The file is a single SQLite database with no extra files, so keep it as a cache or
  artefact: restore it before the run and save it after. A file written by a newer FWLens is
  refused with a message rather than overwritten.

---

## JUnit and Markdown summaries

`analyze` and `report` can also write results for CI views that do not need a pull request:

- `--junit PATH` writes JUnit XML. Each file is a test suite and each finding a failed test case
  (class name = file, name = function and metric). A run with no findings holds one passing
  case. The output is checked against the Jenkins `junit-10.xsd` schema in the tests.
- `--markdown-summary PATH` writes a short summary: counts per metric and the largest findings.
  When PATH is `$GITHUB_STEP_SUMMARY` the text is appended, so earlier steps are kept.

```yaml
# GitHub Actions
- run: fwlens analyze --junit fwlens-junit.xml --markdown-summary "$GITHUB_STEP_SUMMARY"
```

```yaml
# GitLab CI
fwlens:
  script: fwlens analyze --junit fwlens-junit.xml
  artifacts:
    when: always
    reports:
      junit: fwlens-junit.xml
```

These reports list every finding, not only new ones. For a comparison with the target branch
use `pr-comment` or `compare`.

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
| `--base-label TEXT` | how the reference is named in the comment (default "the target branch") |
| `--max-flash-growth BYTES`, `--max-ram-growth BYTES` | fail when the footprint grows by more than this; need `project.map_file` |

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

### The composite action

The repository ships a composite action that installs FWLens from the action's own checkout
(so `uses: markbac/code-quality@<tag or sha>` pins the version you run), then runs
`fwlens analyze` with inline annotations:

```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }
- uses: markbac/code-quality@v0.29.0
  with:
    config: config.yaml          # relative to working-directory
    working-directory: firmware  # default "."
    baseline: baseline.json      # breaches are only gated when a baseline is given
    fail-on-breach: "true"
    python-version: "3.12"
    extra-args: "--jobs 2"       # split on spaces, never passed through a shell
    upload-report: "true"        # also builds the HTML report and uploads it as an artifact
```

Set `upload-sarif: "true"` (with `permissions: security-events: write`) to send the findings to
GitHub code scanning. Outside the action, `fwlens analyze --sarif out.sarif` (also on `report` and
`export`, or `sarif` in `output.formats`) writes SARIF 2.1.0 for `github/codeql-action/upload-sarif`.

The SARIF file also carries the key metrics, so a SARIF viewer shows them without the HTML report:

- `runs[0].properties.fwlens.summary`: files, functions, LOC, average and maximum cyclomatic
  complexity, maximum cognitive complexity and nesting depth, average maintainability index.
- `runs[0].properties.fwlens.functions`: the most complex functions first (up to 500), each with
  file, line, LOC, cyclomatic and cognitive complexity, nesting depth, parameters, return paths,
  fan-in, fan-out and maintainability index. `functionsTotal` says how many exist.
- `runs[0].artifacts`: one entry per first-party file with its length and properties for LOC,
  function count, average and maximum cyclomatic complexity, maintainability, fan-in, fan-out
  and instability.
- Metric-breach results carry `properties` with `metric`, `value`, `threshold` and `function`.

Inputs reach the shell as environment variables, not as pasted text. `pip install fwlens` in
your own workflow works equally well; the pre-commit hook analyses the whole project on each
commit.

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

### Defaults in config.yaml

The `pr_check` section holds the defaults for `compare` and `pr-comment`; any option on the
command line overrides it.

```yaml
pr_check:
  base: output/main-findings.json   # --base
  base_ref: origin/main             # --base-ref (slower: analyses the merge-base in a worktree)
  fail_on_new: true                 # exit 1 on new/worse findings or a footprint limit
  uncertain_gates: false
  base_label: the target branch     # --base-label
  report_url: https://ci.example.com/job/1/artifacts/report.html   # --report-url
  max_items: 20
  max_flash_growth_bytes: 2048      # needs project.map_file
  max_ram_growth_bytes: 256
  status: true                      # also set a commit status named "fwlens"
```

### Flash and RAM footprint

Set `project.map_file` to the linker map and FWLens reads object-level `.text`/`.rodata`
(flash) and `.data`/`.bss` (RAM) sizes, attaches them to the module whose file stem matches the
object (`main.o` or `main.c.obj` to `main.c`), and adds `flash_bytes` and `ram_bytes` to
`modules.csv` and the HTML overview. Only GCC-style map lines are verified; IAR maps are
untested. The figures are per file, not per function.

`--findings-json` records the totals, so a reference file written on the target branch lets
`compare` and `pr-comment` show Flash and RAM deltas and fail on `max_flash_growth_bytes` /
`max_ram_growth_bytes`. A reference made with `--base-ref` has no footprint unless the map
file is committed, so the limits are then reported as not checked.

`--status` (or `pr_check.status`) also sets a `fwlens` commit status. On GitHub the token needs
`statuses: write`; on GitLab it needs `GITLAB_TOKEN`. A failure to set it is a warning only.

Not included yet: restricting the report to files changed in the PR (issue #35). Rule
violations from the MISRA/CERT work will use the same comparison.

