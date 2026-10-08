# Coding standards

[Back to the guide contents](../../FWLENS_GUIDE.md)

## Coding standards (MISRA C, CERT C, BARR-C, Power of 10)

Optional and **off by default**: nothing changes unless `standards.enabled` is set. FWLens
reports what it checked or imported. It never states that a project is compliant: a MISRA
Compliance claim also needs a guideline enforcement plan, any recategorization and deviation
records, which are process documents outside this tool.

```yaml
standards:
  enabled:
    - standard: misra-c-2012
      include_categories: [mandatory, required]   # optional filters
      exclude_rules: ["D4.1"]
    - standard: cert-c
      include_ids: [ENV33-C, MSC30-C]
    - standard: power-of-10                       # NASA/JPL, ids P10-1 to P10-10
    - standard: misra-c-2023                      # or misra-c-2012
    - standard: barr-c-2018                       # Barr Group Embedded C, ids such as 6.1.e
    - standard: autosar-cpp14                     # AUTOSAR C++14 guidelines that apply to C
    - standard: iso-ts-17961                      # ISO/IEC TS 17961 C secure coding, ids such as ptrcomp
    - standard: fwlens                            # secrets, dead code, interrupt safety
  extra_rule_dirs: [./standards]                  # your own *.yaml rule files
  deviations_file: ./standards/deviations.yaml
  imports:                                        # results from other analysers
    - { tool: cppcheck,   path: build/cppcheck.xml }
    - { tool: clang-tidy, path: build/tidy.txt }
    - { tool: clang-tidy-yaml, path: build/tidy-fixes.yaml }   # clang-tidy --export-fixes
    - { tool: clang-analyzer,  path: build/report.plist }      # scan-build -plist
    - { tool: sarif,      path: build/gcc.sarif }              # gcc -fanalyzer -fdiagnostics-format=sarif
```

Findings join the normal breach list, so baseline gating (`--baseline`, `--fail-on-breach`),
the PR/MR comment, SARIF and the GitLab Code Quality report all include them. SARIF uses the
standard's own id (`misra-c-2012:15.1`) with levels from the category (mandatory is an error,
required a warning, advisory a note). GitLab severities follow the same categories.

### Rules are YAML, not Python

Each standard is one file in `fwlens/standards/builtin/` or in your `extra_rule_dirs`. A rule has
metadata (id, kind, category, decidable, scope, CWE) and a `check` block:

| `check.type` | Meaning |
|---|---|
| `native` | FWLens checks it itself with an engine named in `check.engine` |
| `import` | covered by results imported from another tool |
| `manual` | needs human review, listed in the matrix as such |

`check` may also be a list, for a guideline that needs more than one kind of check. A rule can
add `coverage: partial` to say its native checks find some violations but not all. The matrix
then shows `native (partial)` and "no findings" for it is not evidence of compliance.

```yaml
- id: "21.3"
  kind: rule
  title: Do not use the stdlib dynamic memory functions
  category: required
  decidable: true
  scope: single-tu
  check:
    type: native
    engine: ast
    match: { cursor: CALL_EXPR, callee_in: [malloc, calloc, realloc, free] }
```

Engines:

| Engine | What it does | `match` |
|---|---|---|
| `ast` | a libclang cursor kind, optionally restricted to named callees | `cursor`, `callee_in`, `callee_prefix` |
| `compound_body` | selection and iteration statements without a compound body | none |
| `callgraph` | call cycles, for recursion | `cycle: true` |
| `detector` | a named check over the syntax tree and types (essential type model, expressions, declarations, control flow, library use) | `name`, plus the detector's own parameters, for example `limit` |
| `source` | a named check, or a regular expression, over the source text and preprocessor directives | `name` or `pattern` (and `target`) |
| `diagnostic` | warnings libclang reports while parsing | `option` (the `-W` name, or a list) and/or `pattern`, with `flags` to switch warnings on |
| `system` | whole-project checks over every first-party translation unit (identifier uniqueness, linkage, unused declarations) | `name` |

Adding a rule that fits an engine is a YAML edit only. Files are
validated on load with errors that name the file, rule and field, and
`fwlens standards validate [FILES...]` checks rule and deviation files. `fwlens standards list`
shows every rule, how it is checked and which are enabled; `--rule-dir DIR` adds a rule directory
for that call.

A rule may carry a `help` line (how to fix it). It is shown as the rule's help in SARIF
(`help.text`) and in the report's SARIF tab. The FWLens rules have one, and you can add one to
your own rules.

A `tool_map` section maps another tool's check ids onto rule ids. Common cppcheck MISRA and
CERT ids and clang-tidy `cert-*` ids are recognised without it.

### Deviations

`deviations_file` is a separate YAML file so deviations are reviewed and expire on their own:

```yaml
deviations:
  - id: DEV-001
    standard: misra-c-2012
    rule: "21.3"
    type: specific              # project | specific
    justification: Single start-up allocation, reviewed by the architecture board
    approved_by: architecture-board
    scope: { paths: ["src/platform/*.c"], functions: [alloc_init] }
    expires: 2027-03-31
```

A deviation can also be applied where it is needed, with a comment on the line of the finding or
the line above it:

```c
/* fwlens-deviation: Rule 11.4 DEV-007 */
ptr = (uint32_t *)0x40021000u;
```

The register entry still holds the justification, approval and expiry. Give it
`scope: { inline: true }` to make it apply only through such comments. A comment that names an
unknown entry or a different rule covers nothing, so the finding stays visible.

A covered finding is moved out of the gate and shown as deviated in the matrix. A deviation
against a mandatory guideline, or one past its `expires` date, does not apply and becomes a
finding of its own, so it fails the gate.

### Compliance matrix

```bash
fwlens standards report --config config.yaml --output matrix.md      # or --format json
fwlens standards report --config config.yaml --fail-on-violation      # exit 1 on any active finding or deviation problem
```

One row per selected guideline: category, decidability and scope, status (violated, deviated,
no findings, manual review, not assessed), how it is checked and its deviations. Guidelines no
configured source covers say `not assessed`.

The same table is written to `standards.csv` by `export` and `report`, and appears as a
**Standards** tab in the HTML report. Both exist only when `standards.enabled` is set, and both
carry the same note: the table reports what FWLens checked, not compliance.

### What is bundled

The built-in files carry guideline **ids**, the published category, decidability and scope, and
short FWLens-written descriptions of what each check detects. They contain no MISRA or CERT
guideline text. Point your own tooling at your licensed copy for the official wording.

| Standard | Guidelines | Native | Of which partial | Import only | Manual |
|---|---|---|---|---|---|
| MISRA C:2012 (`misra-c-2012`) | 219 | 160 | 61 | 4 | 55 |
| MISRA C:2023 (`misra-c-2023`) | 222 | 161 | 62 | 4 | 57 |
| BARR-C:2018 (`barr-c-2018`) | 155 | 89 | 38 | 0 | 66 |
| SEI CERT C (`cert-c`) | 276 | 96 | 67 | 8 | 172 |
| NASA/JPL Power of 10 (`power-of-10`) | 10 | 9 | 6 | 0 | 1 |
| AUTOSAR C++14, C subset (`autosar-cpp14`) | 81 | 79 | 26 | 1 | 1 |
| ISO/IEC TS 17961 (`iso-ts-17961`) | 43 | 24 | 21 | 6 | 13 |
| FWLens checks (`fwlens`) | 24 | 21 | 13 | 3 | 0 |

`misra-c-2012` already includes Amendments 1 to 4. `misra-c-2023` is the same set plus the
concurrency directives 5.1 to 5.3, with the same checks behind the shared guidelines, so choose
the one your project claims. BARR-C ids follow the standard's own numbering (`6.1.e`, `7.1.j`);
layout rules (white space, indentation, brace placement) read the text of the file and are
approximate, so they are partial. Barr's categories ("shall" and "should") are read from the
wording, so check them against your copy. Every MISRA C:2012 directive and rule is listed, as is every CERT C rule and a selection of the
recommendations. A guideline is `native` when FWLens checks it, `import` when it relies on results
from another analyser, and `manual` when only review can settle it. **Partial** means the native
check finds a clear subset of the violations (an essential type model that stays silent when it is
unsure, direct calls only, first-party code only). Such a guideline never reads as compliant:
"no findings" for it means nothing was found, not that the code complies. Use `fwlens standards
list` to see how each guideline is checked.

**AUTOSAR.** The AUTOSAR guidelines are written for C++14. `autosar-cpp14` holds only those that
mean something in C (loops, `switch`, `goto`, the preprocessor, pointers, unused code, the
library functions C has). Each reuses the check of the MISRA C or CERT C rule it matches. Rule
A2-11-1 (no `volatile`) is real but embedded code cannot follow it: use `exclude_rules`.

**TS 17961.** `iso-ts-17961` uses the specification's mnemonics as ids (`ptrcomp`, `accfree`,
`liberr`). Each rule uses the check of the CERT C rule it corresponds to. The two taint rules need
whole-program taint analysis, so they are manual: import an analyser that does it.

**FWLens checks.** The `fwlens` standard holds checks that are not in a published standard:

- `SEC-1` to `SEC-6`: hard-coded passwords and keys, private key blocks, known token formats
  (AWS, GitHub, Slack, Google, JWT), credentials in URLs, MD5, SHA-1, DES and RC4 calls, and
  hard-coded IPv4 addresses. Pattern based: it finds common shapes, not every secret, and does
  not replace a scanner over the repository history.
- `DEAD-1` to `DEAD-10`: unreachable code, unused static functions, parameters, locals, objects,
  macros, types and labels, locals that are assigned and never read, commented-out code.
- `ISR-1` to `ISR-5`: interrupt handlers are found by name (`SysTick_Handler`,
  `TIM2_IRQHandler`, `ISR_uart`) or by an attribute on the declaration (`__interrupt`, `__irq`,
  `__attribute__((interrupt))`). The checks report a shared variable written in a handler without
  `volatile`, a blocking call, an RTOS call that is not the `FromISR` variant, dynamic memory or
  stdio, and a handler over 40 lines. Only the handler's own body is read, so a hazard reached
  through another function is not seen. The call lists are defaults: copy the rule into your own
  rule file to change them.
- `IMP-1` to `IMP-3`: where imported clang-tidy, clang static analyser, cppcheck and SARIF findings
  land when no enabled standard maps them to a rule. A standard's own `tool_map` entry wins, and
  `tool_map` keys may end in `*` (`"clang-analyzer-*": IMP-1`).

**CWE.** Rules carry CWE ids (`cwe-map.yaml` for MISRA, CERT, Barr, Power of 10 and AUTOSAR, the
rule files themselves for TS 17961 and FWLens). SARIF writes them as rule tags
(`external/cwe/cwe-476`), a `CWE` taxonomy, and a summary in `run.properties.fwlens.cwe` that says
which of the CWE Top 25 (2024) have a rule that checks for them, which have findings, and the
findings per CWE. The HTML SARIF tab shows the same. A guideline can relate to several CWEs: use
them to group findings, not as a statement that a finding is that weakness.

Limits to know about:

- Native checks match call names, so a project function that shares a name with a library
  function is a false positive.
- Statements written by a macro, such as the `if (e) ; else` inside glibc's `assert`, are not
  reported.
- Code in headers is analysed through the translation units that include it. The `system` checks
  only see first-party translation units, so something used only from SDK or third-party code
  looks unused. Those rules are marked partial.
- Recursion follows direct calls only.
- The `format` and `format-security` checks (CERT FIO30-C and FIO47-C) switch on libclang's
  built-in knowledge of `printf`, which FWLens normally turns off.

Findings can also be written as a GitLab SAST report, see [GitLab SAST report](gating-and-ci.md#gitlab-sast-report).
Message triage and recategorisation records are tracked in #88.

### Licensing of the rule data

This is a record of the position, not legal advice, and the question is **not settled**.

- **Bundled:** guideline ids, the published category, decidability and scope, CWE mappings
  (`misra-c-2012.yaml`), and short descriptions written for FWLens. No MISRA or CERT guideline
  text is included, and `guideline_text` is marked user-supplied.
- **User-supplied:** the official guideline wording and any tables from the standards. Point your
  own tooling at your licensed copy.
- **Open:** whether MISRA (HORIBA MIRA) permits bundling the ids, categories and decidability
  attributes, and what the CERT and CWE terms allow, has not been confirmed with the owners.
  Until it is, treat the bundled MISRA data (C:2012 and C:2023, which carry only ids, categories,
  decidability and paraphrased titles) as unconfirmed. BARR-C is published by Barr Group, who
  release the standard for free download. Because rules are plain YAML, a project can move them into its own
  `standards.extra_rule_dirs` and drop the built-in file if that is the safer course.

