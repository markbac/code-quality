# Getting started

[Back to the guide contents](../../FWLENS_GUIDE.md)

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

# Software and cryptography bills of materials (CycloneDX 1.6 JSON)
.\Run-FwLens.ps1 sbom
.\Run-FwLens.ps1 cbom
```

> **Note:** `Run-FwLens.ps1` looks for `fwlens_config.yaml` by default, in the working directory and
> then next to the script. The `fwlens` command defaults to `config.yaml`. If your file is named
> `config.yaml`, pass `-Config config.yaml` to the script.

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
| `init` | Write a starter `config.yaml`; `--type cmake\|make\|ewp\|directory\|auto` picks the template |
| `doctor` | Check libclang, the compiler, git and print every resolved path |
| `config-schema` | Print the JSON Schema for `config.yaml` (`-o FILE` writes it) |
| `sbom` | Write a CycloneDX 1.6 software bill of materials -- see [SBOM](bills-of-materials.md#software-bill-of-materials-sbom) |
| `cbom` | Write a CycloneDX 1.6 cryptography bill of materials -- see [CBOM](bills-of-materials.md#cryptography-bill-of-materials-cbom) |
| `architecture variants` | Compare the architecture of two build configurations or projects -- see [Architecture recovery](architecture-recovery.md#architecture-recovery) |
| `architecture save`, `architecture diff` | Save the recovered architecture, and compare a run with a snapshot or a git revision -- see [Architecture recovery](architecture-recovery.md#architecture-recovery) |
| `architecture adopt` | Write the recovered components, domains and layers as a starting point for the intended architecture -- see [Architecture recovery](architecture-recovery.md#architecture-recovery) |
| `architecture export` | Write the recovered architecture as PlantUML and Structurizr DSL -- see [Architecture recovery](architecture-recovery.md#architecture-recovery) |
| `architecture brief` | Write one JSON file describing the code base for a reader or an LLM -- see [Architecture brief](architecture-brief.md#architecture-brief) |
| `compare`, `pr-comment` | Compare with the target branch; post the result -- see [PR / MR quality check](gating-and-ci.md#pr--mr-quality-check) |
| `standards list\|validate\|report` | MISRA C, CERT C, BARR-C and Power of 10 rules, deviations, compliance matrix |
| `dump-ast` | Print the libclang AST for one file (see below) |

`analyze` and `report` both accept `--baseline`, `--fail-on-breach`, `--update-baseline`,
`--accept-all`, `--accept-id`, and `--prune` -- see [Baseline / breach gating](gating-and-ci.md#baseline--breach-gating).
They also accept `--github-annotations` (print workflow annotations for GitHub Actions) and
`--fail-on-parse-error` (exit 1 when the share of files with fatal or error parse diagnostics is
above `tool.parse_error_threshold`; the default `0` fails on any).
`analyze`, `report`, and `export` all accept `--auto-stub` -- see
[Project-wide auto-stub](parsing.md#project-wide-auto-stub).

`analyze`, `report`, and `export` also accept `--jobs/-j N` (parallel parse workers),
`--timeout SECONDS` (a file whose parse takes longer is killed and reported as a `timeout`
parse error; `0` disables the limit) and `--no-cache`. The same settings are available as
`tool.jobs`, `tool.parse_timeout` and `tool.parse_cache`. Parse results are cached under
`output.cache_dir`, keyed by the source file, every header it includes, its defines and include
paths, the `tool.*` settings, the libclang library and the FWLens version. Files that parsed with
fatal or error diagnostics are never cached.
`report` also writes standalone PNG plots when `plots` is listed in `output.formats` -- see
[Standalone plots](metrics-and-history.md#standalone-plots) -- and Mermaid/SVG diagrams when `diagrams` is listed --
see [Architecture & call-graph diagrams](rtos-and-diagrams.md#architecture--call-graph-diagrams).
`diff-breach` compares two prior JSON exports -- see [Two-hash comparison](parsing.md#two-hash-comparison).
`call-graph` generates an on-demand scoped diagram for one function -- see
[Architecture & call-graph diagrams](rtos-and-diagrams.md#architecture--call-graph-diagrams).

---

#### `dump-ast`

`fwlens dump-ast --file NAME` prints the libclang AST of one in-scope file, for checking what the
analysis sees. `--depth N` limits the depth (default 6); `--var NAME` dumps the initialiser of a
global (a dispatch table, say), `--fn NAME` the references inside a function, and `--find-refs
NAME` searches every in-scope file for functions that reference a global.

### Checking config.yaml

An unknown key (for example `cyclomatic_complexty` under `thresholds`) produces a warning that
names it and suggests the closest known key; the run continues. Unsupported values in
`output.formats` (`html`, `csv`, `json`, `plots`, `diagrams`, `sarif`, `sbom`, `cbom`, `architecture`) and `scope.analyse` stop the
run with the list of valid values. If `config.yaml` is not in the working directory, FWLens looks
for `config.yaml`, `.fwlens.yaml` or `fwlens.yaml` in each parent directory.

`fwlens config-schema` prints a JSON Schema for editors, generated from the same dataclasses the
loader uses (also shipped as `fwlens/config.schema.json`). `config.example.yaml` references it
through a `yaml-language-server` comment.

### Where relative paths in config.yaml point

Input paths (`project.*`, `tool.libclang_path`, `tool.sysroot`, `tool.system_include_dirs` and
`standards.*`) are relative to the directory containing `config.yaml`, so running from another
directory gives the same result. `output.*` paths are the exception: they are relative to the
directory you run `fwlens` from. `fwlens doctor --config config.yaml` prints every resolved path.

## Other build systems and IDEs

| Tool | Route | Key |
| --- | --- | --- |
| IAR Embedded Workbench | reader | `project.ewp` |
| Keil uVision | reader | `project.uvprojx` |
| STM32CubeIDE, Eclipse CDT | reader | `project.cproject` |
| CMake, Make, Ninja | compilation database | `project.compile_commands` |
| Zephyr (`west`) | compilation database (recipe) | `project.compile_commands` |
| PlatformIO | compilation database (recipe) | `project.compile_commands` |
| anything else | scan a directory | `project.source_dir` |

**Keil.** `project.uvprojx: MDK-ARM/project.uvprojx`. `project.configuration` names the *target*
(a project with one target needs no name). FWLens reads the target's `Define` and `IncludePath`
(comma, space or semicolon separated, relative to the `.uvprojx`), and the C files of its groups
(file type 1; assembler and C++ are skipped). Groups become FWLens groups. Whatever the target
keeps in "Misc controls" or in the compiler itself is not read.

**STM32CubeIDE / CDT.** `project.cproject: .cproject`. `project.configuration` names the build
configuration (`Debug`, `Release`). Defines and include paths come from the C compiler options;
`${workspace_loc:/${ProjName}/...}` is resolved, relative paths are resolved from the build
directory, and any other `${variable}` is left out. Source files are the `*.c` files under the
configuration's source folders minus its `excluding` entries.

For both, set `scope.first_party` to the folders that hold your code (for example
`[Core, Drivers]`), because file locations come from the IDE project, not from a fixed layout.

```yaml
project:
  uvprojx: MDK-ARM/project.uvprojx
  configuration: Debug
scope:
  first_party: [Core, Drivers]
```

**Zephyr (west).** `west build` runs CMake, which can write the database:

```bash
west build -b nrf52840dk_nrf52840 app -- -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
```

Then set `project.compile_commands: build/compile_commands.json`. The generated headers
(`-imacros .../autoconf.h`) are read from the build directory, so build first. Cross-compiler
flags such as `-mcpu` and `-mthumb` are accepted; set `tool.target`/`tool.sysroot` if libclang
cannot find the toolchain's headers.

**PlatformIO.**

```bash
pio run -t compiledb
```

writes `compile_commands.json` in the project root (`.pio/build/<env>/` in some versions);
point `project.compile_commands` at it. File paths in it are relative to its `directory`, which
FWLens handles.

These two are recipes, not readers. The tests use compilation databases written in the shape
these tools produce; they do not run `west` or `pio`.

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

`scope.exclude` is a list of globs matched against each path relative to `source_dir` (or
against the bare file or directory name), for example `exclude: ["test/*", "*_generated.c"]`.
`.git`, `build`, `__pycache__`, `.cache`, `node_modules` and `.pytest_cache` are always skipped.

fwlens recursively globs `*.c` under `source_dir`. There is no compile database in this mode,
so include paths are per project, not per file. Three keys control them (all under `project:`):

| Key | Meaning |
| --- | --- |
| `source_dir` | Root that is searched for `*.c` and `*.h`. |
| `include_dirs` | Explicit include path, in search order. Use it to pick one of several ports. Default: none. |
| `include_mode` | `all` (default) adds every directory that holds a header. `used` adds only directories reached by an `#include` from the in-scope `.c` files, following headers transitively. Ignored when `include_dirs` is set. |

and `scope.exclude` (above) leaves paths out of the scan altogether.

When an included header name exists in several directories, fwlens prints one warning naming
the copy that is found first and the ones that are ignored, for example
`Header 'portmacro.h' exists in 3 directories; 'ports/a' wins (searched first), ignored: 'ports/b'`.
Choose the port with `include_dirs` (or exclude the others) to silence it. Boundary classification
(`first_party`/`sdk`/`third_party_lib`) uses the same `scope` config as EWP mode, matched
against each file's path segments; a file under no configured path defaults to
`first_party`. There's no IAR group tree in directory mode, so architecture layer
assignment falls back to path-based matching only (`layers[].groups` rules never match).

`project.ewp` and `project.source_dir` are mutually exclusive; `debug` and `debug-parse`
are EWP-specific diagnostics and aren't available in directory mode.

