# FWLens (Firmware Lens)

**FWLens** is a specialized code quality, static analysis, structural debt, and RTOS architecture inspection tool designed for C/C++ embedded systems. It parses **CMake** (`compile_commands.json`), **Make** (`bear -- make`, `compiledb`), **IAR Embedded Workbench** (`.ewp`), **Keil uVision** (`.uvprojx`), **STM32CubeIDE / Eclipse CDT** (`.cproject`), and source directories using `libclang` to generate rich metrics, dependency graphs, RTOS task maps, and interactive HTML reports.

## Key Features

- **Multi-Build System Support**: Parses **CMake** compilation databases (`compile_commands.json`), **Make** build logs, **IAR Embedded Workbench** (`.ewp`), **Keil uVision** (`.uvprojx`) and **STM32CubeIDE** (`.cproject`) project files, or directory trees.
- **Static Code Analysis**: Computes Cyclomatic Complexity, Cognitive Complexity, Halstead metrics, function length, block depth, parameter counts, and magic number density using `libclang`.
- **Architecture & Layer Boundaries**: Categorizes code across SDK, ThirdParty, BSP, RTOS, Middleware, Services, and Application layers, measuring coupling and instability metrics (Zone of Pain / Zone of Uselessness).
- **RTOS Analysis**: Mappings for embOS RTOS tasks, stacks, priorities, mailboxes, semaphores, and synchronization mechanisms.
- **Git Hotspot Mining**: Correlates commit churn with structural complexity to pinpoint high-risk files.
- **Auto-Stubbing & Header Checks**: Automatic stub generation for missing include headers and missing compiler definitions.
- **Standards and Quality Gates**: MISRA C:2012 and C:2023, CERT C, BARR-C, AUTOSAR (C subset), ISO/IEC TS 17961 and NASA/JPL Power of 10 checks, plus secrets, dead code and interrupt safety checks (over 600 guidelines checked natively, mapped to CWE) with a deviation register and compliance matrix; baselines, a pull-request check, Flash and RAM growth limits from the linker map, and run history.
- **SBOM and CBOM**: `fwlens sbom` writes a CycloneDX 1.6 software bill of materials from the source tree, and `fwlens cbom` a cryptography bill of materials of the algorithms, protocols, libraries, certificates and keys the code names, with keyword autodetection and your own API names from the config (detected usage only, not a complete inventory).
- **Architecture recovery** (being built, see #133): a model of the architecture as implemented, system and subsystem patterns (layered, HAL, super-loop, RTOS, event-driven; UI and comms patterns), conformance rules and PlantUML and Structurizr export. Design in [`docs/ARCHITECTURE_RECOVERY.md`](docs/ARCHITECTURE_RECOVERY.md), tracked in #133.
- **Rich Reporting**: Outputs summary console tables, CSV data exports, JSON metrics, Mermaid dependency diagrams, and self-contained interactive HTML dashboards.

## Quick Start

### Prerequisites

1. **Python 3.10+**
2. **libclang**: installed automatically with FWLens (the `libclang` wheel bundles the shared library, supported range `>=16`). To use a full LLVM install instead, set `tool.libclang_path` or the `LIBCLANG_PATH` environment variable.
3. Install FWLens and its dependencies (`pyproject.toml` is the single source of truth):
   ```bash
   pip install -e .[dev]      # from a checkout
   pip install fwlens         # or from a package index
   ```

libclang is located in this order: `tool.libclang_path` (an explicit path that does not exist is an error), then `LIBCLANG_PATH`, then the bundled wheel library.

For hosts without an LLVM install, FWLens finds system headers by asking your C compiler (`arm-none-eabi-gcc` for ARM targets, `gcc`/`cc`/`clang` for `tool.target: native`). Set `tool.system_include_dirs` to override.

### Configuration Options

Copy `config.example.yaml` to `config.yaml` and choose your build system. Input paths are relative to the config file; `output.*` paths are relative to the directory you run FWLens from.

#### Option A: CMake or Make (`compile_commands.json`)
```yaml
project:
  compile_commands: build/compile_commands.json
  mode: cmake   # or 'make'
```

#### Option B: IAR Embedded Workbench (`.ewp`)
```yaml
project:
  ewp: path/to/your/project.ewp
  configuration: Release
  toolkit_dir: C:\Program Files\IAR Systems\Embedded Workbench 9.6\arm
```

#### Option B2: Keil uVision or STM32CubeIDE
```yaml
project:
  uvprojx: MDK-ARM/project.uvprojx   # or: cproject: .cproject
  configuration: Debug               # the Keil target, or the CubeIDE build configuration
```

#### Option C: Directory Scan Mode
```yaml
project:
  source_dir: src
```

To use a full LLVM install instead of the bundled libclang, add `tool.libclang_path` (or set `LIBCLANG_PATH`).

### Usage

Check the environment, then analyse:

```bash
fwlens doctor --config config.yaml     # libclang, compiler, git, resolved paths
fwlens analyze --config config.yaml    # console summary
fwlens report --config config.yaml     # HTML report plus CSV and JSON exports
```

`python main.py report` does the same from a checkout, and `.\Run-FwLens.ps1 report` wraps it for PowerShell.

Useful options on `analyze`, `report` and `export`: `--jobs/-j`, `--timeout` and `--no-cache` for parsing, `--auto-stub` for missing toolchain headers, and `--fail-on-parse-error`.

Other commands: `init` writes a starter config, `config-schema` prints the JSON Schema for editors, `compare` and `pr-comment` check a pull request, `standards` checks MISRA C, CERT C, BARR-C, AUTOSAR, TS 17961, Power of 10 and the FWLens checks, `call-graph` draws one function's neighbourhood, `diff-breach` compares two exports, and `debug`, `debug-parse` and `dump-ast` diagnose parsing. The guide's Commands section lists them all.

### Bills of materials

```bash
fwlens sbom --config config.yaml   # CycloneDX 1.6 JSON: components, versions, licences, hashes
fwlens cbom --config config.yaml   # CycloneDX 1.6 JSON: cryptographic algorithms, protocols, libraries
```

Both write to `output.exports_dir`, or `output.formats: [sbom, cbom]` makes `report` write them. Versions and licences come only from the source tree and are marked unknown when absent. The CBOM is a static scan: it reports what the code names and cannot see runtime configuration, negotiated protocols or keys. See the guide for details.

### Quality gates and CI

- **Baselines**: `--baseline baseline.json` with `--fail-on-breach` fails only on new or worsened breaches; `--update-baseline` records the current state. Findings follow code that moves or is renamed; matching is heuristic, so a function that is largely rewritten shows as one resolved and one new finding, and `diff-breach` on exports without fingerprints matches by key only. Tune it with the `match:` section (see the guide, "Moved and renamed code").
- **GitHub and GitLab**: `--github-annotations`, `--gitlab-codequality`, `--findings-json`, and `fwlens pr-comment` for pull and merge requests. See the guide for the GitHub Action and GitLab template.
- **Coding standards**: `fwlens standards list`, `validate` and `report` check MISRA C, CERT C, BARR-C, AUTOSAR, TS 17961, Power of 10 and FWLens rules, with CWE ids, deviations and a compliance matrix.

Git-history metrics (hotspots, coupling, ownership) need full history; use `fetch-depth: 0` with `actions/checkout`.

### Tests

```bash
pip install -e .[dev]
pytest
```

For full documentation, see [FWLENS_GUIDE.md](FWLENS_GUIDE.md).
