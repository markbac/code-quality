# FWLens (Firmware Lens)

**FWLens** is a specialized code quality, static analysis, structural debt, and RTOS architecture inspection tool designed for C/C++ embedded systems. It parses **CMake** (`compile_commands.json`), **Make** (`bear -- make`, `compiledb`), **IAR Embedded Workbench** (`.ewp`), and source directories using `libclang` to generate rich metrics, dependency graphs, RTOS task maps, and interactive HTML reports.

## Key Features

- **Multi-Build System Support**: Parses **CMake** compilation databases (`compile_commands.json`), **Make** build logs, **IAR Embedded Workbench** (`.ewp`) project files, or directory trees.
- **Static Code Analysis**: Computes Cyclomatic Complexity, Cognitive Complexity, Halstead metrics, function length, block depth, parameter counts, and magic number density using `libclang`.
- **Architecture & Layer Boundaries**: Categorizes code across SDK, ThirdParty, BSP, RTOS, Middleware, Services, and Application layers, measuring coupling and instability metrics (Zone of Pain / Zone of Uselessness).
- **RTOS Analysis**: Mappings for embOS RTOS tasks, stacks, priorities, mailboxes, semaphores, and synchronization mechanisms.
- **Git Hotspot Mining**: Correlates commit churn with structural complexity to pinpoint high-risk files.
- **Auto-Stubbing & Header Checks**: Automatic stub generation for missing include headers and missing compiler definitions.
- **Rich Reporting**: Outputs summary console tables, CSV data exports, JSON metrics, Mermaid dependency diagrams, and self-contained interactive HTML dashboards.

## Quick Start

### Prerequisites

1. **Python 3.10+**
2. **LLVM / Clang**: Install LLVM and ensure `libclang.dll` (or `libclang.so` / `libclang.dylib`) is available on your machine.
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Configuration Options

Copy `config.example.yaml` to `config.yaml` and choose your build system:

#### Option A: CMake or Make (`compile_commands.json`)
```yaml
tool:
  libclang_path: C:\Program Files\LLVM\bin\libclang.dll

project:
  compile_commands: build/compile_commands.json
  mode: cmake   # or 'make'
```

#### Option B: IAR Embedded Workbench (`.ewp`)
```yaml
tool:
  libclang_path: C:\Program Files\LLVM\bin\libclang.dll

project:
  ewp: path/to/your/project.ewp
  configuration: Release
  toolkit_dir: C:\Program Files\IAR Systems\Embedded Workbench 9.6\arm
```

#### Option C: Directory Scan Mode
```yaml
project:
  source_dir: C:\Projects\my-embedded-library
```

### Usage

Run FWLens analysis using Python:

```bash
python main.py report --config config.yaml
```

Or using PowerShell runner:

```powershell
.\Run-FwLens.ps1 report
```

Run tests:

```bash
pytest
```

For full documentation, see [FWLENS_GUIDE.md](FWLENS_GUIDE.md).