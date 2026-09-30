# FWLens (Firmware Lens)

**FWLens** is a specialized code quality, static analysis, structural debt, and RTOS architecture inspection tool designed for C/C++ embedded systems. It parses IAR Embedded Workbench projects (`.ewp`) and source directories using `libclang` to generate rich metrics, dependency graphs, RTOS task maps, and interactive HTML reports.

## Key Features

- **Static Code Analysis**: Analyzes Cyclomatic Complexity, Cognitive Complexity, Halstead metrics, function length, block depth, parameter counts, and magic number density using `libclang`.
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

### Configuration

Copy `config.example.yaml` to `config.yaml` and configure your project paths:

```yaml
tool:
  libclang_path: C:\Program Files\LLVM\bin\libclang.dll

project:
  ewp: path/to/your/project.ewp
  configuration: Release
  toolkit_dir: C:\Program Files\IAR Systems\Embedded Workbench 9.6\arm
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

For full documentation, see [FWLENS_GUIDE.md](FWLENS_GUIDE.md).