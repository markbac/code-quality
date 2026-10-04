# `py-doclint` — Technical Writing Style & Glossary Validator Toolkit

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)
![Linting](https://img.shields.io/badge/Documentation-Markdown%20Linter-green.svg)

`py-doclint` is a generic, Python-based CLI developer toolkit and linting engine for enforcing technical writing style standards, term capitalization consistency, and prose quality across Markdown documentation repositories.

---

## 🎯 What It Does

In technical documentation, term inconsistency (e.g. mixing `dtls`, `DTLS`, and `Dtls`) and wordy prose degrade documentation quality. `py-doclint` provides:

1. **Glossary Capitalization Enforcement**: Automatically detects lowercase or improperly capitalized technical terms (`LwM2M`, `DTLS`, `UART`, `MQTT`, `IPv6`, `JSON`, `YAML`, `API`, `HTTP`, `HTTPS`).
2. **Redundant Phrase Detection**: Flags wordy, redundant prose (e.g. *"in order to"*, *"at this point in time"*, *"for the purpose of"*).
3. **Acronym Definition Checking**: Identifies acronym expansions (e.g. *"Pre-Shared Key (PSK)"*) and warns on unexpanded acronym usage.
4. **CI/CD Strict Mode**: Enforces exit code `1` in automated testing pipelines when documentation defects exist.
5. **Py-LogKit Logging**: Color-coded output formatting (`pylogkit`).

---

## 🏗️ Tool Architecture

The package follows a decoupled architecture separating AST token parsing from rule validators:

```
py-doclint/
├── pydoclint/
│   ├── __init__.py         # Package initialization
│   ├── linter.py           # Core DocLinter & LintIssue rule engine
│   ├── cli.py              # CLI Argument Parser & Runner
│   └── pylogkit/           # Py-LogKit logging framework
├── tests/
│   └── test_linter.py      # Unit test suite
├── setup.py                # Package metadata & entry points
└── README.md               # Comprehensive documentation
```

### Architecture Pipeline

```
[Markdown Files (.md)] ──► [Line & Code Block Filter]
                                    │
                                    ▼
                          [DocLinter Engine]
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        ▼                           ▼                           ▼
[Glossary Rules]           [Redundant Phrases]         [Acronym Parser]
(LwM2M, DTLS, UART)       ("in order to", etc.)       (Pre-Shared Key)
        │                           │                           │
        └───────────────────────────┼───────────────────────────┘
                                    │
                                    ▼
                         [LintIssue Collector]
                                    │
                                    ▼
                    [Console Output / CI Exit Code]
```

---

## 💻 Installation

```bash
# Clone repository
git clone https://github.com/markbac/py-doclint.git
cd py-doclint

# Install in editable mode
pip install -e .
```

---

## 🛠️ How To Use

### 1. Command-Line Interface (CLI)

```bash
# Lint all Markdown documentation in current directory
py-doclint .

# Target a specific documentation file
py-doclint docs/architecture/Overview.md

# Enforce strict pipeline failure in CI/CD
py-doclint docs/ --strict
```

#### CLI Options Reference

| Flag | Short | Default | Description |
|---|---|---|---|
| `target` | | `.` | Path to Markdown file (`.md`) or documentation folder |
| `--strict` | | `False` | Exit with status code 1 if any style or glossary issues are detected |

---

### 2. Python API

```python
from pathlib import Path
from pydoclint import DocLinter

# Initialize linter with custom glossary override
linter = DocLinter(glossary={
    "LwM2M": ["lwm2m", "LWM2M"],
    "DTLS": ["dtls"],
    "CoAP": ["coap", "COAP"]
})

# Lint single file
issues = linter.lint_file(Path("README.md"))
for issue in issues:
    print(f"[{issue.category}] Line {issue.line_no}: {issue.message}")

# Lint entire directory
dir_results = linter.lint_directory(Path("./docs"))
for path, file_issues in dir_results.items():
    print(f"{path}: {len(file_issues)} issues found.")
```

---

## 🧪 Running Tests

```bash
python -m pytest
```

---

## 📄 License

Licensed under the [MIT License](LICENSE).
