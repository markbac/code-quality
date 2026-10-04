# `py-doc2slides` — Markdown to PowerPoint (.pptx) Presentation Converter

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)
![PowerPoint](https://img.shields.io/badge/Microsoft-PowerPoint-red.svg)

`py-doc2slides` is a generic, Python-based CLI developer toolkit for converting Markdown technical documentation into styled **Microsoft PowerPoint (`.pptx`)** slide presentation decks. Improved and evolved from `createdocs` and `Convert_to_pptx.ps1` in `markbac/technical-documentation`.

---

## 🎯 What It Does

`py-doc2slides` converts technical Markdown documentation into professional PowerPoint presentations:

1. **Automated Slide Delimitation**: Intelligently splits Markdown files into separate slides on horizontal rules (`---`) or heading boundaries (`#`, `##`).
2. **Title & Content Layout Assignment**: Automatically formats the initial slide as a Title/Subtitle slide, and subsequent sections into Title + Body content layouts.
3. **Monospaced Code Block Styling**: Formats technical code fences (` ``` `) into monospaced Consolas text boxes for slide presentations.
4. **Reference Template Support**: Allows injecting custom PowerPoint master templates (`-r Template.pptx`) for corporate branding, slide dimensions (16:9 widescreen), background graphics, and fonts.
5. **Py-LogKit Logging**: Color-coded progress logging (`pylogkit`).

---

## 🏗️ Tool Architecture

The package wraps `python-pptx` layout parsers and paragraph builders:

```
py-doc2slides/
├── pydoc2slides/
│   ├── __init__.py         # Package initialization
│   ├── converter.py        # Core SlidesConverter & Slide Splitter engine
│   ├── cli.py              # CLI Argument Parser & Runner
│   └── pylogkit/           # Py-LogKit logging framework
├── tests/
│   └── test_converter.py   # Unit test suite
├── setup.py                # Package metadata & entry points
└── README.md               # Comprehensive documentation
```

### Slide Processing Pipeline

```
[Markdown File (.md)] ──► [Slide Splitter Engine (--- / #)]
                                     │
                                     ▼
                           [SlidesConverter Engine]
                                     │
         ┌───────────────────────────┼───────────────────────────┐
         ▼                           ▼                           ▼
[Title Slide Layout]        [Bullet Content Layout]     [Code Fence Formatter]
 (First Slide Title/Sub)     (Level 0 Bullet Points)     (Consolas 11pt Box)
         │                           │                           │
         └───────────────────────────┼───────────────────────────┘
                                     │
                                     ▼
                         [Optional Master Template]
                                     │
                                     ▼
                        [PowerPoint Deck (.pptx)]
```

---

## 💻 Installation

```bash
# Clone repository
git clone https://github.com/markbac/py-doc2slides.git
cd py-doc2slides

# Install in editable mode
pip install -e .
```

---

## 🛠️ How To Use

### 1. Command-Line Interface (CLI)

```bash
# Convert single Markdown file to PowerPoint presentation
py-doc2slides Technical_Presentation.md -o Technical_Presentation.pptx

# Convert using reference PowerPoint master template
py-doc2slides Architecture_Overview.md -r Template.pptx

# Batch convert entire directory of Markdown docs
py-doc2slides docs/ -o dist/pptx/
```

#### CLI Options Reference

| Flag | Short | Default | Description |
|---|---|---|---|
| `input` | | *Required* | Path to input Markdown (`.md`) file or directory |
| `--output` | `-o` | Same as input | Output `.pptx` file path or destination directory |
| `--reference` | `-r` | `None` | Optional path to reference PowerPoint (`.pptx`) master template |

---

### 2. Python API

```python
from pathlib import Path
from pydoc2slides import SlidesConverter

# Initialize converter with optional master template
converter = SlidesConverter(template_path=Path("templates/Template.pptx"))

# Convert Markdown file
output_path = converter.convert_file(
    md_path=Path("Presentation.md"),
    output_path=Path("output/Presentation.pptx")
)
print(f"Generated PowerPoint presentation: {output_path}")
```

---

## 🧪 Running Tests

```bash
python -m pytest
```

---

## 📄 License

Licensed under the [MIT License](LICENSE).
