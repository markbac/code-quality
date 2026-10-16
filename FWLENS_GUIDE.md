# fwlens -- Embedded C Architecture & Static Analysis Platform

The guide is split by topic. Each section below opens the file that holds it.

## Contents

### Getting started

- [Quick start](docs/guide/getting-started.md#quick-start)
- [Commands](docs/guide/getting-started.md#commands)
- [Other build systems and IDEs](docs/guide/getting-started.md#other-build-systems-and-ides)
- [Directory mode (no .ewp)](docs/guide/getting-started.md#directory-mode-no-ewp)

### Gating, history and CI integration

- [Baseline / breach gating](docs/guide/gating-and-ci.md#baseline--breach-gating)
- [Run history, trends and the ratchet](docs/guide/gating-and-ci.md#run-history-trends-and-the-ratchet)
- [JUnit and Markdown summaries](docs/guide/gating-and-ci.md#junit-and-markdown-summaries)
- [GitLab integration](docs/guide/gating-and-ci.md#gitlab-integration)
- [PR / MR quality check](docs/guide/gating-and-ci.md#pr--mr-quality-check)

### Coding standards

- [Coding standards (MISRA C, CERT C, BARR-C, Power of 10)](docs/guide/standards.md#coding-standards-misra-c-cert-c-barr-c-power-of-10)

### Bills of materials

- [Software bill of materials (SBOM)](docs/guide/bills-of-materials.md#software-bill-of-materials-sbom)
- [Cryptography bill of materials (CBOM)](docs/guide/bills-of-materials.md#cryptography-bill-of-materials-cbom)

### Parsing, stubs and diagnostics

- [Two-hash comparison](docs/guide/parsing.md#two-hash-comparison)
- [Project-wide auto-stub](docs/guide/parsing.md#project-wide-auto-stub)
- [Diagnostic clusters](docs/guide/parsing.md#diagnostic-clusters)

### Metrics, hotspots and git history

- [Standalone plots](docs/guide/metrics-and-history.md#standalone-plots)
- [File-level metrics](docs/guide/metrics-and-history.md#file-level-metrics)
- [Git history warnings](docs/guide/metrics-and-history.md#git-history-warnings)
- [Hotspot analysis](docs/guide/metrics-and-history.md#hotspot-analysis)
- [Bug-fix-weighted hotspots](docs/guide/metrics-and-history.md#bug-fix-weighted-hotspots)
- [Judge hotspots by name](docs/guide/metrics-and-history.md#judge-hotspots-by-name)
- [Complexity trend over time](docs/guide/metrics-and-history.md#complexity-trend-over-time)
- [Hotspot visualisation](docs/guide/metrics-and-history.md#hotspot-visualisation)
- [ISR / main-loop shared-variable risk](docs/guide/metrics-and-history.md#isr--main-loop-shared-variable-risk)
- [Worst-case stack per entry point](docs/guide/metrics-and-history.md#worst-case-stack-per-entry-point)
- [Tech debt scanning](docs/guide/metrics-and-history.md#tech-debt-scanning)
- [Clone detection](docs/guide/metrics-and-history.md#clone-detection)
- [Change coupling](docs/guide/metrics-and-history.md#change-coupling)
- [Architecture-level change coupling](docs/guide/metrics-and-history.md#architecture-level-change-coupling)
- [Commit heatmaps](docs/guide/metrics-and-history.md#commit-heatmaps)
- [Commit date (activity) heatmap](docs/guide/metrics-and-history.md#commit-date-activity-heatmap)
- [Code ownership / knowledge maps](docs/guide/metrics-and-history.md#code-ownership--knowledge-maps)
- [Information flow complexity](docs/guide/metrics-and-history.md#information-flow-complexity)
- [COCOMO effort estimate](docs/guide/metrics-and-history.md#cocomo-effort-estimate)
- [Reliability growth](docs/guide/metrics-and-history.md#reliability-growth)
- [Composite risk ranking](docs/guide/metrics-and-history.md#composite-risk-ranking)

### RTOS, state machines and diagrams

- [RTOS task/synchronisation analysis](docs/guide/rtos-and-diagrams.md#rtos-tasksynchronisation-analysis)
- [State machine detection](docs/guide/rtos-and-diagrams.md#state-machine-detection)
- [Source viewer & report file size](docs/guide/rtos-and-diagrams.md#source-viewer--report-file-size)
- [Architecture & call-graph diagrams](docs/guide/rtos-and-diagrams.md#architecture--call-graph-diagrams)

### Architecture recovery

- [Architecture recovery](docs/guide/architecture-recovery.md#architecture-recovery)
- [Architecture brief](docs/guide/architecture-brief.md#architecture-brief)

### Reference

- [Configuration reference](docs/guide/reference.md#configuration-reference)
- [Metric reference](docs/guide/reference.md#metric-reference)
- [Analysis sections explained](docs/guide/reference.md#analysis-sections-explained)
- [Known limitations and sanity notes](docs/guide/reference.md#known-limitations-and-sanity-notes)
- [Metrics Etiquette](docs/guide/reference.md#metrics-etiquette)
- [References](docs/guide/reference.md#references)
