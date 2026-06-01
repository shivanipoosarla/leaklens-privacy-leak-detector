# Resume and LinkedIn Snippets

## Resume project entry

**LeakLens: Privacy Leak Detection for Taint-Style KLEE Outputs | Python, KLEE, LLVM, C, Taint Analysis**

- Built a prototype Python post-processor for taint-style KLEE/KLEE-taint output that summarizes potential privacy leaks when symbolic inputs reach unsafe sinks such as `printf()`, `fprintf()`, `send()`, and `write()`.
- Implemented parser logic to extract source, sink, path, severity, evidence line, and parser rule metadata from multiple taint-evidence formats, generating Markdown, JSON, and Graphviz DOT reports.
- Created C examples and sample logs for console, logging, network-style, benign, and mixed-format flows, with unit tests and CI-ready GitHub Actions workflow.

## Shorter resume version

- Built LeakLens, a Python post-processor for taint-style KLEE/KLEE-taint logs that detects symbolic-input flows to unsafe sinks and generates Markdown, JSON, and DOT privacy-leak reports.

## LinkedIn project description

LeakLens is a Python prototype that summarizes privacy-leak evidence from taint-style KLEE/KLEE-taint logs. It detects symbolic inputs reaching configured sinks such as `printf()`, `fprintf()`, `send()`, and `write()`, then generates readable Markdown, JSON, and DOT reports. The project includes C examples, synthetic sample logs, unit tests, and a GitHub Actions workflow.

## GitHub profile pinned repo description

Python post-processor for taint-style KLEE/KLEE-taint logs that summarizes symbolic-input flows to unsafe privacy sinks.

## Safer interview wording

This is a prototype, not a full KLEE extension. The current version analyzes taint-style logs and generates privacy-leak reports. I intentionally documented that `.ktest` parsing, raw KLEE-output correlation, and runtime taint tracking are future work.
