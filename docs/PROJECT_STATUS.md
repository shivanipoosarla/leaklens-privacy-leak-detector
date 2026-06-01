# Project Status

## Implemented

- Command-line parser for taint-style logs.
- Configurable sink list.
- Detection for direct, logging, network-style, and mixed-format taint evidence.
- Markdown, JSON, and DOT report generation.
- Unit tests for supported log formats.
- C syntax checks for example programs using a local KLEE header stub.
- Sample logs and generated reports for reviewers.

## Intentionally not claimed

This prototype does not yet claim to be a full privacy leak detector for raw KLEE output. It does not:

- parse `.ktest` files;
- instrument KLEE;
- perform runtime taint tracking;
- guarantee complete source-to-sink coverage;
- prove absence of leaks when no finding is reported.

## Recommended next steps

1. Add optional `.ktest` parsing.
2. Add real KLEE run instructions.
3. Add more sink categories, such as file, network, logging, IPC, and cloud/API sinks.
4. Add configurable source labels.
5. Add CI status once the repo is pushed to GitHub.
6. Add a small architecture diagram rendered from DOT output.
