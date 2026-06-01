# LeakLens Architecture

LeakLens is organized as a lightweight post-processing pipeline.

```text
C example program
   |
LLVM bitcode
   |
KLEE / KLEE-taint run
   |
Taint-style log output
   |
LeakLens parser
   |
Finding extraction
   |
Markdown / JSON / DOT reports
```

## Components

### 1. Example programs

The `examples/` directory contains small C programs that model common privacy-flow scenarios:

- `leak_printf.c`: symbolic input reaches `printf()`.
- `leak_log.c`: symbolic input reaches a logging-style sink via `fprintf()`.
- `leak_network.c`: symbolic input reaches a network-style `send()` sink.
- `benign.c`: symbolic input is used without reaching a configured privacy sink.

The local `stubs/klee/klee.h` file exists only so the examples can pass syntax checks without a full KLEE installation.

### 2. Sample taint-style logs

The `sample-output/` directory contains synthetic logs that represent the type of evidence LeakLens expects. These logs make the project runnable for reviewers who do not have KLEE installed.

### 3. Parser

The parser in `src/leaklens.py` looks for source/sink/path evidence using simple structured patterns:

- `source=...`
- `sink=...`
- `path=a -> b -> c`
- `symbolic input X reached Y()`
- `tainted variable 'X' reached sink Y()`

The parser extracts:

- source
- sink
- path
- line number
- evidence text
- severity
- parser rule

### 4. Report generation

LeakLens writes three report formats for each input log:

- Markdown: human-readable review output.
- JSON: structured output for automation.
- DOT: source-to-sink graph representation.

## Current design tradeoff

LeakLens intentionally prioritizes a simple, explainable post-processing design. It does not modify KLEE and does not perform runtime taint tracking. This makes the prototype easy to run and review, but it also means accuracy depends on the quality of the taint-style evidence provided in the log.
