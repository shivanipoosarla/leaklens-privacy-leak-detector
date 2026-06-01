# LeakLens Analysis Report

**Input log:** `sample-output/log_leak.info`

## Potential Leaks Detected

### Finding 1
- Source: `secret`
- Sink: `fprintf()`
- Severity: `medium`
- Path: `secret -> log_data -> fprintf`
- Evidence: `TAINTED source=secret path=secret -> log_data -> fprintf`
- Location: `line 2`
- Parser rule: `explicit-path`

## Parse Summary

- Ignored non-evidence lines: `0`

## Notes

This report is based on taint-style log evidence. It does not prove absence of leaks on paths that KLEE did not explore.
