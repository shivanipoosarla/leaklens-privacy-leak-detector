# LeakLens Analysis Report

**Input log:** `sample-output/direct_leak.info`

## Potential Leaks Detected

### Finding 1
- Source: `input`
- Sink: `printf()`
- Severity: `medium`
- Path: `input -> printf`
- Evidence: `TAINTED source=input path=input -> printf`
- Location: `line 2`
- Parser rule: `explicit-path`

## Parse Summary

- Ignored non-evidence lines: `0`

## Notes

This report is based on taint-style log evidence. It does not prove absence of leaks on paths that KLEE did not explore.
