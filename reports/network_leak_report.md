# LeakLens Analysis Report

**Input log:** `sample-output/network_leak.info`

## Potential Leaks Detected

### Finding 1
- Source: `sensitive`
- Sink: `send()`
- Severity: `high`
- Path: `sensitive -> network_send -> send`
- Evidence: `LEAK source=sensitive path=sensitive -> network_send -> send`
- Location: `line 2`
- Parser rule: `explicit-path`

## Parse Summary

- Ignored non-evidence lines: `0`

## Notes

This report is based on taint-style log evidence. It does not prove absence of leaks on paths that KLEE did not explore.
