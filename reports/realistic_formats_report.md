# LeakLens Analysis Report

**Input log:** `sample-output/realistic_formats.info`

## Potential Leaks Detected

### Finding 1
- Source: `token`
- Sink: `printf()`
- Severity: `medium`
- Path: `token -> printf`
- Evidence: `WARNING: tainted variable 'token' reached sink printf()`
- Location: `line 3`
- Parser rule: `declared-sink`

### Finding 2
- Source: `password`
- Sink: `send()`
- Severity: `high`
- Path: `password -> send`
- Evidence: `Leak detected: symbolic input password reached send()`
- Location: `line 4`
- Parser rule: `declared-sink`

### Finding 3
- Source: `api_key`
- Sink: `write()`
- Severity: `high`
- Path: `api_key -> serializer -> write`
- Evidence: `LEAK: source=api_key sink=write path=api_key -> serializer -> write`
- Location: `line 5`
- Parser rule: `explicit-path`

### Finding 4
- Source: `session_id`
- Sink: `fprintf()`
- Severity: `medium`
- Path: `session_id -> audit_log -> fprintf`
- Evidence: `TAINTED source=session_id path=session_id -> audit_log -> fprintf`
- Location: `line 7`
- Parser rule: `explicit-path`

## Safe or Non-Leaking Flows Observed

- `user_id -> mask_value -> strlen`

## Parse Summary

- Ignored non-evidence lines: `2`

## Notes

This report is based on taint-style log evidence. It does not prove absence of leaks on paths that KLEE did not explore.
