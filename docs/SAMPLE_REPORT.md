# Sample LeakLens Report

This is a representative generated report from `sample-output/realistic_formats.info`.

```text
Analyzed 1 log file(s). Potential leaks found: 4.
```

## Finding example

```text
Source: api_key
Sink: write()
Severity: high
Path: api_key -> serializer -> write
Evidence: LEAK: source=api_key sink=write path=api_key -> serializer -> write
Location: line 5
Parser rule: explicit-path
```

## Safe flow example

```text
user_id -> mask_value -> strlen
```

## Important note

A clean report means LeakLens did not find a configured sink in the provided taint-style log. It does not prove that the analyzed program has no privacy leaks.
