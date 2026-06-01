#!/usr/bin/env python3
"""
LeakLens: lightweight post-processor for taint-style KLEE/KLEE-taint logs.

This version is intentionally runnable without a local KLEE installation. It parses
sample taint-style logs, detects when tainted symbolic inputs reach configured
sinks, and writes Markdown/JSON/DOT reports. Optional .ktest support can be added
later without making it a hard dependency.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Sequence

DEFAULT_SINKS = ("printf", "fprintf", "send", "write", "log_data")
DEFAULT_SAFE_TERMS = ("strlen", "strcmp", "memcmp", "internal", "safe")
HIGH_SEVERITY_SINKS = {"send", "write"}


@dataclass(frozen=True)
class Finding:
    """A potential taint flow from a symbolic source to a sink."""

    source: str
    sink: str
    path: list[str]
    evidence: str
    severity: str = "medium"
    line_number: int | None = None
    parser_rule: str = "unknown"


@dataclass(frozen=True)
class AnalysisResult:
    """Structured analysis output for one log file."""

    input_file: str
    findings: list[Finding]
    safe_flows: list[str]
    ignored_lines: int

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)


IDENT = r"[A-Za-z_][\w.:-]*"
FLOW_RE = re.compile(rf"(?P<flow>{IDENT}(?:\s*->\s*{IDENT})+)")
PATH_RE = re.compile(rf"\bpath\s*[:=]\s*(?P<path>{IDENT}(?:\s*->\s*{IDENT})+)", re.I)
SOURCE_PATTERNS = (
    re.compile(r"\b(?:source|src|input|symbolic(?: input)?|tainted(?: variable)?)\s*[:=]\s*[\"']?(?P<source>[A-Za-z_]\w*)", re.I),
    re.compile(r"\bsymbolic input\s+[\"']?(?P<source>[A-Za-z_]\w*)[\"']?", re.I),
    re.compile(r"\btainted variable\s+[\"']?(?P<source>[A-Za-z_]\w*)[\"']?", re.I),
    re.compile(r"\binput\s+[\"'](?P<source>[A-Za-z_]\w*)[\"']", re.I),
)
SINK_PATTERNS = (
    re.compile(r"\b(?:sink|dst|destination)\s*[:=]\s*(?P<sink>[A-Za-z_]\w*)\s*(?:\(|\b)", re.I),
    re.compile(r"\breached\s+(?:sink\s+)?(?P<sink>[A-Za-z_]\w*)\s*(?:\(|\b)", re.I),
    re.compile(r"\bflows?\s+(?:to|into)\s+(?P<sink>[A-Za-z_]\w*)\s*(?:\(|\b)", re.I),
)
TAINT_HINT_RE = re.compile(r"\b(TAINTED|LEAK|LEAKAGE|PRIVACY|taint|tainted|sink|flow)\b", re.I)


def _normalize_sink(name: str) -> str:
    return name.strip().replace("()", "")


def _split_flow(flow_text: str) -> list[str]:
    return [part.strip().replace("()", "") for part in flow_text.split("->") if part.strip()]


def _extract_path(text: str) -> list[str]:
    """Return an explicit path if present, otherwise the first arrow-flow."""
    match = PATH_RE.search(text)
    if match:
        return _split_flow(match.group("path"))

    match = FLOW_RE.search(text)
    if match:
        return _split_flow(match.group("flow"))

    return []


def _contains_sink(text: str, sinks: Sequence[str]) -> str | None:
    """Return the first configured sink that appears as a function/name token."""
    for sink in sinks:
        pattern = rf"\b{re.escape(sink)}\s*(?:\(|\b)"
        if re.search(pattern, text):
            return sink
    return None


def _extract_declared_sink(text: str) -> str | None:
    for pattern in SINK_PATTERNS:
        match = pattern.search(text)
        if match:
            return _normalize_sink(match.group("sink"))
    return None


def _extract_source(text: str, flow_nodes: Sequence[str] | None = None) -> str:
    for pattern in SOURCE_PATTERNS:
        match = pattern.search(text)
        if match:
            return match.group("source")
    if flow_nodes:
        return flow_nodes[0]
    return "unknown"


def _severity_for_sink(sink: str) -> str:
    return "high" if sink in HIGH_SEVERITY_SINKS else "medium"


def _parser_rule(text: str, flow_nodes: Sequence[str], declared_sink: str | None) -> str:
    if PATH_RE.search(text):
        return "explicit-path"
    if declared_sink:
        return "declared-sink"
    if flow_nodes:
        return "arrow-flow"
    return "sink-token"


def parse_log_line(line: str, line_number: int, sinks: Sequence[str] = DEFAULT_SINKS) -> tuple[Finding | None, str | None, bool]:
    """Parse one log line.

    Returns: (finding, safe_flow, ignored)
    """
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None, None, False

    flow_nodes = _extract_path(stripped)
    declared_sink = _extract_declared_sink(stripped)
    configured_sink = _contains_sink(stripped, sinks)

    # Prefer a sink explicitly declared by the log only if it is configured.
    if declared_sink and declared_sink in sinks:
        matched_sink = declared_sink
    else:
        matched_sink = configured_sink

    has_taint_hint = bool(TAINT_HINT_RE.search(stripped))
    has_flow_to_sink = bool(flow_nodes and matched_sink and flow_nodes[-1] == matched_sink)
    has_sink_with_source = bool(matched_sink and _extract_source(stripped, flow_nodes) != "unknown")

    if matched_sink and (has_taint_hint or has_flow_to_sink or has_sink_with_source):
        source = _extract_source(stripped, flow_nodes)
        path = flow_nodes if flow_nodes else [source, matched_sink]
        if path[-1] != matched_sink:
            path = [*path, matched_sink]
        return (
            Finding(
                source=source,
                sink=_normalize_sink(matched_sink),
                path=path,
                evidence=stripped,
                severity=_severity_for_sink(matched_sink),
                line_number=line_number,
                parser_rule=_parser_rule(stripped, flow_nodes, declared_sink),
            ),
            None,
            False,
        )

    if flow_nodes or any(term in stripped.lower() for term in DEFAULT_SAFE_TERMS):
        return None, stripped, False

    return None, None, True


def parse_taint_log(log_path: Path, sinks: Sequence[str] = DEFAULT_SINKS) -> AnalysisResult:
    """Parse a taint-style log and return potential leak findings.

    Supported evidence formats include:
    - TAINTED source=secret path=secret -> printf
    - LEAK: source=secret sink=send path=secret -> network_send -> send
    - Leak detected: symbolic input secret reached send()
    - WARNING: tainted variable 'token' reached sink printf()
    - password -> sanitizer -> write
    """

    findings: list[Finding] = []
    safe_flows: list[str] = []
    ignored_lines = 0

    with log_path.open("r", encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            finding, safe_flow, ignored = parse_log_line(raw_line, line_number, sinks=sinks)
            if finding:
                findings.append(finding)
            elif safe_flow:
                safe_flows.append(safe_flow)
            elif ignored:
                ignored_lines += 1

    return AnalysisResult(str(log_path), findings, safe_flows, ignored_lines)


def write_markdown(result: AnalysisResult, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        handle.write("# LeakLens Analysis Report\n\n")
        handle.write(f"**Input log:** `{result.input_file}`\n\n")

        if result.findings:
            handle.write("## Potential Leaks Detected\n\n")
            for i, finding in enumerate(result.findings, start=1):
                line = f"line {finding.line_number}" if finding.line_number is not None else "unknown line"
                handle.write(f"### Finding {i}\n")
                handle.write(f"- Source: `{finding.source}`\n")
                handle.write(f"- Sink: `{finding.sink}()`\n")
                handle.write(f"- Severity: `{finding.severity}`\n")
                handle.write(f"- Path: `{' -> '.join(finding.path)}`\n")
                handle.write(f"- Evidence: `{finding.evidence}`\n")
                handle.write(f"- Location: `{line}`\n")
                handle.write(f"- Parser rule: `{finding.parser_rule}`\n\n")
        else:
            handle.write("## Result\n\nNo configured privacy sink was reached by a tainted flow in this log.\n\n")

        if result.safe_flows:
            handle.write("## Safe or Non-Leaking Flows Observed\n\n")
            for safe_flow in result.safe_flows:
                handle.write(f"- `{safe_flow}`\n")
            handle.write("\n")

        handle.write("## Parse Summary\n\n")
        handle.write(f"- Ignored non-evidence lines: `{result.ignored_lines}`\n\n")
        handle.write("## Notes\n\n")
        handle.write("This report is based on taint-style log evidence. It does not prove absence of leaks on paths that KLEE did not explore.\n")


def write_json(result: AnalysisResult, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(asdict(result), handle, indent=2)
        handle.write("\n")


def write_dot(result: AnalysisResult, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        handle.write("digraph LeakLens {\n")
        handle.write('  rankdir="LR";\n')
        if not result.findings:
            handle.write('  "no leak detected";\n')
        for finding in result.findings:
            for left, right in zip(finding.path, finding.path[1:]):
                handle.write(f'  "{left}" -> "{right}";\n')
        handle.write("}\n")


def parse_sinks(raw_sinks: str | None) -> tuple[str, ...]:
    if not raw_sinks:
        return DEFAULT_SINKS
    return tuple(s.strip() for s in raw_sinks.split(",") if s.strip())


def analyze_logs(log_paths: Iterable[Path], outdir: Path, sinks: Sequence[str]) -> list[AnalysisResult]:
    results: list[AnalysisResult] = []
    outdir.mkdir(parents=True, exist_ok=True)

    for log_path in log_paths:
        result = parse_taint_log(log_path, sinks=sinks)
        stem = log_path.stem
        write_markdown(result, outdir / f"{stem}_report.md")
        write_json(result, outdir / f"{stem}_report.json")
        write_dot(result, outdir / f"{stem}_flow.dot")
        results.append(result)

    return results


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Detect potential privacy leaks from taint-style KLEE/KLEE-taint logs.")
    parser.add_argument("--log", nargs="+", required=True, help="One or more taint-style log files to analyze.")
    parser.add_argument("--outdir", default="reports", help="Directory for generated Markdown/JSON/DOT reports.")
    parser.add_argument("--sinks", default=",".join(DEFAULT_SINKS), help="Comma-separated sink list. Default: printf,fprintf,send,write,log_data")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    sinks = parse_sinks(args.sinks)
    log_paths = [Path(path) for path in args.log]

    missing = [str(path) for path in log_paths if not path.exists()]
    if missing:
        parser.error(f"Log file(s) not found: {', '.join(missing)}")

    results = analyze_logs(log_paths, Path(args.outdir), sinks)
    finding_count = sum(len(result.findings) for result in results)
    print(f"Analyzed {len(results)} log file(s). Potential leaks found: {finding_count}.")
    print(f"Reports written to: {Path(args.outdir).resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
