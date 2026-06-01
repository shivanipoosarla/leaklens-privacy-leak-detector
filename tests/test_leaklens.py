from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from leaklens import parse_log_line, parse_taint_log


class LeakLensParserTests(unittest.TestCase):
    def test_direct_leak_detected(self):
        result = parse_taint_log(ROOT / "sample-output" / "direct_leak.info")
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].source, "input")
        self.assertEqual(result.findings[0].sink, "printf")
        self.assertEqual(result.findings[0].path, ["input", "printf"])
        self.assertEqual(result.findings[0].parser_rule, "explicit-path")

    def test_network_leak_high_severity(self):
        result = parse_taint_log(ROOT / "sample-output" / "network_leak.info")
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].source, "sensitive")
        self.assertEqual(result.findings[0].sink, "send")
        self.assertEqual(result.findings[0].severity, "high")
        self.assertEqual(result.findings[0].path, ["sensitive", "network_send", "send"])

    def test_log_leak_detected(self):
        result = parse_taint_log(ROOT / "sample-output" / "log_leak.info")
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].source, "secret")
        self.assertEqual(result.findings[0].sink, "fprintf")
        self.assertEqual(result.findings[0].path, ["secret", "log_data", "fprintf"])

    def test_benign_has_no_findings(self):
        result = parse_taint_log(ROOT / "sample-output" / "benign.info")
        self.assertEqual(result.findings, [])
        self.assertTrue(result.safe_flows)

    def test_natural_language_reached_sink_format(self):
        finding, safe_flow, ignored = parse_log_line("Leak detected: symbolic input password reached send()", 1)
        self.assertIsNone(safe_flow)
        self.assertFalse(ignored)
        self.assertIsNotNone(finding)
        self.assertEqual(finding.source, "password")
        self.assertEqual(finding.sink, "send")
        self.assertEqual(finding.path, ["password", "send"])
        self.assertEqual(finding.parser_rule, "declared-sink")

    def test_quoted_tainted_variable_format(self):
        finding, safe_flow, ignored = parse_log_line("WARNING: tainted variable 'token' reached sink printf()", 7)
        self.assertIsNotNone(finding)
        self.assertEqual(finding.source, "token")
        self.assertEqual(finding.sink, "printf")
        self.assertEqual(finding.line_number, 7)

    def test_explicit_sink_and_path_format(self):
        finding, _, _ = parse_log_line("LEAK: source=api_key sink=write path=api_key -> serializer -> write", 3)
        self.assertIsNotNone(finding)
        self.assertEqual(finding.source, "api_key")
        self.assertEqual(finding.sink, "write")
        self.assertEqual(finding.severity, "high")
        self.assertEqual(finding.path, ["api_key", "serializer", "write"])

    def test_realistic_formats_file(self):
        result = parse_taint_log(ROOT / "sample-output" / "realistic_formats.info")
        self.assertEqual(len(result.findings), 4)
        self.assertEqual(result.findings[0].source, "token")
        self.assertEqual(result.findings[1].source, "password")
        self.assertEqual(result.findings[2].path, ["api_key", "serializer", "write"])
        self.assertEqual(result.findings[3].path, ["session_id", "audit_log", "fprintf"])
        self.assertTrue(any("strlen" in flow for flow in result.safe_flows))
        self.assertEqual(result.ignored_lines, 2)

    def test_custom_sink_filter_ignores_unconfigured_sink(self):
        finding, safe_flow, ignored = parse_log_line("TAINTED source=secret path=secret -> fprintf", 1, sinks=("printf",))
        self.assertIsNone(finding)
        self.assertIsNotNone(safe_flow)
        self.assertFalse(ignored)


if __name__ == "__main__":
    unittest.main()
