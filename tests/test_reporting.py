import json
import tempfile
import unittest
from pathlib import Path

from cyber_assessment.reporting import render_html, write_reports
from cyber_assessment.config import PROJECT_ROOT
from cyber_assessment.errors import AssessmentError


class ReportingTests(unittest.TestCase):
    def setUp(self):
        self.payload = {
            "assessment": {
                "assessment_id": "12345678-1234-1234-1234-123456789abc",
                "requested_target": '<script>alert("x")</script>',
                "status": "partial",
                "started_at": "2026-01-01T00:00:00+00:00",
                "finished_at": "2026-01-01T00:00:01+00:00",
                "scope_snapshot_json": "{}",
            },
            "scope": {"approved_ports": [8000]},
            "module_runs": [
                {"module_name": "tcp_assessment", "status": "succeeded"},
                {"module_name": "web_assessment", "status": "failed", "error_detail": "TLS error"},
            ],
            "resolved_addresses": [],
            "port_results": [],
            "web_results": [],
            "findings": [
                {
                    "severity": "low",
                    "title": '<img src=x onerror=alert(1)>',
                    "description": "Untrusted <tag>",
                    "confidence": "medium",
                    "recommendation": "Review & configure.",
                }
            ],
        }

    def test_html_context_escapes_untrusted_values(self):
        rendered = render_html(self.payload)
        self.assertNotIn('<script>alert("x")</script>', rendered)
        self.assertIn("&lt;script&gt;", rendered)
        self.assertIn("&lt;img", rendered)
        self.assertNotIn("<img src=x", rendered)

    def test_reports_are_written_with_json_serialization(self):
        with tempfile.TemporaryDirectory(prefix="report-test-", dir=PROJECT_ROOT) as directory:
            json_path, html_path = write_reports(self.payload, Path(directory))
            parsed = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(parsed["assessment"]["status"], "partial")
            self.assertTrue(html_path.read_text(encoding="utf-8").startswith("<!doctype html>"))

    def test_output_directory_outside_project_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(AssessmentError):
                write_reports(self.payload, Path(directory))


if __name__ == "__main__":
    unittest.main()
