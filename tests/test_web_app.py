import importlib
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from cyber_assessment import cli
from cyber_assessment.config import PROJECT_ROOT
from cyber_assessment.database import AssessmentDatabase
from cyber_assessment.errors import PersistenceError
from cyber_assessment.models import ModuleRunResult, PortResult, WebResult
from cyber_assessment.web import create_app
from cyber_assessment.web.__main__ import WEB_HOST, WEB_PORT, main


class WebAppTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(
            prefix="cyber-assessment-web-test-",
            dir=PROJECT_ROOT,
        )
        self.addCleanup(self.temp_dir.cleanup)
        self.work_dir = Path(self.temp_dir.name)
        self.database = AssessmentDatabase(self.work_dir / "test.sqlite3")
        self.runner = Mock()
        self.app = create_app(
            {"TESTING": True, "REPORTS_DIR": self.work_dir / "reports"},
            database=self.database,
            assessment_runner=self.runner,
        )
        self.client = self.app.test_client()

    def csrf_token(self):
        with self.client.session_transaction() as browser_session:
            return browser_session["_csrf_token"]

    def post_data(self, **values):
        return {"csrf_token": self.csrf_token(), **values}

    def preview_local_target(self):
        self.client.get("/assessments/new")
        return self.client.post(
            "/assessments/preview",
            data=self.post_data(target="127.0.0.1", method_mode="all"),
        )

    def pending_token_from(self, response):
        match = re.search(
            r'action="/assessments/([A-Za-z0-9_-]+)/confirm"',
            response.get_data(as_text=True),
        )
        self.assertIsNotNone(match)
        return match.group(1)

    def test_dashboard_and_form_load_without_starting_assessment(self):
        dashboard = self.client.get("/")
        self.assertEqual(dashboard.status_code, 200)
        self.assertIn(b"Security overview", dashboard.data)
        self.assertIn(b"0", dashboard.data)

        form = self.client.get("/assessments/new")
        self.assertEqual(form.status_code, 200)
        self.assertIn(b"localhost", form.data)
        self.assertIn(b"80, 443, 8000, 8080", form.data)
        self.runner.assert_not_called()
        self.assertEqual(self.database.get_dashboard_summary()["total_assessments"], 0)

    def test_hosted_demo_uses_synthetic_data_without_database_or_report_access(self):
        private_marker = "SYNTHETIC_REPORT_SENTINEL_FOR_TEST"
        reports_dir = self.work_dir / "private-reports"
        reports_dir.mkdir()
        (reports_dir / "assessment-00000000-0000-4000-8000-000000000001.json").write_text(
            private_marker,
            encoding="utf-8",
        )
        unused_database = Mock()
        unused_runner = Mock()
        app = create_app(
            {
                "TESTING": True,
                "HOSTED_DEMO": True,
                "SECRET_KEY": "test-hosted-demo-secret",
                "REPORTS_DIR": reports_dir,
            },
            database=unused_database,
            assessment_runner=unused_runner,
        )
        client = app.test_client()
        public_base = "https://cyber-assessment-demo.onrender.com"
        public_address = {"REMOTE_ADDR": "203.0.113.10"}

        health = client.get("/healthz", base_url=public_base, environ_base=public_address)
        self.assertEqual(health.status_code, 200)
        self.assertEqual(health.json, {"mode": "demo", "status": "ok"})

        dashboard = client.get("/", base_url=public_base, environ_base=public_address)
        self.assertEqual(dashboard.status_code, 200)
        self.assertIn(b"PUBLIC DEMO", dashboard.data)
        self.assertIn(b"SAMPLE DATA", dashboard.data)
        self.assertIn(b"demo.local", dashboard.data)
        self.assertNotIn(private_marker.encode(), dashboard.data)

        assessment_form = client.get(
            "/assessments/new",
            base_url=public_base,
            environ_base=public_address,
        )
        self.assertEqual(assessment_form.status_code, 200)
        self.assertIn(b"Assessments are disabled", assessment_form.data)
        self.assertNotIn(b"<form", assessment_form.data)

        history = client.get("/history", base_url=public_base, environ_base=public_address)
        findings = client.get("/findings", base_url=public_base, environ_base=public_address)
        sample_result = client.get(
            "/assessments/00000000-0000-4000-8000-000000000001",
            base_url=public_base,
            environ_base=public_address,
        )
        self.assertEqual(history.status_code, 200)
        self.assertEqual(findings.status_code, 200)
        self.assertEqual(sample_result.status_code, 200)
        for response in (history, findings, sample_result):
            self.assertIn(b"PUBLIC DEMO", response.data)
            self.assertNotIn(private_marker.encode(), response.data)

        reports = client.get("/reports", base_url=public_base, environ_base=public_address)
        self.assertEqual(reports.status_code, 200)
        self.assertIn(b"Reports are unavailable in demo mode", reports.data)
        self.assertNotIn(private_marker.encode(), reports.data)
        self.assertNotIn("REPORTS_DIR", app.config)

        report_id = "00000000-0000-4000-8000-000000000001"
        for path in (
            f"/reports/{report_id}/view",
            f"/reports/{report_id}/view/json",
            f"/reports/{report_id}/view/html",
            f"/reports/{report_id}/download/json",
            f"/reports/{report_id}/download/html",
        ):
            response = client.get(path, base_url=public_base, environ_base=public_address)
            self.assertEqual(response.status_code, 404, path)
            self.assertNotIn(private_marker.encode(), response.data)

        for path in (
            "/assessments/preview",
            f"/assessments/{report_id}/confirm",
            f"/assessments/{report_id}/cancel",
        ):
            response = client.post(path, base_url=public_base, environ_base=public_address)
            self.assertEqual(response.status_code, 404, path)

        unused_database.initialize.assert_not_called()
        unused_runner.assert_not_called()
        self.assertNotIn("cyber_assessment.database", app.extensions)
        self.assertNotIn("cyber_assessment.assessment_runner", app.extensions)
        self.assertTrue(app.config["SESSION_COOKIE_SECURE"])

    def test_hosted_demo_requires_a_session_secret(self):
        with self.assertRaisesRegex(RuntimeError, "session secret"):
            create_app(
                {
                    "TESTING": True,
                    "HOSTED_DEMO": True,
                    "SECRET_KEY": "",
                }
            )

    def test_public_wsgi_entry_point_refuses_local_mode(self):
        module_name = "cyber_assessment.web.wsgi"
        with patch.dict(os.environ, {"CYBER_ASSESSMENT_HOSTED_DEMO": "0"}):
            with self.assertRaisesRegex(RuntimeError, "requires hosted demo mode"):
                importlib.import_module(module_name)
        self.assertNotIn(module_name, sys.modules)

    def test_unapproved_target_is_rejected_before_scope_resolution(self):
        self.client.get("/assessments/new")
        with patch("cyber_assessment.web.resolve_scope") as resolve_scope:
            response = self.client.post(
                "/assessments/preview",
                data=self.post_data(target="192.0.2.10", method_mode="all"),
            )
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"not present in the project-local allowlist", response.data)
        resolve_scope.assert_not_called()
        self.runner.assert_not_called()

    def test_confirmation_cancel_does_not_run_assessment(self):
        preview = self.preview_local_target()
        self.assertEqual(preview.status_code, 200)
        self.assertIn(b"Resolved and approved IP addresses", preview.data)
        self.assertIn(b"127.0.0.1", preview.data)
        self.runner.assert_not_called()

        pending_token = self.pending_token_from(preview)
        response = self.client.post(
            f"/assessments/{pending_token}/cancel",
            data=self.post_data(),
        )
        self.assertEqual(response.status_code, 302)
        self.runner.assert_not_called()
        self.assertEqual(self.database.get_dashboard_summary()["total_assessments"], 0)

    def test_confirmation_requires_both_acknowledgement_and_typed_yes(self):
        preview = self.preview_local_target()
        pending_token = self.pending_token_from(preview)
        response = self.client.post(
            f"/assessments/{pending_token}/confirm",
            data=self.post_data(acknowledged="yes", confirmation="no"),
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"Tick the authorization acknowledgement", response.data)
        self.runner.assert_not_called()
        self.assertEqual(self.database.get_dashboard_summary()["total_assessments"], 0)

    def test_confirmed_request_uses_existing_workflow_and_renders_results_reports(self):
        def fake_tcp(scope, assessment_id, module_run_id, _settings):
            return ModuleRunResult(
                module_name="tcp_assessment",
                status="succeeded",
                module_run_id=module_run_id,
                port_results=(
                    PortResult(
                        assessment_id,
                        module_run_id,
                        scope.approved_ips[0],
                        8000,
                        "open",
                        "http-alt",
                        "well_known_port",
                        0.5,
                        None,
                    ),
                ),
            )

        def fake_web(scope, _rules, _settings, assessment_id, module_run_id):
            return ModuleRunResult(
                module_name="web_assessment",
                status="succeeded",
                module_run_id=module_run_id,
                web_results=(
                    WebResult(
                        assessment_id=assessment_id,
                        module_run_id=module_run_id,
                        requested_scheme="http",
                        requested_host=scope.canonical_target,
                        connected_ip=scope.approved_ips[0],
                        port=8000,
                        http_status=200,
                        redirect_chain=(),
                        tls_status="not_applicable",
                        headers=(("x-content-type-options", "nosniff"),),
                        cookies=(),
                        approved_hop_ips=scope.approved_ips,
                        error_code=None,
                    ),
                ),
            )

        app = create_app(
            {"TESTING": True, "REPORTS_DIR": self.work_dir / "workflow-reports"},
            database=self.database,
        )
        client = app.test_client()
        client.get("/assessments/new")
        preview = client.post(
            "/assessments/preview",
            data={"csrf_token": self._csrf_for(client), "target": "127.0.0.1", "method_mode": "all"},
        )
        pending_token = self.pending_token_from(preview)

        with (
            patch("cyber_assessment.cli.AssessmentDatabase", return_value=self.database),
            patch("cyber_assessment.cli.assess_tcp", side_effect=fake_tcp) as tcp_assessor,
            patch("cyber_assessment.cli.assess_web", side_effect=fake_web) as web_assessor,
        ):
            response = client.post(
                f"/assessments/{pending_token}/confirm",
                data={
                    "csrf_token": self._csrf_for(client),
                    "acknowledged": "yes",
                    "confirmation": "yes",
                },
            )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(tcp_assessor.call_count, 1)
        self.assertEqual(web_assessor.call_count, 1)
        assessment_id = response.headers["Location"].rsplit("/", 1)[-1]
        result = client.get(response.headers["Location"])
        self.assertEqual(result.status_code, 200)
        self.assertIn(b"Assessment results", result.data)
        self.assertIn(b"TCP port 8000 is open", result.data)

        finding_items = self.database.list_findings()
        self.assertTrue(finding_items)
        findings_page = client.get("/findings?severity=informational")
        self.assertEqual(findings_page.status_code, 200)
        self.assertIn(b"TCP port 8000 is open", findings_page.data)
        history_page = client.get("/history")
        self.assertIn(assessment_id.encode(), history_page.data)

        json_path = self.work_dir / "workflow-reports" / f"assessment-{assessment_id}.json"
        html_path = self.work_dir / "workflow-reports" / f"assessment-{assessment_id}.html"
        self.assertTrue(json_path.is_file())
        self.assertTrue(html_path.is_file())
        self.assertEqual(json.loads(json_path.read_text(encoding="utf-8"))["assessment"]["status"], "completed")

        reports_page = client.get("/reports")
        self.assertEqual(reports_page.status_code, 200)
        self.assertIn(assessment_id.encode(), reports_page.data)
        report_preview = client.get(f"/reports/{assessment_id}/view")
        self.assertEqual(report_preview.status_code, 200)
        self.assertIn(b'sandbox=""', report_preview.data)
        html_report = client.get(f"/reports/{assessment_id}/view/html")
        self.addCleanup(html_report.close)
        self.assertEqual(html_report.status_code, 200)
        self.assertIn("sandbox", html_report.headers["Content-Security-Policy"])
        json_report = client.get(f"/reports/{assessment_id}/view/json")
        self.assertEqual(json_report.status_code, 200)
        self.assertIn(b"schema_version", json_report.data)
        self.assertIn(b"1.0", json_report.data)
        download = client.get(f"/reports/{assessment_id}/download/json")
        self.addCleanup(download.close)
        self.assertEqual(download.status_code, 200)
        self.assertIn("attachment", download.headers["Content-Disposition"])

    @staticmethod
    def _csrf_for(client):
        with client.session_transaction() as browser_session:
            return browser_session["_csrf_token"]

    def test_database_errors_are_reported_without_exposing_details(self):
        class FailingDatabase(AssessmentDatabase):
            def get_dashboard_summary(self):
                raise PersistenceError("sensitive database path must not appear")

        broken_database = FailingDatabase(self.work_dir / "broken.sqlite3")
        app = create_app(
            {"TESTING": True, "REPORTS_DIR": self.work_dir / "broken-reports"},
            database=broken_database,
        )
        response = app.test_client().get("/")
        self.assertEqual(response.status_code, 503)
        self.assertIn(b"Assessment data unavailable", response.data)
        self.assertNotIn(b"sensitive database path", response.data)

    def test_loopback_access_headers_and_csrf_are_enforced(self):
        remote_client = self.app.test_client()
        response = remote_client.get(
            "/",
            environ_base={"REMOTE_ADDR": "192.0.2.10"},
        )
        self.assertEqual(response.status_code, 403)

        untrusted_client = self.app.test_client()
        untrusted_host = untrusted_client.get("/", base_url="http://example.test")
        self.assertEqual(untrusted_host.status_code, 400)

        local_response = self.client.get("/assessments/new")
        self.assertEqual(local_response.status_code, 200)
        self.assertIn("default-src 'self'", local_response.headers["Content-Security-Policy"])
        self.assertEqual(local_response.headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("HttpOnly", local_response.headers["Set-Cookie"])
        self.assertIn("SameSite=Strict", local_response.headers["Set-Cookie"])

        missing_token = self.client.post(
            "/assessments/preview",
            data={"target": "127.0.0.1", "method_mode": "all"},
        )
        self.assertEqual(missing_token.status_code, 400)
        self.runner.assert_not_called()

    def test_findings_page_context_escapes_untrusted_stored_text(self):
        self.database.list_findings = Mock(
            return_value=[
                {
                    "assessment_id": "12345678-1234-1234-1234-123456789abc",
                    "requested_target": '<script>alert("target")</script>',
                    "severity": "low",
                    "category": "header",
                    "confidence": "medium",
                    "title": '<img src=x onerror=alert(1)>',
                    "description": "Untrusted <tag>",
                    "recommendation": "Review & configure.",
                    "created_at": "2026-01-01T00:00:00+00:00",
                    "evidence": {"detail": "<script>"},
                }
            ]
        )
        response = self.client.get("/findings")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b'<script>alert("target")</script>', response.data)
        self.assertNotIn(b"<img src=x", response.data)
        self.assertIn(b"&lt;script&gt;", response.data)

    def test_reports_reject_arbitrary_paths_and_server_binds_loopback(self):
        self.assertEqual(self.client.get("/reports/not-an-id/download/json").status_code, 404)
        self.assertEqual(WEB_HOST, "127.0.0.1")
        self.assertEqual(WEB_PORT, 5000)
        server = Mock()
        with patch("cyber_assessment.web.__main__.create_app", return_value=server):
            main()
        server.run.assert_called_once_with(
            host="127.0.0.1",
            port=5000,
            debug=False,
            use_reloader=False,
            threaded=True,
        )


if __name__ == "__main__":
    unittest.main()
