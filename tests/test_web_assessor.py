import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cyber_assessment.config import AppSettings
from cyber_assessment.models import AssessmentScope, ResolvedAddress, TargetRule
from cyber_assessment.web_assessor import assess_web


class _Handler(BaseHTTPRequestHandler):
    redirect_to_public = False
    redirect_location = "http://example.com/"
    seen_host = None

    def do_GET(self):
        type(self).seen_host = self.headers.get("Host")
        if type(self).redirect_to_public:
            self.send_response(302)
            self.send_header("Location", type(self).redirect_location)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
        self.send_header("Set-Cookie", "sessionid=secret-value; HttpOnly; SameSite=Lax")
        self.end_headers()
        self.wfile.write(b"<html><title>Local test</title></html>")

    def log_message(self, format, *args):
        return


class WebAssessorTests(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]
        self.settings = AppSettings(
            approved_ports=(self.port,),
            web_ports=(("http", (self.port,)), ("https", ())),
            connect_timeout_seconds=0.5,
            request_timeout_seconds=1,
            minimum_delay_seconds=0.1,
            max_redirects=2,
            user_agent="local-test",
        )
        self.rules = (
            TargetRule(
                "test-localhost", "localhost", ("127.0.0.1",),
                (self.port,), ("http", "https"),
            ),
        )
        self.scope = AssessmentScope(
            original_target="localhost",
            canonical_target="localhost",
            target_kind="hostname",
            approved_addresses=(
                ResolvedAddress("localhost", "127.0.0.1", 4, "test-localhost", "2026-01-01T00:00:00+00:00"),
            ),
            hostname_to_ips=(("localhost", ("127.0.0.1",)),),
            approved_ports=(self.port,),
            permitted_methods=frozenset({"http", "https"}),
        )

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        _Handler.redirect_to_public = False
        _Handler.redirect_location = "http://example.com/"
        _Handler.seen_host = None

    def test_http_headers_and_cookie_attributes_are_inspected_without_cookie_value(self):
        result = assess_web(self.scope, self.rules, self.settings, "assessment-test", 7)
        self.assertEqual(result.status, "succeeded")
        web = result.web_results[0]
        self.assertEqual(web.http_status, 200)
        self.assertIn(("x-content-type-options", "nosniff"), web.headers)
        self.assertEqual(web.cookies[0].name, "sessionid")
        self.assertTrue(web.cookies[0].httponly)
        self.assertNotIn("secret-value", repr(web))
        self.assertEqual(_Handler.seen_host, f"localhost:{self.port}")
        self.assertEqual(web.connected_ip, "127.0.0.1")

    def test_redirect_to_unapproved_host_is_not_followed(self):
        _Handler.redirect_to_public = True
        result = assess_web(self.scope, self.rules, self.settings, "assessment-test", 7)
        web = result.web_results[0]
        self.assertEqual(web.http_status, 302)
        self.assertEqual(web.error_code, "redirect_out_of_scope")
        self.assertEqual(result.status, "partial")

    def test_http_to_https_redirect_is_followed_but_tls_failure_is_not_bypassed(self):
        _Handler.redirect_to_public = True
        _Handler.redirect_location = f"https://127.0.0.1:{self.port}/"
        rules = self.rules + (
            TargetRule(
                "test-loopback-ip", "127.0.0.1", ("127.0.0.1",),
                (self.port,), ("http", "https"),
            ),
        )
        result = assess_web(self.scope, rules, self.settings, "assessment-test", 7)
        web = result.web_results[0]
        self.assertEqual(web.redirect_chain, (f"https://127.0.0.1:{self.port}",))
        self.assertEqual(web.error_code, "tls_error")
        self.assertEqual(web.tls_status, "failed")


if __name__ == "__main__":
    unittest.main()
