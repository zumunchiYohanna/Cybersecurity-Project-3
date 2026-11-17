import unittest

from cyber_assessment.models import CookieAttributes, PortResult, WebResult
from cyber_assessment.risk import classify_port, classify_web


class RiskTests(unittest.TestCase):
    def test_open_port_is_informational(self):
        port = PortResult("a", 1, "127.0.0.1", 80, "open", "http", "well_known_port", 1.0, None)
        self.assertEqual(classify_port(port).severity, "informational")

    def test_likely_session_cookie_without_secure_is_medium(self):
        web = WebResult(
            "a", 2, "https", "localhost", "127.0.0.1", 443, 200, (),
            "verified", (), (CookieAttributes("sessionid", False, False, None),),
            ("127.0.0.1",), None,
        )
        severities = {finding.severity for finding in classify_web(web)}
        self.assertIn("medium", severities)
        self.assertIn("low", severities)

    def test_missing_frame_protection_is_low_not_high(self):
        web = WebResult(
            "a", 2, "http", "localhost", "127.0.0.1", 80, 200, (),
            "not_applicable", (), (), ("127.0.0.1",), None,
        )
        self.assertNotIn("high", {finding.severity for finding in classify_web(web)})


if __name__ == "__main__":
    unittest.main()
