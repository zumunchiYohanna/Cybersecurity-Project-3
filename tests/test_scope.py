import unittest
from unittest.mock import patch

from cyber_assessment.config import load_allowlist, load_settings
from cyber_assessment.errors import InvalidTargetError, ScopeDeniedError
from cyber_assessment.scope import match_target_rule, resolve_scope


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.settings = load_settings()
        self.rules = load_allowlist()

    def test_loopback_targets_are_allowlisted_and_resolve_to_loopback_only(self):
        with patch("cyber_assessment.scope._resolve_addresses", return_value=("127.0.0.1", "::1")):
            scope = resolve_scope("localhost", self.rules, self.settings.approved_ports)
        self.assertEqual(scope.canonical_target, "localhost")
        self.assertEqual(set(scope.approved_ips), {"127.0.0.1", "::1"})
        self.assertEqual(scope.ips_for_hostname("localhost"), scope.approved_ips)

    def test_malformed_and_non_allowlisted_targets_are_rejected(self):
        with self.assertRaises(InvalidTargetError):
            match_target_rule("http://localhost/path", self.rules, self.settings.approved_ports)
        with self.assertRaises(ScopeDeniedError):
            match_target_rule("192.0.2.10", self.rules, self.settings.approved_ports)

    def test_dns_answer_outside_loopback_is_rejected(self):
        with patch("cyber_assessment.scope._resolve_addresses", return_value=("127.0.0.1", "192.0.2.8")):
            with self.assertRaises(ScopeDeniedError):
                resolve_scope("localhost", self.rules, self.settings.approved_ports)

    def test_dns_answer_must_be_explicitly_approved(self):
        with patch("cyber_assessment.scope._resolve_addresses", return_value=("127.0.0.2",)):
            with self.assertRaises(ScopeDeniedError):
                resolve_scope("localhost", self.rules, self.settings.approved_ports)


if __name__ == "__main__":
    unittest.main()
