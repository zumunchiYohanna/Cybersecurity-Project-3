import io
import socket
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from cyber_assessment import cli
from cyber_assessment.errors import ResolutionError


class CLITests(unittest.TestCase):
    def test_confirmed_summary_precedes_prompt_and_reuses_validated_scope(self):
        output = io.StringIO()
        events = []
        approved_ips = ("127.0.0.1", "::1")

        def resolve_addresses(host):
            events.append(("resolve", host))
            return approved_ips

        def confirm(prompt):
            events.append(("confirm", prompt))
            summary = output.getvalue()
            self.assertIn("Original target: LOCALhost", summary)
            self.assertIn("Canonical target: localhost", summary)
            self.assertIn("Resolved IP addresses: 127.0.0.1, ::1", summary)
            self.assertIn("Assessment methods: tcp", summary)
            self.assertIn("Approved ports: 80, 443, 8000, 8080", summary)
            self.assertIn("loopback addresses only", summary)
            return "yes"

        with (
            patch("cyber_assessment.scope._resolve_addresses", side_effect=resolve_addresses) as resolver,
            patch("builtins.input", side_effect=confirm),
            patch(
                "cyber_assessment.cli._assess",
                return_value=("completed", Path("unused.json"), Path("unused.html")),
            ) as assess,
            patch("cyber_assessment.cli.assess_tcp") as tcp_assessor,
            patch("cyber_assessment.cli.assess_web") as web_assessor,
            redirect_stdout(output),
        ):
            result = cli.main(["LOCALhost", "--tcp-only"])

        self.assertEqual(result, 0)
        self.assertEqual(events[0], ("resolve", "localhost"))
        self.assertEqual(events[1][0], "confirm")
        resolver.assert_called_once_with("localhost")
        self.assertEqual(len(events), 2)
        scope = assess.call_args.args[0]
        self.assertEqual(scope.original_target, "LOCALhost")
        self.assertEqual(scope.canonical_target, "localhost")
        self.assertEqual(scope.approved_ips, approved_ips)
        tcp_assessor.assert_not_called()
        web_assessor.assert_not_called()

    def test_declined_confirmation_never_starts_assessment(self):
        with (
            patch(
                "cyber_assessment.scope._resolve_addresses",
                return_value=("127.0.0.1", "::1"),
            ),
            patch("builtins.input", return_value="no"),
            patch("cyber_assessment.cli._assess") as assess,
            patch("cyber_assessment.cli.assess_tcp") as tcp_assessor,
            patch("cyber_assessment.cli.assess_web") as web_assessor,
            redirect_stdout(io.StringIO()),
        ):
            result = cli.main(["localhost", "--tcp-only"])

        self.assertEqual(result, 1)
        assess.assert_not_called()
        tcp_assessor.assert_not_called()
        web_assessor.assert_not_called()

    def test_resolution_errors_and_empty_answers_stop_before_prompt(self):
        failures = (
            ResolutionError("test DNS failure"),
            socket.timeout("test DNS timeout"),
            (),
        )
        for failure in failures:
            with self.subTest(failure=failure):
                if isinstance(failure, BaseException):
                    resolution_patch = patch(
                        "cyber_assessment.scope._resolve_addresses",
                        side_effect=failure,
                    )
                else:
                    resolution_patch = patch(
                        "cyber_assessment.scope.socket.getaddrinfo",
                        return_value=[],
                    )
                with (
                    resolution_patch,
                    patch("builtins.input") as prompt,
                    patch("cyber_assessment.cli._assess") as assess,
                    patch("cyber_assessment.cli.assess_tcp") as tcp_assessor,
                    patch("cyber_assessment.cli.assess_web") as web_assessor,
                    redirect_stdout(io.StringIO()),
                    redirect_stderr(io.StringIO()),
                ):
                    result = cli.main(["localhost", "--tcp-only"])

                self.assertEqual(result, 2)
                prompt.assert_not_called()
                assess.assert_not_called()
                tcp_assessor.assert_not_called()
                web_assessor.assert_not_called()

    def test_disallowed_dns_answer_stops_before_prompt_without_filtering(self):
        with (
            patch(
                "cyber_assessment.scope._resolve_addresses",
                return_value=("127.0.0.1", "192.0.2.8"),
            ) as resolver,
            patch("builtins.input") as prompt,
            patch("cyber_assessment.cli._assess") as assess,
            patch("cyber_assessment.cli.assess_tcp") as tcp_assessor,
            patch("cyber_assessment.cli.assess_web") as web_assessor,
            redirect_stdout(io.StringIO()),
            redirect_stderr(io.StringIO()),
        ):
            result = cli.main(["localhost", "--tcp-only"])

        self.assertEqual(result, 2)
        resolver.assert_called_once_with("localhost")
        prompt.assert_not_called()
        assess.assert_not_called()
        tcp_assessor.assert_not_called()
        web_assessor.assert_not_called()


if __name__ == "__main__":
    unittest.main()
