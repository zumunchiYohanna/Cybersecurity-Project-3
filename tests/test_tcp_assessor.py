import socket
import unittest
from unittest.mock import patch

from cyber_assessment.config import AppSettings
from cyber_assessment.models import AssessmentScope, ResolvedAddress
from cyber_assessment.tcp_assessor import assess_tcp


class TCPAssessorTests(unittest.TestCase):
    def test_open_and_closed_ports_are_distinguished_on_loopback(self):
        real_socket = socket.socket
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        open_port = listener.getsockname()[1]
        closed_port = open_port + 1

        class RefusingSocket:
            def __enter__(self):
                return self

            def __exit__(self, _exception_type, _exception, _traceback):
                return False

            def settimeout(self, _timeout):
                return None

            def connect(self, _address):
                raise ConnectionRefusedError("simulated explicit refusal")

        scope = AssessmentScope(
            original_target="127.0.0.1",
            canonical_target="127.0.0.1",
            target_kind="ip",
            approved_addresses=(
                ResolvedAddress(None, "127.0.0.1", 4, "test-loopback", "2026-01-01T00:00:00+00:00"),
            ),
            hostname_to_ips=(("127.0.0.1", ("127.0.0.1",)),),
            approved_ports=(open_port, closed_port),
            permitted_methods=frozenset({"tcp"}),
        )
        settings = AppSettings(
            approved_ports=(open_port, closed_port),
            web_ports=(("http", (open_port,)), ("https", ())),
            connect_timeout_seconds=0.5,
            request_timeout_seconds=1,
            minimum_delay_seconds=0.1,
            max_redirects=1,
            user_agent="test",
        )
        try:
            calls = 0

            def create_socket(family, socket_type):
                nonlocal calls
                calls += 1
                return real_socket(family, socket_type) if calls == 1 else RefusingSocket()

            with patch("cyber_assessment.tcp_assessor.socket.socket", side_effect=create_socket):
                result = assess_tcp(scope, "assessment-test", 1, settings)
        finally:
            listener.close()
        states = {item.port: item.state for item in result.port_results}
        self.assertEqual(states[open_port], "open")
        self.assertEqual(states[closed_port], "closed")
        self.assertEqual({item.ip_address for item in result.port_results}, {"127.0.0.1"})


if __name__ == "__main__":
    unittest.main()
