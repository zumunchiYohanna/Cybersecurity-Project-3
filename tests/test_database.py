import sqlite3
import tempfile
import unittest
from pathlib import Path

from cyber_assessment.database import AssessmentDatabase
from cyber_assessment.models import AssessmentScope, ModuleRunResult, PortResult, ResolvedAddress


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(prefix="cyber-assessment-test-", dir=Path(__file__).resolve().parents[1])
        self.addCleanup(self.temp_dir.cleanup)
        self.database = AssessmentDatabase(Path(self.temp_dir.name) / "test.sqlite3")
        self.database.initialize()
        self.scope = AssessmentScope(
            "127.0.0.1", "127.0.0.1", "ip",
            (ResolvedAddress(None, "127.0.0.1", 4, "loopback", "2026-01-01T00:00:00+00:00"),),
            (("127.0.0.1", ("127.0.0.1",)),),
            (8000,), frozenset({"tcp", "http", "https"}),
        )
        self.module_ids = self.database.create_assessment(
            self.scope, "assessment-db-test", "2026-01-01T00:00:00+00:00"
        )

    def test_foreign_keys_are_enabled_and_reject_wrong_ip_and_wrong_module(self):
        connection = self.database._connect()
        self.addCleanup(connection.close)
        self.assertEqual(connection.execute("PRAGMA foreign_keys").fetchone()[0], 1)
        tcp_id = self.module_ids["tcp_assessment"]
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                """INSERT INTO port_results
                (assessment_id, module_run_id, module_name, ip_address, port, state, observed_at)
                VALUES (?, ?, 'tcp_assessment', '192.0.2.1', 8000, 'open', ?)""",
                ("assessment-db-test", tcp_id, "2026-01-01T00:00:00+00:00"),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                """INSERT INTO port_results
                (assessment_id, module_run_id, module_name, ip_address, port, state, observed_at)
                VALUES (?, ?, 'tcp_assessment', '127.0.0.1', 8000, 'open', ?)""",
                ("assessment-db-test", self.module_ids["web_assessment"], "2026-01-01T00:00:00+00:00"),
            )

    def test_failed_web_module_preserves_successful_tcp_results(self):
        tcp_id = self.module_ids["tcp_assessment"]
        tcp = PortResult(
            "assessment-db-test", tcp_id, "127.0.0.1", 8000,
            "open", "http-alt", "well_known_port", 0.5, None,
        )
        self.database.complete_module(
            ModuleRunResult(
                module_name="tcp_assessment",
                status="succeeded",
                module_run_id=tcp_id,
                port_results=(tcp,),
            )
        )
        web_id = self.module_ids["web_assessment"]
        self.database.complete_module(
            ModuleRunResult(
                module_name="web_assessment",
                status="failed",
                module_run_id=web_id,
                error_code="tls_error",
                error_detail="Local TLS verification failed.",
            )
        )
        self.assertEqual(self.database.finalize_assessment("assessment-db-test"), "partial")
        result = self.database.get_assessment("assessment-db-test")
        self.assertEqual(len(result["port_results"]), 1)
        web_run = next(row for row in result["module_runs"] if row["module_name"] == "web_assessment")
        self.assertEqual(web_run["status"], "failed")
        self.assertEqual(web_run["error_code"], "tls_error")
        assessment = result["assessment"]
        self.assertEqual(assessment["status"], "partial")


if __name__ == "__main__":
    unittest.main()
