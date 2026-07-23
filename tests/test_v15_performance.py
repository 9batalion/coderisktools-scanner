import tempfile
import unittest
from pathlib import Path

from src.vulnerability.benchmark import run_database_benchmark_repeated
from src.vulnerability.database import VulnerabilityDatabase


class TestV15Performance(unittest.TestCase):
    def test_repeated_database_benchmark_reports_stability(self):
        with tempfile.TemporaryDirectory() as directory:
            database = VulnerabilityDatabase(str(Path(directory) / "db.sqlite"))
            try:
                database.import_osv_records([{"id": "CVE-2026-100", "affected": [{"package": {"ecosystem": "PyPI", "name": "example"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}]}], source="fixture")
                cases = [{"case_id": "affected", "ecosystem": "PyPI", "name": "example", "version": "1.0.0", "expected": True}]
                report = run_database_benchmark_repeated(database, cases, repetitions=3, max_p95_ms=1000.0)
                self.assertTrue(report["passed"])
                self.assertEqual(report["repetitions"], 3)
                self.assertEqual(len(report["runs"]), 3)
                self.assertIn("p95", report["latency_ms"])
            finally:
                database.close()
