import tempfile
import unittest
from pathlib import Path

from src.vulnerability.benchmark import run_database_memory_benchmark
from src.vulnerability.database import VulnerabilityDatabase


class TestV15Memory(unittest.TestCase):
    def test_memory_benchmark_reports_peak_and_acceptance(self):
        with tempfile.TemporaryDirectory() as directory:
            database = VulnerabilityDatabase(str(Path(directory) / "db.sqlite"))
            try:
                database.import_osv_records([{"id": "CVE-2026-MEM", "affected": [{"package": {"ecosystem": "PyPI", "name": "memory-example"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}]}], source="fixture")
                cases = [{"case_id": "affected", "ecosystem": "PyPI", "name": "memory-example", "version": "1.0.0", "expected": True}]
                report = run_database_memory_benchmark(database, cases, repetitions=2, max_peak_kib=1024 * 1024)
                self.assertTrue(report["passed"])
                self.assertEqual(report["repetitions"], 2)
                self.assertGreaterEqual(report["peak_kib"], 0.0)
            finally:
                database.close()
