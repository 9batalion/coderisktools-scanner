import tempfile
import unittest
from pathlib import Path

from src.vulnerability.benchmark import run_database_benchmark
from src.vulnerability.database import VulnerabilityDatabase


class TestV15DatabaseBenchmark(unittest.TestCase):
    def test_database_adapter_uses_real_evaluate_component(self):
        with tempfile.TemporaryDirectory() as directory:
            database = VulnerabilityDatabase(str(Path(directory) / "db.sqlite"))
            try:
                database.import_osv_records([{"id": "CVE-2026-99", "affected": [{"package": {"ecosystem": "PyPI", "name": "example"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}]}], source="fixture")
                cases = [
                    {"case_id": "affected", "ecosystem": "PyPI", "name": "example", "version": "1.0.0", "expected": True},
                    {"case_id": "clean", "ecosystem": "PyPI", "name": "other", "version": "1.0.0", "expected": False},
                ]
                report = run_database_benchmark(database, cases)
                self.assertEqual(report["metrics"]["true_positive"], 1)
                self.assertEqual(report["metrics"]["true_negative"], 1)
                self.assertEqual(report["summary"]["recall"], 1.0)
            finally:
                database.close()
