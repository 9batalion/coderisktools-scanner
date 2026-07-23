import tempfile
import unittest
from pathlib import Path

from src.vulnerability.benchmark import build_final_benchmark_report
from src.vulnerability.database import VulnerabilityDatabase


class TestV15FinalReport(unittest.TestCase):
    def test_final_report_combines_quality_performance_and_ecosystems(self):
        with tempfile.TemporaryDirectory() as directory:
            database = VulnerabilityDatabase(str(Path(directory) / "db.sqlite"))
            try:
                database.import_osv_records([{"id": "CVE-2026-101", "affected": [{"package": {"ecosystem": "PyPI", "name": "example"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}]}], source="fixture")
                report = build_final_benchmark_report(database, {"PyPI": [{"case_id": "affected", "ecosystem": "PyPI", "name": "example", "version": "1.0.0", "expected": True}, {"case_id": "clean", "ecosystem": "PyPI", "name": "other", "version": "1.0.0", "expected": False}]})
                self.assertTrue(report["passed"])
                self.assertEqual(report["ecosystems"], ["PyPI"])
                self.assertEqual(report["summary"]["recall"], 1.0)
                self.assertIn("performance", report)
            finally:
                database.close()
