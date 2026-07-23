import unittest

from src.vulnerability.release import database_health_report, source_coverage_report


class TestV16HealthCoverage(unittest.TestCase):
    def test_health_and_coverage_reports(self):
        health = database_health_report({"snapshot_id": "snap-1", "status": "active", "records": 10, "errors": [], "quality": {"invalid": 0}})
        self.assertTrue(health["healthy"])
        coverage = source_coverage_report({"OSV": {"records": 8, "advisories": 4}, "CSAF": {"records": 2, "advisories": 1}})
        self.assertEqual(coverage["total_records"], 10)
        self.assertEqual(coverage["sources"][0]["source_id"], "CSAF")
        self.assertEqual(coverage["source_count"], 2)
