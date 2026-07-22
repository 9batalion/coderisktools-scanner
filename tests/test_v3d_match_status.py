"""RED tests for the additive V3 match status contract."""

import unittest

from src.vulnerability.database import VulnerabilityDatabase
from src.vulnerability.models import Component


RECORD = {
    "schema_version": "1.4.0",
    "id": "OSV-2025-STATUS",
    "aliases": ["CVE-2025-3333"],
    "affected": [{
        "package": {"ecosystem": "PyPI", "name": "demo"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}],
    }],
}


class TestV3MatchStatus(unittest.TestCase):
    def test_missing_version_is_indeterminate(self):
        database = VulnerabilityDatabase(":memory:")
        evaluation = database.evaluate_component(Component("pypi", "demo"))
        self.assertEqual(evaluation["status"], "indeterminate")
        self.assertEqual(evaluation["confidence"], "indeterminate")
        self.assertEqual(evaluation["method"], "unresolved-range")
        self.assertEqual(evaluation["matches"], [])

    def test_known_exact_version_without_advisory_is_not_affected(self):
        database = VulnerabilityDatabase(":memory:")
        evaluation = database.evaluate_component(Component("pypi", "demo", "3.0.0", purl="pkg:pypi/demo@3.0.0"))
        self.assertEqual(evaluation["status"], "not_affected")
        self.assertEqual(evaluation["confidence"], "high")
        self.assertEqual(evaluation["method"], "exact-package-version")

    def test_affected_version_keeps_match_explanations(self):
        database = VulnerabilityDatabase(":memory:")
        database.import_osv_records([RECORD])
        evaluation = database.evaluate_component(Component("pypi", "demo", "1.0.0", purl="pkg:pypi/demo@1.0.0"))
        self.assertEqual(evaluation["status"], "affected")
        self.assertEqual(evaluation["confidence"], "high")
        self.assertEqual(evaluation["method"], "ecosystem-range")
        self.assertEqual(len(evaluation["matches"]), 1)
        self.assertIn("OSV-2025-STATUS", evaluation["matches"][0]["advisory_id"])


if __name__ == "__main__":
    unittest.main()
