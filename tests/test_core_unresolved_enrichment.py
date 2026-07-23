import tempfile
import unittest

from src.vulnerability.database import VulnerabilityDatabase


class TestCoreUnresolvedEnrichment(unittest.TestCase):
    def test_kev_can_be_staged_without_matching_advisory_in_core_mode(self):
        record = {
            "cveID": "CVE-2026-9999",
            "vendorProject": "Example",
            "product": "Example Product",
            "vulnerabilityName": "Example vulnerability",
            "dateAdded": "2026-07-23",
            "shortDescription": "Example",
            "requiredAction": "Apply update",
            "dueDate": "2026-08-23",
            "knownRansomwareCampaignUse": "Unknown",
        }
        with tempfile.TemporaryDirectory() as directory:
            with VulnerabilityDatabase(f"{directory}/core.sqlite3") as database:
                stats = database.import_kev_json([record], allow_unresolved=True)
                self.assertEqual(stats.records_seen, 1)
                self.assertEqual(stats.errors, ())
                row = database.connection.execute(
                    "SELECT source, cve_id, reason FROM unresolved_enrichments"
                ).fetchone()
                self.assertEqual(tuple(row), ("kev", "CVE-2026-9999", "advisory-not-found"))
