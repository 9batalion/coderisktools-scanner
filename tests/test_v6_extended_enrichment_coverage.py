import unittest

from src.vulnerability.database import VulnerabilityDatabase


class TestV6ExtendedEnrichmentCoverage(unittest.TestCase):
    def test_extended_report_tracks_epss_and_vulnrichment_without_changing_legacy_api(self):
        database = VulnerabilityDatabase()
        database.import_osv_records([{"id": "OSV-V6-COVERAGE", "aliases": ["CVE-2026-6001"], "affected": []}])
        database.connection.execute(
            "INSERT INTO epss_scores(cve_id, advisory_id, source, content_digest, score, percentile, score_date, record_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("CVE-2026-6001", "OSV-V6-COVERAGE", "epss", "sha256:epss", 0.5, 0.8, "2026-01-01", "{}"),
        )
        database.connection.execute(
            "INSERT INTO vulnrichment_records(cve_id, advisory_id, source, content_digest, enrichment_json) VALUES (?, ?, ?, ?, ?)",
            ("CVE-2026-6001", "OSV-V6-COVERAGE", "vulnrichment", "sha256:ve", "{}"),
        )
        database.connection.commit()
        report = database.extended_enrichment_coverage_report("CVE-2026-6001", requested_sources=("epss", "vulnrichment"))
        self.assertEqual(report["sources"]["epss"]["status"], "available")
        self.assertEqual(report["sources"]["vulnrichment"]["status"], "available")
        self.assertEqual(report["sources"]["nvd"]["status"], "not_requested")
        self.assertEqual(report["counts"], {"available": 2, "unavailable": 0, "not_requested": 2})

    def test_extended_report_rejects_unknown_source(self):
        with self.assertRaises(ValueError):
            VulnerabilityDatabase().extended_enrichment_coverage_report("CVE-2026-6001", requested_sources=("cisa",))


if __name__ == "__main__":
    unittest.main()
