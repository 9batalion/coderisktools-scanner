import tempfile
import unittest
from pathlib import Path

from src.vulnerability.database import VulnerabilityDatabase
from src.vulnerability.sources.csaf import ingest_file, ingest_file_to_database


class TestV14CsafRemediations(unittest.TestCase):
    def test_remediation_and_vendor_status_are_preserved(self):
        payload = '{"csaf_version":"2.0","document":{"category":"csaf_security_advisory","title":"Vendor advisory","tracking":{"id":"CSAF-2026-2"}},"product_tree":{"branches":[{"product":{"product_id":"pkg-1","product_identification_helper":{"purl":"pkg:pypi/example@1.0.0"}}}]},"vulnerabilities":[{"cve":"CVE-2026-12","product_status":{"known_affected":["pkg-1"],"vendor_specific":{"pkg-1":{"status":"under_investigation"}}},"remediations":[{"category":"vendor_fix","details":"Upgrade to 1.0.1","product_ids":["pkg-1"]}]}]}'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            feed = root / "csaf.json"
            feed.write_text(payload, encoding="utf-8")
            parsed = ingest_file(str(feed))
            advisory = parsed["advisories"][0]
            self.assertEqual(advisory["remediations"][0]["category"], "vendor_fix")
            self.assertEqual(advisory["vendor_status"]["pkg-1"]["status"], "under_investigation")
            database = VulnerabilityDatabase(str(root / "db.sqlite"))
            try:
                report = ingest_file_to_database(str(feed), database, "csaf-2")
                self.assertEqual(report["state"], "staged")
            finally:
                database.close()
