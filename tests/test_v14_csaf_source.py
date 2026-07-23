import tempfile
import unittest
from pathlib import Path

from src.vulnerability.database import VulnerabilityDatabase
from src.vulnerability.models import Component
from src.vulnerability.sources.csaf import CSAF_SOURCE_ID, ingest_file, ingest_file_to_database


class TestV14CsafSource(unittest.TestCase):
    def test_generic_csaf_product_tree_and_status_staging(self):
        payload = '{"csaf_version":"2.0","document":{"category":"csaf_security_advisory","title":"Example advisory","tracking":{"id":"CSAF-2026-1","current_release_date":"2026-01-01T00:00:00Z"}},"product_tree":{"branches":[{"name":"product","product":{"product_id":"pkg-1","product_identification_helper":{"purl":"pkg:pypi/example@1.0.0"}}}]},"vulnerabilities":[{"cve":"CVE-2026-11","product_status":{"known_affected":["pkg-1"]},"notes":[{"category":"description","text":"Example"}]}]}'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            feed = root / "csaf.json"
            feed.write_text(payload, encoding="utf-8")
            parsed = ingest_file(str(feed))
            self.assertEqual(parsed["source_id"], CSAF_SOURCE_ID)
            self.assertEqual(parsed["advisory_count"], 1)
            database = VulnerabilityDatabase(str(root / "db.sqlite"))
            try:
                report = ingest_file_to_database(str(feed), database, "csaf-1")
                self.assertEqual(report["state"], "staged")
                result = database.evaluate_component(Component(ecosystem="PyPI", name="example", version="1.0.0"))
                self.assertEqual(result["status"], "affected")
            finally:
                database.close()
