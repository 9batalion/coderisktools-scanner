import json
import tempfile
import unittest
from pathlib import Path

from src.vulnerability.database import VulnerabilityDatabase
from src.vulnerability.sources.osv import OSV_SOURCE_ID, ingest_file


class TestOSVSourceAdapter(unittest.TestCase):
    def test_public_adapter_ingests_local_feed_without_changing_report_contract(self):
        record = {
            "id": "OSV-P1-SOURCE-1",
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "demo"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
                }
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            feed = root / "osv.json"
            feed.write_text(json.dumps({"vulns": [record]}), encoding="utf-8")
            database = VulnerabilityDatabase(str(root / "vuln.sqlite"))
            try:
                report = ingest_file(str(feed), database, "p1-osv", source_id=OSV_SOURCE_ID)
            finally:
                database.close()

        self.assertEqual(report.source_id, "osv")
        self.assertEqual(report.state, "staged")
        self.assertEqual(report.records_seen, 1)
        self.assertEqual(report.advisories_imported, 1)
        self.assertEqual(report.affected_packages_imported, 1)

    def test_adapter_rejects_network_style_source_path_before_database_write(self):
        with tempfile.TemporaryDirectory() as directory:
            database = VulnerabilityDatabase(str(Path(directory) / "vuln.sqlite"))
            try:
                with self.assertRaises((OSError, ValueError)):
                    ingest_file("https://example.invalid/osv.json", database, "p1-osv")
                count = database.connection.execute("SELECT COUNT(*) FROM advisories").fetchone()[0]
            finally:
                database.close()
        self.assertEqual(count, 0)


if __name__ == "__main__":
    unittest.main()
