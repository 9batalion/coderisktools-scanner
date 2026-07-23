import tempfile
import unittest
from pathlib import Path

from src.vulnerability.database import VulnerabilityDatabase
from src.vulnerability.models import Component
from src.vulnerability.sources.suse import ingest_file, ingest_file_to_database, SUSE_SOURCE_ID


class TestV12SuseSource(unittest.TestCase):
    def test_suse_parser_and_staging_preserve_sle_metadata(self):
        payload = '{"schema":"coderisktools.vulnerability.suse-feed","version":1,"release":"sles-15-sp5","advisories":[{"id":"SUSE-SU-9999:1","package":"openssl","fixed":"3.0.8-150500.3.20.1","severity":"important","binary_packages":["libopenssl3"],"backport":true}]}'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            feed = root / "suse.json"
            feed.write_text(payload, encoding="utf-8")
            parsed = ingest_file(str(feed))
            self.assertEqual(parsed["source_id"], SUSE_SOURCE_ID)
            database = VulnerabilityDatabase(str(root / "db.sqlite"))
            try:
                report = ingest_file_to_database(str(feed), database, "suse-sles15-1")
                self.assertEqual(report["state"], "staged")
                self.assertFalse(report["activated"])
                affected = database.evaluate_component(Component(ecosystem="RPM", name="libopenssl3", version="3.0.8-150500.3.19.1"))
                fixed = database.evaluate_component(Component(ecosystem="RPM", name="libopenssl3", version="3.0.8-150500.3.20.1"))
                self.assertEqual(affected["status"], "affected")
                self.assertEqual(fixed["status"], "not_affected")
            finally:
                database.close()
