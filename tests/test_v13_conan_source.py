import tempfile
import unittest
from pathlib import Path

from src.vulnerability.database import VulnerabilityDatabase
from src.vulnerability.models import Component
from src.vulnerability.sources.conan import CONAN_SOURCE_ID, ingest_file, ingest_file_to_database


class TestV13ConanSource(unittest.TestCase):
    def test_conan_fixture_staging_and_fixed_boundary(self):
        payload = '{"schema":"coderisktools.vulnerability.conan-feed","version":1,"advisories":[{"id":"CVE-2026-9","package":"openssl","fixed":"3.2.2","severity":"high"}]}'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            feed = root / "conan.json"
            feed.write_text(payload, encoding="utf-8")
            parsed = ingest_file(str(feed))
            self.assertEqual(parsed["source_id"], CONAN_SOURCE_ID)
            database = VulnerabilityDatabase(str(root / "db.sqlite"))
            try:
                report = ingest_file_to_database(str(feed), database, "conan-1")
                self.assertEqual(report["state"], "staged")
                affected = database.evaluate_component(Component(ecosystem="Conan", name="openssl", version="3.2.1"))
                fixed = database.evaluate_component(Component(ecosystem="Conan", name="openssl", version="3.2.2"))
                self.assertEqual(affected["status"], "affected")
                self.assertEqual(fixed["status"], "not_affected")
            finally:
                database.close()
