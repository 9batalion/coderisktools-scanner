import tempfile
import unittest
from pathlib import Path

from src.vulnerability.database import VulnerabilityDatabase
from src.vulnerability.models import Component
from src.vulnerability.sources.haskell import HASKELL_SOURCE_ID, ingest_file, ingest_file_to_database


class TestV13HaskellSource(unittest.TestCase):
    def test_haskell_fixture_staging_and_fixed_boundary(self):
        payload = '{"schema":"coderisktools.vulnerability.haskell-feed","version":1,"advisories":[{"id":"CVE-2026-7","package":"aeson","fixed":"2.2.1.1","severity":"high"}]}'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            feed = root / "haskell.json"
            feed.write_text(payload, encoding="utf-8")
            parsed = ingest_file(str(feed))
            self.assertEqual(parsed["source_id"], HASKELL_SOURCE_ID)
            database = VulnerabilityDatabase(str(root / "db.sqlite"))
            try:
                report = ingest_file_to_database(str(feed), database, "haskell-1")
                self.assertEqual(report["state"], "staged")
                affected = database.evaluate_component(Component(ecosystem="Hackage", name="aeson", version="2.2.1.0"))
                fixed = database.evaluate_component(Component(ecosystem="Hackage", name="aeson", version="2.2.1.1"))
                self.assertEqual(affected["status"], "affected")
                self.assertEqual(fixed["status"], "not_affected")
            finally:
                database.close()
