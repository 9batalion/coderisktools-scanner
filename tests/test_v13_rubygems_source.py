import tempfile
import unittest
from pathlib import Path

from src.vulnerability.database import VulnerabilityDatabase
from src.vulnerability.models import Component
from src.vulnerability.sources.rubygems import RUBYGEMS_SOURCE_ID, ingest_file, ingest_file_to_database


class TestV13RubygemsSource(unittest.TestCase):
    def test_rubygems_fixture_staging_and_fixed_boundary(self):
        payload = '{"schema":"coderisktools.vulnerability.rubygems-feed","version":1,"advisories":[{"id":"CVE-2026-3","package":"rack","fixed":"3.0.9","severity":"high"}]}'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            feed = root / "rubygems.json"
            feed.write_text(payload, encoding="utf-8")
            parsed = ingest_file(str(feed))
            self.assertEqual(parsed["source_id"], RUBYGEMS_SOURCE_ID)
            database = VulnerabilityDatabase(str(root / "db.sqlite"))
            try:
                report = ingest_file_to_database(str(feed), database, "rubygems-1")
                self.assertEqual(report["state"], "staged")
                affected = database.evaluate_component(Component(ecosystem="RubyGems", name="rack", version="3.0.8"))
                fixed = database.evaluate_component(Component(ecosystem="RubyGems", name="rack", version="3.0.9"))
                self.assertEqual(affected["status"], "affected")
                self.assertEqual(fixed["status"], "not_affected")
            finally:
                database.close()
