import tempfile
import unittest
from pathlib import Path

from src.vulnerability.database import VulnerabilityDatabase
from src.vulnerability.models import Component
from src.vulnerability.sources.nuget import NUGET_SOURCE_ID, ingest_file, ingest_file_to_database


class TestV13NugetSource(unittest.TestCase):
    def test_nuget_fixture_staging_and_fixed_boundary(self):
        payload = '{"schema":"coderisktools.vulnerability.nuget-feed","version":1,"advisories":[{"id":"CVE-2026-2","package":"Example.Core","fixed":"8.0.4","severity":"high"}]}'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            feed = root / "nuget.json"
            feed.write_text(payload, encoding="utf-8")
            parsed = ingest_file(str(feed))
            self.assertEqual(parsed["source_id"], NUGET_SOURCE_ID)
            database = VulnerabilityDatabase(str(root / "db.sqlite"))
            try:
                report = ingest_file_to_database(str(feed), database, "nuget-1")
                self.assertEqual(report["state"], "staged")
                affected = database.evaluate_component(Component(ecosystem="NuGet", name="Example.Core", version="8.0.3"))
                fixed = database.evaluate_component(Component(ecosystem="NuGet", name="Example.Core", version="8.0.4"))
                self.assertEqual(affected["status"], "affected")
                self.assertEqual(fixed["status"], "not_affected")
            finally:
                database.close()
