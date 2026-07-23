import tempfile
import unittest
from pathlib import Path

from src.vulnerability.database import VulnerabilityDatabase
from src.vulnerability.models import Component
from src.vulnerability.sources.swift import SWIFT_SOURCE_ID, ingest_file, ingest_file_to_database


class TestV13SwiftSource(unittest.TestCase):
    def test_swift_fixture_staging_and_fixed_boundary(self):
        payload = '{"schema":"coderisktools.vulnerability.swift-feed","version":1,"advisories":[{"id":"CVE-2026-4","package":"swift-nio","fixed":"2.65.0","severity":"high"}]}'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            feed = root / "swift.json"
            feed.write_text(payload, encoding="utf-8")
            parsed = ingest_file(str(feed))
            self.assertEqual(parsed["source_id"], SWIFT_SOURCE_ID)
            database = VulnerabilityDatabase(str(root / "db.sqlite"))
            try:
                report = ingest_file_to_database(str(feed), database, "swift-1")
                self.assertEqual(report["state"], "staged")
                affected = database.evaluate_component(Component(ecosystem="Swift", name="swift-nio", version="2.64.0"))
                fixed = database.evaluate_component(Component(ecosystem="Swift", name="swift-nio", version="2.65.0"))
                self.assertEqual(affected["status"], "affected")
                self.assertEqual(fixed["status"], "not_affected")
            finally:
                database.close()
