import tempfile
import unittest
from pathlib import Path

from src.vulnerability.database import VulnerabilityDatabase
from src.vulnerability.models import Component
from src.vulnerability.sources.maven import MAVEN_SOURCE_ID, ingest_file, ingest_file_to_database


class TestV13MavenSource(unittest.TestCase):
    def test_maven_fixture_staging_and_fixed_boundary(self):
        payload = '{"schema":"coderisktools.vulnerability.maven-feed","version":1,"advisories":[{"id":"CVE-2026-1","package":"org.example:demo","fixed":"2.4.1","severity":"high"}]}'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            feed = root / "maven.json"
            feed.write_text(payload, encoding="utf-8")
            parsed = ingest_file(str(feed))
            self.assertEqual(parsed["source_id"], MAVEN_SOURCE_ID)
            database = VulnerabilityDatabase(str(root / "db.sqlite"))
            try:
                report = ingest_file_to_database(str(feed), database, "maven-1")
                self.assertEqual(report["state"], "staged")
                affected = database.evaluate_component(Component(ecosystem="Maven", name="org.example:demo", version="2.4.0"))
                fixed = database.evaluate_component(Component(ecosystem="Maven", name="org.example:demo", version="2.4.1"))
                self.assertEqual(affected["status"], "affected")
                self.assertEqual(fixed["status"], "not_affected")
            finally:
                database.close()
