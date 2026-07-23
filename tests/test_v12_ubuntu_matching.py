import tempfile
import unittest
from pathlib import Path

from src.vulnerability.database import VulnerabilityDatabase
from src.vulnerability.models import Component
from src.vulnerability.sources.ubuntu import ingest_file_to_database


class TestV12UbuntuMatching(unittest.TestCase):
    def test_ubuntu_fixed_revision_boundary(self):
        payload = '{"schema":"coderisktools.vulnerability.ubuntu-feed","version":1,"release":"jammy","advisories":[{"id":"USN-1","package":"openssl","fixed":"3.0.11-1ubuntu2.1","binary_packages":["libssl3"]}]}'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            feed = root / "ubuntu.json"
            feed.write_text(payload, encoding="utf-8")
            database = VulnerabilityDatabase(str(root / "db.sqlite"))
            try:
                ingest_file_to_database(str(feed), database, "ubuntu-jammy-1")
                affected = database.evaluate_component(Component(ecosystem="Ubuntu", name="libssl3", version="3.0.11-1ubuntu2"))
                fixed = database.evaluate_component(Component(ecosystem="Ubuntu", name="libssl3", version="3.0.11-1ubuntu2.1"))
                self.assertEqual(affected["status"], "affected")
                self.assertEqual(fixed["status"], "not_affected")
            finally:
                database.close()
