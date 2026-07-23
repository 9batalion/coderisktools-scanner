import tempfile
import unittest
from pathlib import Path

from src.vulnerability.database import VulnerabilityDatabase
from src.vulnerability.models import Component
from src.vulnerability.sources.debian import ingest_file_to_database


class TestV12DebianBackportMatching(unittest.TestCase):
    def test_debian_backport_fixed_revision_is_not_affected(self):
        payload = '{"schema":"coderisktools.vulnerability.debian-feed","version":1,"release":"bookworm","advisories":[{"id":"DSA-1","package":"openssl","fixed":"3.0.11-1~deb12u2","backport":true,"binary_packages":["libssl3"]}]}'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            feed = root / "debian.json"
            feed.write_text(payload, encoding="utf-8")
            database = VulnerabilityDatabase(str(root / "db.sqlite"))
            try:
                ingest_file_to_database(str(feed), database, "debian-bookworm-1")
                affected = database.evaluate_component(Component(ecosystem="Debian", name="libssl3", version="3.0.11-1~deb12u1"))
                fixed = database.evaluate_component(Component(ecosystem="Debian", name="libssl3", version="3.0.11-1~deb12u2"))
                self.assertEqual(affected["status"], "affected")
                self.assertEqual(fixed["status"], "not_affected")
            finally:
                database.close()
