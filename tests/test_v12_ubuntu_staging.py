import tempfile
import unittest
from pathlib import Path

from src.vulnerability.database import VulnerabilityDatabase
from src.vulnerability.sources.ubuntu import ingest_file_to_database


class TestV12UbuntuStaging(unittest.TestCase):
    def test_ubuntu_feed_stages_usn_without_activation(self):
        payload = '{"schema":"coderisktools.vulnerability.ubuntu-feed","version":1,"release":"jammy","advisories":[{"id":"USN-1","package":"openssl","fixed":"3.0.11-1ubuntu2.1","binary_packages":["libssl3"]}]}'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            feed = root / "ubuntu.json"
            feed.write_text(payload, encoding="utf-8")
            database = VulnerabilityDatabase(str(root / "db.sqlite"))
            try:
                report = ingest_file_to_database(str(feed), database, "ubuntu-jammy-1")
                self.assertEqual(report["state"], "staged")
                self.assertFalse(report["activated"])
                self.assertEqual(database.advisory_count(), 1)
                self.assertEqual(database.snapshot_status("ubuntu-jammy-1")["state"], "staged")
                self.assertEqual(database.connection.execute("SELECT source FROM advisories WHERE id='USN-1'").fetchone()[0], "ubuntu-security:jammy")
            finally:
                database.close()
