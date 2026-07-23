import tempfile
import unittest
from pathlib import Path

from src.vulnerability.database import VulnerabilityDatabase
from src.vulnerability.sources.debian import ingest_file_to_database


class TestV12DebianStaging(unittest.TestCase):
    def test_debian_feed_stages_normalized_osv_records_without_activation(self):
        payload = '{"schema":"coderisktools.vulnerability.debian-feed","version":1,"release":"bookworm","advisories":[{"id":"DSA-1","package":"openssl","fixed":"3.0.11-1~deb12u2","backport":true,"binary_packages":["libssl3"]}]}'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            feed = root / "debian.json"
            database_path = root / "db.sqlite"
            feed.write_text(payload, encoding="utf-8")
            database = VulnerabilityDatabase(str(database_path))
            try:
                report = ingest_file_to_database(str(feed), database, "debian-bookworm-1")
                self.assertEqual(report["state"], "staged")
                self.assertFalse(report["activated"])
                self.assertEqual(database.advisory_count(), 1)
                self.assertEqual(database.snapshot_status("debian-bookworm-1")["state"], "staged")
                self.assertEqual(database.connection.execute("SELECT record_count FROM source_snapshots WHERE snapshot_id='debian-bookworm-1'").fetchone()[0], 1)
                self.assertEqual(database.connection.execute("SELECT COUNT(*) FROM quality_metrics WHERE snapshot_id='debian-bookworm-1'").fetchone()[0], 3)
                self.assertEqual(database.connection.execute("SELECT source FROM advisories WHERE id='DSA-1'").fetchone()[0], "debian-security:bookworm")
            finally:
                database.close()
