import tempfile
import unittest
from pathlib import Path

from src.vulnerability.database import VulnerabilityDatabase
from src.vulnerability.ingestion import ingest_osv_streaming_file


class TestP2StreamingOsvIntegration(unittest.TestCase):
    def test_jsonl_is_validated_then_imported_without_materializing_feed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "feed.jsonl"
            path.write_text(
                '{"id":"OSV-STREAM-1","affected":[{"package":{"ecosystem":"PyPI","name":"demo"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}\n',
                encoding="utf-8",
            )
            database = VulnerabilityDatabase(":memory:")
            try:
                report = ingest_osv_streaming_file(str(path), database, "snap-stream", "osv")
                self.assertEqual(report.state, "staged")
                self.assertEqual(report.records_seen, 1)
                self.assertEqual(report.advisories_imported, 1)
                self.assertEqual(database.snapshot_status("snap-stream")["state"], "staged")
                self.assertEqual(database.connection.execute("SELECT record_count FROM source_snapshots WHERE snapshot_id = 'snap-stream'").fetchone()[0], 1)
                self.assertEqual(database.connection.execute("SELECT COUNT(*) FROM quality_metrics WHERE snapshot_id = 'snap-stream'").fetchone()[0], 3)
            finally:
                database.close()

    def test_streaming_ingestion_rejects_invalid_record_before_target_import(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "feed.jsonl"
            path.write_text('{"id":"OSV-STREAM-2"}\nnot-json\n', encoding="utf-8")
            database = VulnerabilityDatabase(":memory:")
            try:
                report = ingest_osv_streaming_file(str(path), database, "snap-invalid", "osv")
                self.assertEqual(report.state, "rejected")
                self.assertEqual(database.advisory_count(), 0)
                self.assertEqual(database.connection.execute("SELECT COUNT(*) FROM import_errors WHERE snapshot_id = 'snap-invalid'").fetchone()[0], 1)
            finally:
                database.close()
