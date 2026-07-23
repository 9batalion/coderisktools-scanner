import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.vulnerability.database import VulnerabilityDatabase
from src.vulnerability.sources.osv import fetch_and_ingest_stream
from src.vulnerability.updater import FetchPolicy


class TestOSVFullFeedContract(unittest.TestCase):
    def test_fetch_stream_ingest_keeps_activation_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "osv.jsonl"
            db = VulnerabilityDatabase(Path(directory) / "db.sqlite")
            metadata = {"final_url": "https://osv.dev/vulns/all.jsonl", "payload_sha256": "sha256:" + "a" * 64, "bytes_written": 10}
            with patch("src.vulnerability.sources.osv.stream_json_artifact_to_file", return_value=metadata):
                with patch("src.vulnerability.sources.osv.ingest_osv_streaming_file") as ingest:
                    ingest.return_value.to_dict.return_value = {"state": "staged", "activated": False}
                    result = fetch_and_ingest_stream(
                        "https://osv.dev/vulns/all.jsonl",
                        target,
                        db,
                        "snapshot-osv-1",
                        FetchPolicy(frozenset({"osv.dev"})),
                    )
            ingest.assert_called_once()
            self.assertEqual(result["state"], "staged")
            self.assertFalse(result["activated"])
            self.assertEqual(result["source_digest"], "sha256:" + "a" * 64)
