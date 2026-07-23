import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from src.vulnerability.sources.nvd import ingest_file


class TestNVDFeedIngestion(unittest.TestCase):
    def test_ingests_bounded_nvd_api_batch_with_source_digest(self):
        payload = {"vulnerabilities": [{"cve": {"id": "CVE-2024-12345", "descriptions": [], "references": [], "metrics": {}, "configurations": []}}]}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nvd.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            database = Mock()
            database.lookup_advisory.return_value = {"status": "exact", "advisory_id": "CVE-2024-12345"}
            report = ingest_file(path, database, "snapshot-nvd-1")
            database.record_source_record.assert_called_once()
            self.assertEqual(report["state"], "staged")
            self.assertEqual(report["records_seen"], 1)
            self.assertEqual(report["records_imported"], 1)
            self.assertTrue(report["source_digest"].startswith("sha256:"))

    def test_invalid_record_is_reported_without_activation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nvd.json"
            path.write_text(json.dumps({"vulnerabilities": [{"cve": {"id": "bad"}}]}), encoding="utf-8")
            database = Mock()
            report = ingest_file(path, database, "snapshot-nvd-2", activate=True)
            self.assertEqual(report["state"], "partial")
            self.assertFalse(report["activated"])
            self.assertEqual(report["records_imported"], 0)
            self.assertEqual(len(report["errors"]), 1)
