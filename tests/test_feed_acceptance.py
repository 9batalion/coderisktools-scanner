import json
import tempfile
import unittest
from pathlib import Path

from src.vulnerability.sources.feed_acceptance import evaluate_feed_artifact


class TestFeedAcceptance(unittest.TestCase):
    def test_accepts_supplied_artifact_without_network_or_activation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "feed.json"
            path.write_text(json.dumps({"vulnerabilities": [{"id": "CVE-1"}]}), encoding="utf-8")
            report = evaluate_feed_artifact(path, source_id="kev", expected_list_key="vulnerabilities")
            self.assertEqual(report["state"], "accepted")
            self.assertFalse(report["activated"])
            self.assertFalse(report["network_used"])
            self.assertTrue(report["source_digest"].startswith("sha256:"))

    def test_rejects_missing_envelope(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "feed.json"
            path.write_text(json.dumps({"items": []}), encoding="utf-8")
            report = evaluate_feed_artifact(path, source_id="epss", expected_list_key="data")
            self.assertEqual(report["state"], "rejected")
            self.assertFalse(report["activated"])
