import tempfile
import unittest
from pathlib import Path

from src.vulnerability.sources.debian import DEBIAN_SOURCE_ID, ingest_file


class TestV12DebianSource(unittest.TestCase):
    def test_ingest_debian_local_feed_preserves_backport_metadata(self):
        payload = """{
          "schema": "coderisktools.vulnerability.debian-feed",
          "version": 1,
          "release": "bookworm",
          "advisories": [{
            "id": "DSA-9999-1",
            "package": "openssl",
            "urgency": "high",
            "fixed": "3.0.11-1~deb12u2",
            "backport": true,
            "source_package": "openssl",
            "binary_packages": ["openssl", "libssl3"]
          }]
        }"""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "debian.json"
            path.write_text(payload, encoding="utf-8")
            result = ingest_file(str(path))
        self.assertEqual(result["source_id"], DEBIAN_SOURCE_ID)
        self.assertEqual(result["source_digest"].split(":", 1)[0], "sha256")
        self.assertEqual(len(result["source_digest"].split(":", 1)[1]), 64)
        self.assertEqual(result["provenance"]["source_id"], DEBIAN_SOURCE_ID)
        self.assertEqual(result["release"], "bookworm")
        self.assertEqual(result["advisory_count"], 1)
        self.assertTrue(result["advisories"][0]["backport"])
        self.assertEqual(result["advisories"][0]["binary_packages"], ["libssl3", "openssl"])

    def test_rejects_unbounded_or_invalid_debian_feed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "debian.json"
            path.write_text('{"schema":"wrong","version":1,"advisories":[]}', encoding="utf-8")
            with self.assertRaises(ValueError):
                ingest_file(str(path))
