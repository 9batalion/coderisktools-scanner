import tempfile
import unittest
from pathlib import Path

from src.vulnerability.sources.ubuntu import UBUNTU_SOURCE_ID, ingest_file


class TestV12UbuntuSource(unittest.TestCase):
    def test_ingest_ubuntu_fixture_preserves_release_and_provenance(self):
        payload = '{"schema":"coderisktools.vulnerability.ubuntu-feed","version":1,"release":"jammy","advisories":[{"id":"USN-9999-1","package":"openssl","fixed":"3.0.11-1ubuntu2.1","binary_packages":["libssl3"]}]}'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ubuntu.json"
            path.write_text(payload, encoding="utf-8")
            result = ingest_file(str(path))
        self.assertEqual(result["source_id"], UBUNTU_SOURCE_ID)
        self.assertEqual(result["release"], "jammy")
        self.assertEqual(result["advisory_count"], 1)
        self.assertTrue(result["source_digest"].startswith("sha256:"))
        self.assertEqual(result["advisories"][0]["binary_packages"], ["libssl3"])

    def test_rejects_debian_schema_as_ubuntu_feed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ubuntu.json"
            path.write_text('{"schema":"coderisktools.vulnerability.debian-feed","version":1,"release":"jammy","advisories":[]}', encoding="utf-8")
            with self.assertRaises(ValueError):
                ingest_file(str(path))
