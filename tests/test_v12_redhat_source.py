import tempfile
import unittest
from pathlib import Path

from src.vulnerability.sources.redhat import REDHAT_SOURCE_ID, ingest_file


class TestV12RedHatSource(unittest.TestCase):
    def test_ingest_redhat_fixture_preserves_rpm_metadata(self):
        payload = '{"schema":"coderisktools.vulnerability.redhat-feed","version":1,"release":"rhel-9","advisories":[{"id":"RHSA-9999:001","package":"openssl","fixed":"3.0.7-25.el9_2","severity":"Important","binary_packages":["openssl-libs"],"backport":true}]}'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "redhat.json"
            path.write_text(payload, encoding="utf-8")
            result = ingest_file(str(path))
        self.assertEqual(result["source_id"], REDHAT_SOURCE_ID)
        self.assertEqual(result["release"], "rhel-9")
        self.assertEqual(result["advisories"][0]["severity"], "Important")
        self.assertTrue(result["advisories"][0]["backport"])
        self.assertTrue(result["source_digest"].startswith("sha256:"))

    def test_rejects_wrong_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "redhat.json"
            path.write_text('{"schema":"coderisktools.vulnerability.ubuntu-feed","version":1,"release":"rhel-9","advisories":[]}', encoding="utf-8")
            with self.assertRaises(ValueError):
                ingest_file(str(path))
