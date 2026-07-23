import tempfile
import unittest
from pathlib import Path

from src.vulnerability.database import VulnerabilityDatabase
from src.vulnerability.models import Component
from src.vulnerability.sources.alpine import ALPINE_SOURCE_ID, ingest_file, ingest_file_to_database
from src.vulnerability.versions.alpine import compare_alpine_version


class TestV12AlpineSource(unittest.TestCase):
    def test_apk_comparator_and_alpine_staging(self):
        self.assertLess(compare_alpine_version("3.18.4-r0", "3.18.4-r1"), 0)
        payload = '{"schema":"coderisktools.vulnerability.alpine-feed","version":1,"release":"v3.18","advisories":[{"id":"CVE-9999-1","package":"openssl","fixed":"3.1.4-r2","severity":"high","binary_packages":["libcrypto3"],"backport":true}]}'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            feed = root / "alpine.json"
            feed.write_text(payload, encoding="utf-8")
            parsed = ingest_file(str(feed))
            self.assertEqual(parsed["source_id"], ALPINE_SOURCE_ID)
            database = VulnerabilityDatabase(str(root / "db.sqlite"))
            try:
                report = ingest_file_to_database(str(feed), database, "alpine-v318-1")
                self.assertEqual(report["state"], "staged")
                affected = database.evaluate_component(Component(ecosystem="Alpine", name="libcrypto3", version="3.1.4-r1"))
                fixed = database.evaluate_component(Component(ecosystem="Alpine", name="libcrypto3", version="3.1.4-r2"))
                self.assertEqual(affected["status"], "affected")
                self.assertEqual(fixed["status"], "not_affected")
            finally:
                database.close()
