import tempfile
import unittest
from pathlib import Path

from src.vulnerability.database import VulnerabilityDatabase
from src.vulnerability.models import Component
from src.vulnerability.sources.redhat import ingest_file_to_database


class TestV12RedHatStaging(unittest.TestCase):
    def test_redhat_rpm_boundary_stages_without_activation(self):
        payload = '{"schema":"coderisktools.vulnerability.redhat-feed","version":1,"release":"rhel-9","advisories":[{"id":"RHSA-1","package":"openssl","fixed":"3.0.7-25.el9_2","severity":"Important","binary_packages":["openssl-libs"],"backport":true}]}'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            feed = root / "redhat.json"
            feed.write_text(payload, encoding="utf-8")
            database = VulnerabilityDatabase(str(root / "db.sqlite"))
            try:
                report = ingest_file_to_database(str(feed), database, "rhel-9-1")
                self.assertEqual(report["state"], "staged")
                self.assertFalse(report["activated"])
                affected = database.evaluate_component(Component(ecosystem="RPM", name="openssl-libs", version="3.0.7-24.el9_2"))
                fixed = database.evaluate_component(Component(ecosystem="RPM", name="openssl-libs", version="3.0.7-25.el9_2"))
                self.assertEqual(affected["status"], "affected")
                self.assertEqual(fixed["status"], "not_affected")
            finally:
                database.close()
