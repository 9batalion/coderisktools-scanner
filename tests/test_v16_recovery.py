import tempfile
import unittest
from pathlib import Path

from src.vulnerability.airgap import export_air_gap_bundle, import_air_gap_bundle
from src.vulnerability.database import VulnerabilityDatabase
from src.vulnerability.release import rollback_readiness_report


class TestV16Recovery(unittest.TestCase):
    def test_rollback_plan_is_non_destructive_until_apply(self):
        database = VulnerabilityDatabase(":memory:")
        try:
            report = rollback_readiness_report(database, {"keep-1"})
            self.assertTrue(report["ready"])
            self.assertFalse(report["applied"])
        finally:
            database.close()

    def test_airgap_bundle_can_be_restored(self):
        with tempfile.TemporaryDirectory() as directory:
            source_path = Path(directory) / "source.sqlite"
            bundle = Path(directory) / "snapshot.tar.gz"
            target = Path(directory) / "restored.sqlite"
            database = VulnerabilityDatabase(str(source_path))
            database.import_osv_records([{"id": "CVE-2026-DR", "affected": []}], source="fixture")
            export_air_gap_bundle(database, bundle)
            database.close()
            result = import_air_gap_bundle(bundle, target)
            self.assertFalse(result["activated"])
            self.assertTrue(target.is_file())
