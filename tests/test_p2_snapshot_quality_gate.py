import unittest

from src.vulnerability.database import SnapshotActivationError, VulnerabilityDatabase


class TestP2SnapshotQualityGate(unittest.TestCase):
    def test_quality_gate_reports_integrity_and_foreign_keys(self):
        database = VulnerabilityDatabase(":memory:")
        try:
            report = database.snapshot_quality_gate()
            self.assertTrue(report["healthy"])
            self.assertEqual(report["checks"]["sqlite_integrity"], "ok")
            self.assertEqual(report["checks"]["foreign_keys"], "ok")
        finally:
            database.close()

    def test_activation_rejects_foreign_key_corruption(self):
        database = VulnerabilityDatabase(":memory:")
        try:
            database.connection.execute("PRAGMA foreign_keys = OFF")
            database.connection.execute("INSERT INTO affected_packages(advisory_id, ecosystem, name) VALUES ('missing', 'PyPI', 'demo')")
            database.connection.commit()
            manifest = database.build_snapshot_manifest()
            database.stage_snapshot("missing-snapshot", "sha256:fixture", manifest)
            with self.assertRaises(SnapshotActivationError):
                database.activate_snapshot("missing-snapshot")
        finally:
            database.close()
