import unittest

from src.vulnerability.database import VulnerabilityDatabase


class TestP2SnapshotRetention(unittest.TestCase):
    def test_prune_is_dry_run_by_default_and_never_removes_active(self):
        database = VulnerabilityDatabase(":memory:")
        try:
            manifest = database.build_snapshot_manifest()
            database.stage_snapshot("keep", "sha256:keep", manifest)
            database.stage_snapshot("old", "sha256:old", manifest)
            database.activate_snapshot("keep")
            plan = database.prune_snapshots({"keep"})
            self.assertEqual(plan["candidates"], ["old"])
            self.assertFalse(plan["applied"])
            self.assertIsNotNone(database.snapshot_status("old"))
            applied = database.prune_snapshots({"keep"}, apply=True)
            self.assertEqual(applied["removed"], ["old"])
            self.assertIsNotNone(database.snapshot_status("keep"))
            with self.assertRaises(KeyError):
                database.snapshot_status("old")
        finally:
            database.close()
