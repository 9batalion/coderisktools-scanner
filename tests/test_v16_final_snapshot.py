import unittest

from src.vulnerability.release import build_production_snapshot_report


class TestV16FinalSnapshotReport(unittest.TestCase):
    def test_final_report_combines_release_gates(self):
        report = build_production_snapshot_report(
            {
                "build_id": "build-1",
                "source_digest": "sha256:abc",
                "manifest_digest": "sha256:def",
                "reproducibility": {"python": "3.11", "platform": "linux", "deterministic": True},
                "licenses": ["MIT"],
                "attributions": ["OSV"],
                "manifest_signature": {"verified": True},
                "airgap_bundle": {"verified": True},
            },
            {"snapshot_id": "snap-1", "status": "active", "records": 10, "errors": [], "quality": {"invalid": 0}},
            {"OSV": {"records": 10, "advisories": 5}},
            rollback={"ready": True, "applied": False},
            disaster_recovery={"verified": True, "activated": False},
        )
        self.assertTrue(report["ready"])
        self.assertEqual(report["failed"], [])
        self.assertTrue(report["health"]["healthy"])
