import unittest

from src.vulnerability.release import production_snapshot_gate


class TestV16ProductionGate(unittest.TestCase):
    def test_complete_snapshot_passes_readiness_gate(self):
        report = production_snapshot_gate({
            "build_id": "build-1",
            "source_digest": "sha256:abc",
            "manifest_digest": "sha256:def",
            "reproducibility": {"python": "3.11", "platform": "linux", "deterministic": True},
            "licenses": ["MIT"],
            "attributions": ["OSV"],
            "manifest_signature": {"verified": True},
            "airgap_bundle": {"verified": True},
        })
        self.assertTrue(report["passed"])
        self.assertEqual(report["failed"], [])

    def test_incomplete_snapshot_reports_missing_requirements(self):
        report = production_snapshot_gate({"build_id": "build-2"})
        self.assertFalse(report["passed"])
        self.assertIn("source_digest", report["failed"])
