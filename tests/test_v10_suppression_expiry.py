import json
import tempfile
import unittest
from pathlib import Path

from src.vulnerability.vex import load_suppressions, suppression_lifecycle_report


FP = "sha256:" + "b" * 64


class TestV10SuppressionExpiry(unittest.TestCase):
    def test_v2_suppression_requires_lifecycle_metadata_and_reports_expired_unused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "suppressions.json"
            path.write_text(json.dumps({
                "schema": "coderisktools.vulnerability.suppressions", "version": 2,
                "entries": [{
                    "fingerprint": FP, "reason": "accepted risk", "owner": "security",
                    "ticket": "SEC-123", "scope": "service-a", "expires_at": "2026-01-01",
                }],
            }), encoding="utf-8")
            entries = load_suppressions(str(path))
            self.assertEqual(entries[0]["owner"], "security")
            report = suppression_lifecycle_report(entries, observed_fingerprints=(), as_of="2026-07-22")
            self.assertEqual(report["counts"], {"active": 0, "expired": 1, "used": 0, "unused": 1})
            self.assertEqual(report["entries"][0]["status"], "expired")
            self.assertEqual(report["entries"][0]["usage"], "unused")

    def test_v2_rejects_invalid_expiry_and_missing_owner(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "suppressions.json"
            path.write_text(json.dumps({
                "schema": "coderisktools.vulnerability.suppressions", "version": 2,
                "entries": [{"fingerprint": FP, "reason": "x", "ticket": "T", "scope": "s", "expires_at": "not-a-date"}],
            }), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_suppressions(str(path))


if __name__ == "__main__":
    unittest.main()
