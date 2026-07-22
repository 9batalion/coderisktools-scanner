"""RED tests for V10 vulnerability baseline/delta contract."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from src.vulnerability.reporting import build_json_vulnerability_delta_report


def finding(fingerprint: str, advisory: str) -> dict:
    return {
        "type": "vulnerability", "advisory_id": advisory, "aliases": [],
        "component_purl": "pkg:pypi/demo@1", "manifest_path": "requirements.txt",
        "status": "affected", "method": "exact-version", "confidence": "high",
        "fixed_versions": [], "explanation": "exact match", "fingerprint": fingerprint,
        "snapshot_id": "snapshot-osv", "source": "osv", "severity": "high",
        "evidence": "demo==1",
    }


class TestV10VulnerabilityBaselineDelta(unittest.TestCase):
    def test_delta_preserves_exact_findings_and_reports_resolved(self):
        old = "sha256:" + "a" * 64
        current = "sha256:" + "b" * 64
        report = json.loads(build_json_vulnerability_delta_report(
            [finding(old, "CVE-OLD"), finding(current, "CVE-NEW")],
            "snapshot-osv",
            {old, "sha256:" + "c" * 64},
        ))
        self.assertEqual(report["schema"], "coderisktools.vulnerability.delta")
        self.assertEqual(report["version"], 1)
        self.assertEqual([item["fingerprint"] for item in report["new_findings"]], [current])
        self.assertEqual([item["fingerprint"] for item in report["existing_findings"]], [old])
        self.assertEqual(report["resolved_fingerprints"], ["sha256:" + "c" * 64])
        self.assertEqual(report["new_findings"][0]["evidence"], "demo==1")

    def test_delta_rejects_invalid_fingerprint_baseline(self):
        with self.assertRaises(ValueError):
            build_json_vulnerability_delta_report([], "snapshot-osv", {"not-a-fingerprint"})


class TestV10BaselineCliContract(unittest.TestCase):
    def test_scan_baseline_emits_delta_without_hiding_findings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline = root / "baseline.json"
            baseline.write_text(json.dumps({
                "schema": "coderisktools.vulnerability.baseline", "version": 1,
                "fingerprints": ["sha256:" + "a" * 64],
            }), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, "-m", "src", "vuln", "scan", "--root", str(root),
                 "--database", str(root / "missing.sqlite"), "--baseline", str(baseline), "--format", "json"],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 3)
            self.assertEqual(json.loads(result.stderr)["state"], "rejected")


if __name__ == "__main__":
    unittest.main()
