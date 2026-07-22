import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from src.vulnerability.sbom import build_osv_scanner_evidence_report


class TestV11OsvScannerEvidence(unittest.TestCase):
    def test_builds_sorted_external_evidence_without_inventory_semantics(self):
        document = {
            "osv-scanner": {"version": "2.0.0"},
            "results": [{
                "source": {"path": "requirements.txt", "type": "lockfile"},
                "packages": [{
                    "package": {"name": "demo", "version": "1.0.0", "ecosystem": "PyPI", "purl": "pkg:pypi/demo@1.0.0"},
                    "vulnerabilities": [{"id": "GHSA-demo", "aliases": ["CVE-2026-1101"]}],
                }],
            }],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "osv.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            report = build_osv_scanner_evidence_report(path)
        self.assertEqual(report["schema"], "coderisktools.vulnerability.external-evidence")
        self.assertEqual(report["tool"], "OSV-Scanner")
        self.assertEqual(report["finding_count"], 1)
        self.assertEqual(report["findings"][0]["evidence_type"], "external-tool")
        self.assertNotIn("components", report)

    def test_rejects_duplicate_package_identity_and_missing_tool_version(self):
        base = {
            "osv-scanner": {"version": "2.0.0"},
            "results": [{"source": {"path": "a.lock"}, "packages": [
                {"package": {"name": "demo", "version": "1", "ecosystem": "PyPI"}, "vulnerabilities": []},
                {"package": {"name": "demo", "version": "1", "ecosystem": "PyPI"}, "vulnerabilities": []},
            ]}],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "osv.json"
            path.write_text(json.dumps(base), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate package"):
                build_osv_scanner_evidence_report(path)
            base["osv-scanner"] = {}
            path.write_text(json.dumps(base), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "tool version"):
                build_osv_scanner_evidence_report(path)

    def test_cli_exposes_external_evidence_explicitly(self):
        document = {"osv-scanner": {"version": "2.0.0"}, "results": []}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "osv.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            result = subprocess.run([sys.executable, "-m", "src", "vuln", "inventory", "--osv-scanner", str(path)], capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["schema"], "coderisktools.vulnerability.external-evidence")


if __name__ == "__main__":
    unittest.main()
