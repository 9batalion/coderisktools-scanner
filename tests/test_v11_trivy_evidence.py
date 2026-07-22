import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from src.vulnerability.sbom import build_trivy_evidence_report


class TestV11TrivyEvidence(unittest.TestCase):
    def _document(self):
        return {
            "SchemaVersion": 2,
            "ArtifactName": "demo",
            "ArtifactType": "filesystem",
            "Metadata": {"OS": {"Family": "alpine", "Name": "3.20"}},
            "Results": [{
                "Target": "requirements.txt",
                "Class": "lang-pkgs",
                "Type": "python-pkg",
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-2026-0001",
                    "PkgName": "demo",
                    "InstalledVersion": "1.2.3",
                    "FixedVersion": "1.2.4",
                    "PkgPath": "requirements.txt",
                    "PrimaryURL": "https://example.invalid/advisory",
                }],
            }],
        }

    def test_builds_external_evidence_without_inventory_claim(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "trivy.json"
            path.write_text(json.dumps(self._document()), encoding="utf-8")
            report = build_trivy_evidence_report(path)
        self.assertEqual(report["schema"], "coderisktools.vulnerability.external-evidence")
        self.assertEqual(report["tool"], "Trivy")
        self.assertEqual(report["finding_count"], 1)
        finding = report["findings"][0]
        self.assertEqual(finding["evidence_type"], "external-tool")
        self.assertEqual(finding["vulnerability"]["id"], "CVE-2026-0001")
        self.assertEqual(finding["package"]["version"], "1.2.3")

    def test_cli_accepts_local_trivy_json(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "trivy.json"
            path.write_text(json.dumps(self._document()), encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, "-m", "src", "vuln", "inventory", "--trivy", str(path)],
                capture_output=True, text=True, check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)["tool"], "Trivy")

    def test_rejects_missing_vulnerability_identity(self):
        document = self._document()
        del document["Results"][0]["Vulnerabilities"][0]["VulnerabilityID"]
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "trivy.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaises(ValueError):
                build_trivy_evidence_report(path)
