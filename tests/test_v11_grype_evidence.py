import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from src.vulnerability.sbom import build_grype_evidence_report


class TestV11GrypeEvidence(unittest.TestCase):
    def _document(self):
        return {
            "descriptor": {"name": "grype", "version": "0.88.0"},
            "matches": [{
                "artifact": {
                    "name": "demo",
                    "version": "1.2.3",
                    "type": "python",
                    "purl": "pkg:pypi/demo@1.2.3",
                    "locations": [{"path": "requirements.txt"}],
                },
                "vulnerability": {
                    "id": "CVE-2026-0002",
                    "severity": "High",
                    "urls": ["https://example.invalid/advisory"],
                },
                "relatedVulnerabilities": [{"id": "GHSA-demo-0002"}],
            }],
        }

    def test_builds_external_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "grype.json"
            path.write_text(json.dumps(self._document()), encoding="utf-8")
            report = build_grype_evidence_report(path)
        self.assertEqual(report["schema"], "coderisktools.vulnerability.external-evidence")
        self.assertEqual(report["tool"], "Grype")
        self.assertEqual(report["tool_version"], "0.88.0")
        self.assertEqual(report["finding_count"], 1)
        self.assertEqual(report["findings"][0]["vulnerability"]["id"], "CVE-2026-0002")
        self.assertEqual(report["findings"][0]["package"]["purl"], "pkg:pypi/demo@1.2.3")

    def test_cli_accepts_local_grype_json(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "grype.json"
            path.write_text(json.dumps(self._document()), encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, "-m", "src", "vuln", "inventory", "--grype", str(path)],
                capture_output=True, text=True, check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)["tool"], "Grype")

    def test_rejects_missing_artifact_identity(self):
        document = self._document()
        del document["matches"][0]["artifact"]["version"]
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "grype.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaises(ValueError):
                build_grype_evidence_report(path)
