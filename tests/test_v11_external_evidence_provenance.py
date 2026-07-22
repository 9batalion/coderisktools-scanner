import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from src.vulnerability.sbom import attach_external_evidence_provenance, build_osv_scanner_evidence_report


class TestV11ExternalEvidenceProvenance(unittest.TestCase):
    def _osv(self):
        return {"osv-scanner": {"version": "2.0.0"}, "results": []}

    def _provenance(self, source_sha256):
        return {
            "schema": "coderisktools.vulnerability.external-evidence-provenance",
            "version": 1,
            "source_id": "osv-local",
            "source_format": "OSV-Scanner",
            "source_sha256": source_sha256,
            "collected_at": "2026-07-22T12:00:00Z",
            "collector": "ci-evidence-job",
            "tool_version": "2.0.0",
        }

    def test_attaches_verified_provenance(self):
        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / "osv.json"
            sidecar = Path(td) / "osv.provenance.json"
            source.write_text(json.dumps(self._osv()), encoding="utf-8")
            digest = __import__("hashlib").sha256(source.read_bytes()).hexdigest()
            sidecar.write_text(json.dumps(self._provenance("sha256:" + digest)), encoding="utf-8")
            report = attach_external_evidence_provenance(build_osv_scanner_evidence_report(source), source, sidecar)
        self.assertEqual(report["provenance"]["source_id"], "osv-local")
        self.assertEqual(report["provenance"]["source_sha256"], "sha256:" + digest)
        self.assertIn("provenance_digest", report)

    def test_rejects_tampered_source_digest(self):
        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / "osv.json"
            sidecar = Path(td) / "osv.provenance.json"
            source.write_text(json.dumps(self._osv()), encoding="utf-8")
            sidecar.write_text(json.dumps(self._provenance("sha256:" + "0" * 64)), encoding="utf-8")
            with self.assertRaises(ValueError):
                attach_external_evidence_provenance(build_osv_scanner_evidence_report(source), source, sidecar)

    def test_cli_attaches_provenance(self):
        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / "osv.json"
            sidecar = Path(td) / "osv.provenance.json"
            source.write_text(json.dumps(self._osv()), encoding="utf-8")
            digest = __import__("hashlib").sha256(source.read_bytes()).hexdigest()
            sidecar.write_text(json.dumps(self._provenance("sha256:" + digest)), encoding="utf-8")
            completed = subprocess.run([sys.executable, "-m", "src", "vuln", "inventory", "--osv-scanner", str(source), "--provenance", str(sidecar)], capture_output=True, text=True, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)["provenance"]["source_id"], "osv-local")
