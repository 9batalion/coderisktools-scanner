"""RED tests for V10 OpenVEX/CycloneDX VEX and suppression annotations."""

import json
import tempfile
import unittest
from pathlib import Path

from src.vulnerability.vex import annotate_vulnerability_findings, load_suppressions, load_vex_document


FP = "sha256:" + "a" * 64
FINDING = {
    "fingerprint": FP, "advisory_id": "CVE-VEX-1", "aliases": ["GHSA-vex"],
    "component_purl": "pkg:pypi/demo@1.0", "evidence": "demo==1.0",
}


class TestVexContracts(unittest.TestCase):
    def test_openvex_not_affected_annotates_without_dropping_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "openvex.json"
            path.write_text(json.dumps({"statements": [{
                "vulnerability": {"@id": "CVE-VEX-1"},
                "products": ["pkg:pypi/demo@1.0"], "status": "not_affected",
                "justification": "component_not_present",
            }]}), encoding="utf-8")
            annotated = annotate_vulnerability_findings([FINDING], load_vex_document(str(path)))
            self.assertTrue(annotated[0]["suppressed"])
            self.assertEqual(annotated[0]["vex_status"], "not_affected")
            self.assertEqual(annotated[0]["evidence"], "demo==1.0")

    def test_cyclonedx_resolved_maps_to_fixed(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "bom.json"
            path.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.5", "vulnerabilities": [{
                "id": "CVE-VEX-1", "analysis": {"state": "resolved"},
                "affects": [{"ref": "pkg:pypi/demo@1.0"}],
            }]}), encoding="utf-8")
            statement = load_vex_document(str(path))[0]
            self.assertEqual(statement["status"], "fixed")
            self.assertFalse(annotate_vulnerability_findings([FINDING], [statement])[0]["suppressed"])

    def test_strict_suppression_is_reasoned_and_exact(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "suppressions.json"
            path.write_text(json.dumps({
                "schema": "coderisktools.vulnerability.suppressions", "version": 1,
                "entries": [{"fingerprint": FP, "reason": "accepted risk"}],
            }), encoding="utf-8")
            annotated = annotate_vulnerability_findings([FINDING], (), load_suppressions(str(path)))
            self.assertTrue(annotated[0]["suppressed"])
            self.assertEqual(annotated[0]["suppression_reason"], "accepted risk")
            self.assertEqual(annotated[0]["evidence"], "demo==1.0")

    def test_not_affected_requires_justification(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "bad.json"
            path.write_text(json.dumps({"statements": [{
                "vulnerability": "CVE-VEX-1", "products": ["pkg:pypi/demo@1.0"], "status": "not_affected",
            }]}), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_vex_document(str(path))


if __name__ == "__main__":
    unittest.main()
