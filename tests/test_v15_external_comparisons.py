import json
import unittest
from pathlib import Path

from src.vulnerability.benchmark import compare_external_evidence


class TestExternalComparisons(unittest.TestCase):
    def test_comparison_classifies_differences_without_merging_results(self):
        fixture = json.loads((Path(__file__).parent / "fixtures" / "v15_external_comparison.json").read_text(encoding="utf-8"))
        report = compare_external_evidence(
            set(fixture["internal"]),
            {tool: set(ids) for tool, ids in fixture["tools"].items()},
        )
        self.assertEqual(report["tools"], ["Grype", "OSV-Scanner", "Trivy"])
        self.assertEqual(report["tools"][0], "Grype")
        self.assertIn("CVE-3", report["differences"]["OSV-Scanner"]["external_only"])
        self.assertIn("CVE-4", report["differences"]["Grype"]["external_only"])
        self.assertEqual(report["differences"]["Trivy"]["status"], "aligned")
