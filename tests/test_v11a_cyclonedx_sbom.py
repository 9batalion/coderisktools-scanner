"""CycloneDX SBOM importer tests for V11a."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from src.vulnerability.sbom import build_cyclonedx_inventory_report, load_cyclonedx_inventory


class TestCycloneDXSbom(unittest.TestCase):
    def test_imports_exact_components_with_sbom_provenance(self):
        document = {
            "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "components": [
                {"type": "library", "name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0"},
                {"type": "library", "name": "left-pad", "version": "1.3.0", "purl": "pkg:npm/left-pad@1.3.0"},
            ],
        }
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "bom.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            inventory = load_cyclonedx_inventory(path)
            self.assertEqual([item.name for item in inventory.components], ["requests", "left-pad"])
            self.assertEqual(inventory.components[0].source_type, "cyclonedx")
            report = build_cyclonedx_inventory_report(path)
            self.assertEqual(report["source"], {"format": "CycloneDX", "spec_version": "1.5", "path": "bom.json"})
            self.assertEqual(report["component_count"], 2)

    def test_cli_import_is_deterministic_and_rejects_duplicate_identity(self):
        document = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [{"name": "demo", "version": "1", "purl": "pkg:pypi/demo@1"}]}
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "bom.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            command = [sys.executable, "-m", "src", "vuln", "inventory", "--sbom", str(path)]
            first = subprocess.run(command, capture_output=True, text=True, check=False)
            second = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(first.stdout, second.stdout)
            duplicate = {**document, "components": document["components"] * 2}
            path.write_text(json.dumps(duplicate), encoding="utf-8")
            rejected = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(rejected.returncode, 3)
            self.assertEqual(json.loads(rejected.stderr)["state"], "rejected")


if __name__ == "__main__":
    unittest.main()
