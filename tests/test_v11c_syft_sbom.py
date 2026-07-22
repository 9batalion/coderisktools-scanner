"""Syft native JSON SBOM importer tests for V11c."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from src.vulnerability.sbom import build_syft_inventory_report, load_syft_inventory


DOCUMENT = {
    "artifacts": [
        {"id": "artifact-1", "name": "requests", "version": "2.31.0", "type": "python", "purl": "pkg:pypi/requests@2.31.0"},
        {"id": "artifact-2", "name": "left-pad", "version": "1.3.0", "type": "npm", "purl": "pkg:npm/left-pad@1.3.0"},
    ],
    "descriptor": {"name": "syft", "version": "1.0.0"},
    "source": {"type": "directory", "name": "demo"},
}


class TestSyftSbom(unittest.TestCase):
    def test_imports_artifacts_with_syft_provenance(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "syft.json"
            path.write_text(json.dumps(DOCUMENT), encoding="utf-8")
            inventory = load_syft_inventory(path)
            self.assertEqual([item.name for item in inventory.components], ["requests", "left-pad"])
            self.assertEqual(inventory.components[0].source_type, "syft")
            self.assertTrue(inventory.components[0].exact_version)
            report = build_syft_inventory_report(path)
            self.assertEqual(report["source"], {"format": "Syft", "spec_version": "1.0.0", "path": "syft.json"})
            self.assertEqual(report["component_count"], 2)

    def test_cli_autodetect_is_deterministic_and_rejects_duplicate_purl(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "syft.json"
            path.write_text(json.dumps(DOCUMENT), encoding="utf-8")
            command = [sys.executable, "-m", "src", "vuln", "inventory", "--sbom", str(path)]
            first = subprocess.run(command, capture_output=True, text=True, check=False)
            second = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(first.stdout, second.stdout)
            duplicate = json.loads(json.dumps(DOCUMENT))
            duplicate["artifacts"].append(dict(DOCUMENT["artifacts"][0], id="artifact-duplicate"))
            path.write_text(json.dumps(duplicate), encoding="utf-8")
            rejected = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(rejected.returncode, 3)
            self.assertEqual(json.loads(rejected.stderr)["state"], "rejected")


if __name__ == "__main__":
    unittest.main()
