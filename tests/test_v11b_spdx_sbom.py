"""SPDX JSON SBOM importer tests for V11b."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from src.vulnerability.sbom import build_spdx_inventory_report, load_spdx_inventory


class TestSpdxSbom(unittest.TestCase):
    def test_imports_packages_with_purl_and_provenance(self):
        document = {
            "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
            "name": "demo", "documentNamespace": "https://example.invalid/spdx/demo",
            "packages": [{
                "SPDXID": "SPDXRef-Package-requests", "name": "requests", "versionInfo": "2.31.0",
                "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:pypi/requests@2.31.0"}],
            }],
        }
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "bom.spdx.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            inventory = load_spdx_inventory(path)
            self.assertEqual(inventory.components[0].purl, "pkg:pypi/requests@2.31.0")
            self.assertEqual(inventory.components[0].source_type, "spdx")
            self.assertTrue(inventory.components[0].exact_version)
            report = build_spdx_inventory_report(path)
            self.assertEqual(report["source"], {"format": "SPDX", "spec_version": "SPDX-2.3", "path": "bom.spdx.json"})

    def test_cli_is_deterministic_and_rejects_duplicate_identity(self):
        package = {"SPDXID": "SPDXRef-Package-demo", "name": "demo", "versionInfo": "1.0"}
        document = {"spdxVersion": "SPDX-2.2", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT", "name": "demo", "documentNamespace": "https://example.invalid/spdx/demo", "packages": [package]}
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "bom.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            command = [sys.executable, "-m", "src", "vuln", "inventory", "--sbom", str(path)]
            first = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(json.loads(first.stdout)["source"]["format"], "SPDX")
            duplicate = {**document, "packages": [package, dict(package, SPDXID="SPDXRef-Package-demo-2")]}
            path.write_text(json.dumps(duplicate), encoding="utf-8")
            rejected = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(rejected.returncode, 3)
            self.assertEqual(json.loads(rejected.stderr)["state"], "rejected")


if __name__ == "__main__":
    unittest.main()
