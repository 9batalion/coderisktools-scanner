import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from src.vulnerability.airgap import export_air_gap_bundle, import_air_gap_bundle
from src.vulnerability.database import VulnerabilityDatabase


class TestP2AirGapBundle(unittest.TestCase):
    def test_export_and_import_verifies_manifest_and_is_not_active(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_path = root / "source.sqlite"
            bundle = root / "bundle.tar.gz"
            target = root / "target.sqlite"
            source = VulnerabilityDatabase(str(source_path))
            try:
                exported = export_air_gap_bundle(source, bundle)
                self.assertEqual(exported["schema"], "coderisktools.vulnerability.air-gap-bundle")
            finally:
                source.close()
            result = import_air_gap_bundle(bundle, target)
            self.assertFalse(result["activated"])
            imported = VulnerabilityDatabase.read_only(str(target))
            try:
                self.assertEqual(imported.build_snapshot_manifest()["content_digest"], exported["manifest"]["content_digest"])
            finally:
                imported.close()

    def test_tampered_bundle_is_rejected_without_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = VulnerabilityDatabase(str(root / "source.sqlite"))
            try:
                export_air_gap_bundle(source, root / "bundle.tar.gz")
            finally:
                source.close()
            tampered = root / "tampered.tar.gz"
            with tarfile.open(root / "bundle.tar.gz", "r:gz") as source_tar, tarfile.open(tampered, "w:gz") as target_tar:
                for member in source_tar.getmembers():
                    payload = source_tar.extractfile(member).read()
                    if member.name == "manifest.json":
                        value = json.loads(payload)
                        value["manifest"]["advisory_count"] = 1
                        payload = json.dumps(value, sort_keys=True).encode()
                        member.size = len(payload)
                    target_tar.addfile(member, io.BytesIO(payload))
            with self.assertRaises(Exception):
                import_air_gap_bundle(tampered, root / "target.sqlite")
            self.assertFalse((root / "target.sqlite").exists())
