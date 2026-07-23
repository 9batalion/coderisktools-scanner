import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.vulnerability.bootstrap import (
    activate_seed_database,
    validate_signed_release_manifest,
    verify_asset_sha256,
)


class SeedBootstrapTests(unittest.TestCase):
    def test_verify_asset_sha256_accepts_exact_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "seed.sqlite"
            path.write_bytes(b"real-seed-bytes")
            digest = "sha256:" + hashlib.sha256(b"real-seed-bytes").hexdigest()
            self.assertEqual(verify_asset_sha256(path, digest), digest)

    def test_verify_asset_sha256_rejects_tampering(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "seed.sqlite"
            path.write_bytes(b"tampered")
            with self.assertRaises(ValueError):
                verify_asset_sha256(path, "sha256:" + "0" * 64)

    def test_verify_asset_sha256_rejects_malformed_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "seed.sqlite"
            path.write_bytes(b"seed")
            for value in ("sha256:abc", "sha256:" + "A" * 64, "md5:" + "0" * 32):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    verify_asset_sha256(path, value)

    def test_signed_release_manifest_must_match_detached_manifest(self):
        manifest = json.loads((Path(__file__).parents[1] / "data/vulnerability-seed/manifest.json").read_text(encoding="utf-8"))
        envelope = {"key_id": "coderisktools-seed-2026", "manifest": manifest}
        with patch("src.vulnerability.bootstrap.verify_manifest", return_value=dict(manifest)):
            actual = validate_signed_release_manifest(manifest, envelope, {"coderisktools-seed-2026": b"k" * 32})
        self.assertEqual(actual, manifest)
        tampered = dict(manifest)
        tampered["advisory_count"] += 1
        with patch("src.vulnerability.bootstrap.verify_manifest", return_value=dict(manifest)):
            with self.assertRaises(ValueError):
                validate_signed_release_manifest(tampered, envelope, {"coderisktools-seed-2026": b"k" * 32})

    def test_seed_activation_is_explicit_and_profile_bound(self):
        source_root = Path(__file__).parents[1] / "data/vulnerability-seed"
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "seed.sqlite"
            shutil.copy2(source_root / "seed-vulndb.sqlite", database)
            manifest = json.loads((source_root / "manifest.json").read_text(encoding="utf-8"))
            state = activate_seed_database(database, manifest, apply=False)
            self.assertEqual(state["state"], "activation_planned")
            state = activate_seed_database(database, manifest, apply=True)
            self.assertEqual(state["state"], "active")
            self.assertEqual(state["profile"], "seed")


if __name__ == "__main__":
    unittest.main()
