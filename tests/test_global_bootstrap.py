import hashlib
import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from scripts.build_global_osv_vulndb import build_global_osv_snapshot
from scripts.package_global_osv_release import package_global_osv_release
from src.vulnerability.database import VulnerabilityDatabase
from src.vulnerability.global_bootstrap import (
    _installation_lock,
    _extract_single_database,
    bootstrap_global_osv_asset,
    validate_signed_global_manifest,
)


class GlobalBootstrapTests(unittest.TestCase):
    def test_installation_lock_rejects_parallel_bootstrap(self):
        with tempfile.TemporaryDirectory() as directory:
            lock = Path(directory) / "database.bootstrap.lock"
            with _installation_lock(lock):
                with self.assertRaises(RuntimeError):
                    with _installation_lock(lock):
                        self.fail("parallel lock unexpectedly succeeded")

    def test_database_descriptor_pins_inode_across_path_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database_path = root / "database.sqlite"
            moved_path = root / "moved.sqlite"
            with VulnerabilityDatabase(str(database_path)) as database:
                database.import_osv_records([self._record()], source_record_mode="digest-only")
            descriptor = os.open(database_path, os.O_RDONLY)
            try:
                database_path.rename(moved_path)
                database_path.write_bytes(b"not sqlite")
                with VulnerabilityDatabase.from_file_descriptor(descriptor, readonly=True) as pinned:
                    self.assertEqual(pinned.advisory_count(), 1)
            finally:
                os.close(descriptor)

    @staticmethod
    def _record():
        return {
            "id": "OSV-BOOTSTRAP-1",
            "aliases": ["CVE-2026-1000"],
            "affected": [{
                "package": {"ecosystem": "PyPI", "name": "example"},
                "versions": ["1.0.0"],
            }],
        }

    def test_extracts_exactly_one_digest_bound_sqlite_member(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "database.zip"
            output = root / "database.sqlite"
            payload = b"SQLite bytes"
            with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zipped:
                zipped.writestr("database.sqlite", payload)
            manifest = {
                "archive_member": "database.sqlite",
                "database_bytes": len(payload),
                "database_sha256": "sha256:" + hashlib.sha256(payload).hexdigest(),
            }
            with archive.open("rb") as source, output.open("w+b") as target:
                _extract_single_database(source, target, root, manifest)
            self.assertEqual(output.read_bytes(), payload)

    def test_rejects_zip_with_more_than_one_member(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "database.zip"
            output = root / "database.sqlite"
            with zipfile.ZipFile(archive, "w") as zipped:
                zipped.writestr("database.sqlite", b"db")
                zipped.writestr("extra.txt", b"not allowed")
            manifest = {
                "archive_member": "database.sqlite",
                "database_bytes": 2,
                "database_sha256": "sha256:" + hashlib.sha256(b"db").hexdigest(),
            }
            with self.assertRaises(ValueError):
                with archive.open("rb") as source, output.open("w+b") as target:
                    _extract_single_database(source, target, root, manifest)

    def test_signed_global_manifest_is_profile_bound(self):
        manifest = {
            "asset_sha256": "sha256:" + "a" * 64,
            "archive_member": "database.sqlite",
            "completeness": "full-osv-source",
            "database_bytes": 10,
            "database_sha256": "sha256:" + "b" * 64,
            "manifest_format": "compact-v1",
            "production_full_database": False,
            "profile": "global-osv",
            "snapshot_id": "global-osv-2026-07-23",
        }
        envelope = {"key_id": "global-key"}
        with patch("src.vulnerability.global_bootstrap.verify_manifest", return_value=dict(manifest)):
            actual = validate_signed_global_manifest(manifest, envelope, {"global-key": b"k" * 32})
        self.assertEqual(actual, manifest)

    def test_bootstrap_downloads_zip_verifies_database_and_activates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_zip = root / "source.zip"
            source_manifest = root / "source.json"
            source_database = root / "source.sqlite"
            database_manifest = root / "database.manifest.json"
            database_sha = root / "database.sha256"
            osv_payload = json.dumps(self._record())
            with zipfile.ZipFile(source_zip, "w", compression=zipfile.ZIP_DEFLATED) as zipped:
                zipped.writestr("OSV-BOOTSTRAP-1.json", osv_payload)
            with zipfile.ZipFile(source_zip) as zipped:
                uncompressed = sum(item.file_size for item in zipped.infolist())
            source_manifest.write_text(json.dumps({
                "sha256": "sha256:" + hashlib.sha256(source_zip.read_bytes()).hexdigest(),
                "records": 1,
                "uncompressed_bytes": uncompressed,
            }))
            build_global_osv_snapshot(
                source_zip,
                source_manifest,
                source_database,
                database_manifest,
                database_sha,
                snapshot_id="global-osv-bootstrap-test",
                maximum_database_bytes=100_000_000,
                reserve_free_bytes=1_000_000,
            )
            asset = root / "database.zip"
            release_manifest_path = root / "database.release.manifest.json"
            signature_path = root / "database.sig.json"
            private_key_path = root / "private.key"
            private_key_path.write_bytes(b"k" * 32)
            public_key = b"p" * 32

            def fake_sign(payload, key_id, _private_key):
                return {
                    "schema": "coderisktools.vulnerability.signed-manifest",
                    "version": 1,
                    "key_id": key_id,
                    "manifest": payload,
                    "signature": "test-only-envelope",
                }

            with patch("scripts.package_global_osv_release.sign_manifest", side_effect=fake_sign):
                package_global_osv_release(
                    source_database,
                    database_manifest,
                    asset,
                    release_manifest_path,
                    signature_path,
                    private_key_path,
                    key_id="global-key",
                    minimum_records=1,
                )
            manifest = json.loads(release_manifest_path.read_text())
            envelope = json.loads(signature_path.read_text())

            def metadata_download(url, *_args, **_kwargs):
                return json.dumps(envelope if url.endswith("sig") else manifest).encode()

            def asset_download(_url, destination, _hosts, **_kwargs):
                destination.seek(0)
                destination.truncate(0)
                destination.write(asset.read_bytes())
                destination.flush()
                destination.seek(0)
                return asset.stat().st_size, manifest["asset_sha256"]

            destination = root / "installed.sqlite"
            with (
                patch("src.vulnerability.global_bootstrap._download", side_effect=metadata_download),
                patch("src.vulnerability.global_bootstrap._download_to_file", side_effect=asset_download),
                patch("src.vulnerability.global_bootstrap.verify_manifest", return_value=manifest),
            ):
                result = bootstrap_global_osv_asset(
                    "https://github.com/database.zip",
                    "https://github.com/manifest",
                    "https://github.com/sig",
                    destination,
                    trusted_keys={"global-key": public_key},
                )
            self.assertEqual(result["state"], "active")
            with VulnerabilityDatabase.read_only(str(destination)) as database:
                active = database.active_snapshot()
                self.assertIsNotNone(active)
                self.assertEqual((active or {})["snapshot_id"], "global-osv-bootstrap-test")


if __name__ == "__main__":
    unittest.main()
