import hashlib
import json
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from scripts.build_global_osv_vulndb import build_global_osv_snapshot
from scripts.verify_global_osv_vulndb import verify_global_osv_snapshot
from src.vulnerability.database import VulnerabilityDatabase
from src.vulnerability.full_snapshot import import_osv_zip, validate_zip_central_directory
from src.vulnerability.models import Component


class GlobalOsvSnapshotTests(unittest.TestCase):
    @staticmethod
    def _record(identifier: str, package: str, fixed: str = "2.0.0") -> dict:
        return {
            "id": identifier,
            "aliases": ["CVE-2026-0001"] if identifier.endswith("1") else [],
            "summary": "real source summary",
            "details": "source-backed details",
            "modified": "2026-07-23T00:00:00Z",
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": package},
                    "versions": ["1.0.0"],
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}],
                }
            ],
        }

    def test_digest_only_source_evidence_keeps_hash_and_matching_data(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "database.sqlite"
            record = self._record("OSV-1", "example")
            with VulnerabilityDatabase(str(database_path)) as database:
                stats = database.import_osv_records([record], source_record_mode="digest-only")
                self.assertEqual(stats.advisories_imported, 1)
                evidence = database.connection.execute(
                    "SELECT content_digest, record_json FROM source_records WHERE native_record_id = 'OSV-1'"
                ).fetchone()
                self.assertTrue(evidence["content_digest"].startswith("sha256:"))
                marker = json.loads(evidence["record_json"])
                self.assertEqual(marker, {"_payload_omitted": True, "id": "OSV-1"})
                matches = database.match_component(Component("pypi", "example", "1.0.0"))
                self.assertEqual([match.advisory_id for match in matches], ["OSV-1"])

    def test_large_batch_can_defer_global_alias_correlation(self):
        with VulnerabilityDatabase(":memory:") as database:
            with patch.object(database, "correlate_aliases", wraps=database.correlate_aliases) as correlate:
                stats = database.import_osv_records(
                    [self._record("OSV-1", "example")],
                    source_record_mode="digest-only",
                    correlate_aliases=False,
                )
                self.assertEqual(stats.advisories_imported, 1)
                correlate.assert_not_called()
                self.assertEqual(database.alias_count(), 0)

    def test_package_less_git_advisory_is_retained_as_unmapped_source_evidence(self):
        record = {
            "id": "CVE-2026-9999",
            "summary": "GIT-only advisory",
            "affected": [{"ranges": [{"type": "GIT", "repo": "https://example.invalid/repo", "events": [{"introduced": "0"}]}]}],
        }
        with VulnerabilityDatabase(":memory:") as database:
            stats = database.import_osv_records([record], source_record_mode="digest-only")
            self.assertEqual(stats.advisories_imported, 1)
            self.assertEqual(stats.affected_packages_imported, 0)
            self.assertEqual(stats.unmapped_affected_entries, 1)
            self.assertEqual(stats.errors, ())
            self.assertEqual(database.advisory_count(), 1)

    def test_compact_manifest_is_bounded_and_detects_content_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "database.sqlite"
            with VulnerabilityDatabase(str(database_path)) as database:
                database.import_osv_records([self._record("OSV-1", "example")], source_record_mode="digest-only")
                first = database.build_compact_snapshot_manifest()
                self.assertEqual(first["manifest_format"], "compact-v1")
                self.assertNotIn("advisories", first)
                self.assertEqual(first["advisory_count"], 1)
                database.connection.execute("UPDATE advisories SET summary = 'changed' WHERE id = 'OSV-1'")
                database.connection.commit()
                second = database.build_compact_snapshot_manifest()
                self.assertNotEqual(first["content_digest"], second["content_digest"])

    def test_compact_snapshot_can_be_staged_and_quality_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "database.sqlite"
            with VulnerabilityDatabase(str(database_path)) as database:
                database.import_osv_records([self._record("OSV-1", "example")], source_record_mode="digest-only")
                provenance = {
                    "profile": "global-osv",
                    "completeness": "full-osv-source",
                    "production_full_database": False,
                    "snapshot_id": "global-osv-test",
                    "source_digest": "sha256:" + "a" * 64,
                    "source_record_mode": "digest-only",
                    "sources": {"osv-global": {"sha256": "sha256:" + "a" * 64}},
                }
                manifest = database.build_compact_snapshot_manifest(provenance)
                manifest.update(provenance)
                database.stage_snapshot("global-osv-test", "sha256:" + "a" * 64, manifest)
                quality = database.snapshot_quality_gate("global-osv-test")
                self.assertTrue(quality["healthy"], quality)
                database.connection.execute(
                    "UPDATE snapshots SET source_digest = ? WHERE snapshot_id = 'global-osv-test'",
                    ("sha256:" + "b" * 64,),
                )
                database.connection.commit()
                tampered = database.snapshot_quality_gate("global-osv-test")
                self.assertFalse(tampered["healthy"])
                self.assertIn("manifest:source_digest", tampered["issues"])

    def test_zip_import_is_streamed_and_reports_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_path = root / "osv.zip"
            database_path = root / "database.sqlite"
            with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("PyPI/OSV-1.json", json.dumps(self._record("OSV-1", "example")))
                archive.writestr("npm/OSV-2.json", json.dumps(self._record("OSV-2", "example-js")))
            with VulnerabilityDatabase(str(database_path)) as database:
                report = import_osv_zip(database, archive_path, batch_records=1, source_record_mode="digest-only")
                self.assertEqual(report.members_seen, 2)
                self.assertEqual(report.advisories_imported, 2)
                self.assertEqual(report.errors, ())
                self.assertTrue(report.archive_sha256.startswith("sha256:"))
                self.assertEqual(database.advisory_count(), 2)

    def test_builder_publishes_only_a_staged_verified_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_path = root / "osv.zip"
            source_manifest = root / "source.json"
            output = root / "global.sqlite"
            manifest_output = root / "global.manifest.json"
            sha_output = root / "global.sha256"
            with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("PyPI/OSV-1.json", json.dumps(self._record("OSV-1", "example")))
            digest = "sha256:" + hashlib.sha256(archive_path.read_bytes()).hexdigest()
            with zipfile.ZipFile(archive_path) as archive:
                uncompressed = sum(info.file_size for info in archive.infolist())
            source_manifest.write_text(json.dumps({"sha256": digest, "url": "https://example.invalid/osv.zip", "records": 1, "uncompressed_bytes": uncompressed}))
            manifest = build_global_osv_snapshot(
                archive_path,
                source_manifest,
                output,
                manifest_output,
                sha_output,
                snapshot_id="global-osv-test",
                maximum_database_bytes=100_000_000,
                reserve_free_bytes=1_000_000,
            )
            self.assertTrue(output.is_file())
            ready_output = output.with_suffix(output.suffix + ".ready.json")
            self.assertTrue(ready_output.is_file())
            self.assertEqual(manifest["completeness"], "full-osv-source")
            self.assertFalse(manifest["production_full_database"])
            verification = verify_global_osv_snapshot(output, manifest_output, minimum_records=1)
            self.assertEqual(verification["state"], "staged")
            self.assertEqual(verification["integrity_check"], "ok")
            with VulnerabilityDatabase(str(output)) as database:
                status = database.snapshot_status("global-osv-test")
                self.assertEqual(status["state"], "staged")
                self.assertIsNone(database.active_snapshot())
                self.assertTrue(database.snapshot_quality_gate("global-osv-test")["healthy"])
            ready_output.unlink()
            with self.assertRaises(ValueError):
                verify_global_osv_snapshot(output, manifest_output, minimum_records=1)

    def test_zip_import_rejects_compressed_archive_over_limit_before_import(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_path = root / "osv.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("OSV-1.json", json.dumps(self._record("OSV-1", "example")))
            with VulnerabilityDatabase(":memory:") as database:
                with self.assertRaises(ValueError):
                    import_osv_zip(database, archive_path, max_archive_bytes=1)
                self.assertEqual(database.advisory_count(), 0)

    def test_central_directory_member_limit_is_checked_before_zipfile_open(self):
        with tempfile.TemporaryDirectory() as directory:
            archive_path = Path(directory) / "osv.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("OSV-1.json", b"{}")
            raw = bytearray(archive_path.read_bytes())
            eocd = raw.rfind(b"PK\x05\x06")
            struct.pack_into("<H", raw, eocd + 8, 2)
            struct.pack_into("<H", raw, eocd + 10, 2)
            archive_path.write_bytes(raw)
            with archive_path.open("rb") as stream:
                with self.assertRaises(ValueError):
                    validate_zip_central_directory(stream, max_members=1)

    def test_non_sentinel_zip64_metadata_cannot_bypass_member_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            archive_path = Path(directory) / "osv.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("OSV-1.json", b"{}")
            raw = archive_path.read_bytes()
            eocd = raw.rfind(b"PK\x05\x06")
            legacy = struct.unpack_from("<4s4H2LH", raw, eocd)
            central_bytes, central_offset = legacy[5], legacy[6]
            zip64_record = struct.pack(
                "<4sQ2H2L4Q",
                b"PK\x06\x06", 44, 45, 45, 0, 0, 2, 2, central_bytes, central_offset,
            )
            locator = struct.pack("<4sLQL", b"PK\x06\x07", 0, eocd, 1)
            archive_path.write_bytes(raw[:eocd] + zip64_record + locator + raw[eocd:])
            with archive_path.open("rb") as stream:
                with self.assertRaises(ValueError):
                    validate_zip_central_directory(stream, max_members=1)

    def test_builder_rejects_duplicate_advisory_ids_without_publishing_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_path = root / "osv.zip"
            source_manifest = root / "source.json"
            output = root / "global.sqlite"
            manifest_output = root / "global.manifest.json"
            sha_output = root / "global.sha256"
            record = self._record("OSV-1", "example")
            with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("a.json", json.dumps(record))
                archive.writestr("b.json", json.dumps(record))
            with zipfile.ZipFile(archive_path) as archive:
                uncompressed = sum(info.file_size for info in archive.infolist())
            digest = "sha256:" + hashlib.sha256(archive_path.read_bytes()).hexdigest()
            source_manifest.write_text(json.dumps({"sha256": digest, "records": 2, "uncompressed_bytes": uncompressed}))
            with self.assertRaises(ValueError):
                build_global_osv_snapshot(
                    archive_path,
                    source_manifest,
                    output,
                    manifest_output,
                    sha_output,
                    snapshot_id="global-osv-duplicate",
                    maximum_database_bytes=100_000_000,
                    reserve_free_bytes=1_000_000,
                )
            self.assertFalse(output.exists())
            self.assertFalse(manifest_output.exists())
            self.assertFalse(sha_output.exists())

    def test_zip_import_rejects_directory_only_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_path = root / "osv.zip"
            database_path = root / "database.sqlite"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("PyPI/", b"")
            with VulnerabilityDatabase(str(database_path)) as database:
                with self.assertRaises(ValueError):
                    import_osv_zip(database, archive_path)
                self.assertEqual(database.advisory_count(), 0)

    def test_zip_import_rejects_malformed_record_at_error_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_path = root / "osv.zip"
            database_path = root / "database.sqlite"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("PyPI/OSV-bad.json", "{")
            with VulnerabilityDatabase(str(database_path)) as database:
                with self.assertRaises(ValueError):
                    import_osv_zip(database, archive_path, max_errors=0)
                self.assertEqual(database.advisory_count(), 0)

    def test_zip_import_rejects_traversal_before_import(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_path = root / "osv.zip"
            database_path = root / "database.sqlite"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("../escape.json", json.dumps(self._record("OSV-1", "example")))
            with VulnerabilityDatabase(str(database_path)) as database:
                with self.assertRaises(ValueError):
                    import_osv_zip(database, archive_path)
                self.assertEqual(database.advisory_count(), 0)


if __name__ == "__main__":
    unittest.main()
