#!/usr/bin/env python3
"""Independently verify a staged global OSV SQLite snapshot."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any

from src.vulnerability.database import VulnerabilityDatabase

_MAX_METADATA_BYTES = 2 * 1024 * 1024


def _read_bounded_regular(path: Path, label: str) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_size <= 0 or file_stat.st_size > _MAX_METADATA_BYTES:
            raise ValueError(f"{label} must be a bounded regular file")
        chunks: list[bytes] = []
        remaining = file_stat.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) != file_stat.st_size or os.read(descriptor, 1):
            raise ValueError(f"{label} changed while being read")
        return data
    finally:
        os.close(descriptor)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def verify_global_osv_snapshot(database_path: Path, manifest_path: Path, *, minimum_records: int = 1) -> dict[str, Any]:
    for path, label in ((database_path, "database"), (manifest_path, "manifest")):
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"{label} must be a regular non-symlink file")
    if minimum_records <= 0:
        raise ValueError("minimum_records must be positive")
    manifest_raw = _read_bounded_regular(manifest_path, "manifest")
    manifest = json.loads(manifest_raw)
    if manifest.get("profile") != "global-osv" or manifest.get("completeness") != "full-osv-source":
        raise ValueError("unexpected global OSV manifest profile")
    if manifest.get("production_full_database") is not False or manifest.get("source_record_mode") != "digest-only":
        raise ValueError("global OSV manifest boundaries are invalid")
    expected_database_digest = manifest.get("database_sha256")
    actual_database_digest = _sha256(database_path)
    if expected_database_digest != actual_database_digest:
        raise ValueError("database SHA-256 mismatch")
    if manifest.get("database_bytes") != database_path.stat().st_size:
        raise ValueError("database size does not match manifest")
    snapshot_id = manifest.get("snapshot_id")
    source = manifest.get("sources", {}).get("osv-global", {})
    if not isinstance(snapshot_id, str) or not snapshot_id:
        raise ValueError("snapshot_id is missing")
    source_records_expected = source.get("records")
    if (
        source.get("status") != "complete"
        or type(source_records_expected) is not int
        or source_records_expected < minimum_records
        or source.get("members_seen") != source_records_expected
        or manifest.get("advisory_count") != source_records_expected
        or manifest.get("source_digest") != source.get("sha256")
        or manifest.get("quality", {}).get("import_errors") != 0
    ):
        raise ValueError("global OSV source record gate failed")
    ready_path = database_path.with_suffix(database_path.suffix + ".ready.json")
    ready_raw = _read_bounded_regular(ready_path, "release ready marker")
    ready = json.loads(ready_raw)
    if ready.get("schema") != "coderisktools.vulnerability.release-set-ready.v1" or ready.get("snapshot_id") != snapshot_id:
        raise ValueError("release ready marker contract mismatch")
    if ready.get("database") != {"name": database_path.name, "bytes": database_path.stat().st_size, "sha256": actual_database_digest}:
        raise ValueError("release ready marker database mismatch")
    manifest_ready = ready.get("manifest", {})
    if manifest_ready.get("name") != manifest_path.name or manifest_ready.get("sha256") != "sha256:" + hashlib.sha256(manifest_raw).hexdigest():
        raise ValueError("release ready marker manifest mismatch")
    checksum_ready = ready.get("checksum", {})
    checksum_name = checksum_ready.get("name")
    if not isinstance(checksum_name, str) or Path(checksum_name).name != checksum_name:
        raise ValueError("release ready marker checksum name is invalid")
    checksum_raw = _read_bounded_regular(database_path.parent / checksum_name, "checksum")
    if checksum_ready.get("sha256") != "sha256:" + hashlib.sha256(checksum_raw).hexdigest():
        raise ValueError("release ready marker checksum mismatch")
    database = VulnerabilityDatabase.read_only(str(database_path))
    try:
        integrity = database.connection.execute("PRAGMA integrity_check").fetchone()[0]
        foreign_key_errors = len(database.connection.execute("PRAGMA foreign_key_check").fetchall())
        if integrity != "ok" or foreign_key_errors:
            raise ValueError("SQLite integrity or foreign-key verification failed")
        provenance = {
            key: manifest[key]
            for key in (
                "completeness", "production_full_database", "profile", "snapshot_id",
                "source_digest", "source_record_mode", "sources",
            )
            if key in manifest
        }
        actual_manifest = database.build_compact_snapshot_manifest(provenance)
        for key in ("content_digest", "advisory_count", "affected_package_count", "table_counts", "provenance_digest"):
            if actual_manifest.get(key) != manifest.get(key):
                raise ValueError(f"compact manifest mismatch: {key}")
        snapshot = database.snapshot_status(snapshot_id)
        quality = database.snapshot_quality_gate(snapshot_id)
        if not quality["healthy"]:
            raise ValueError("stored snapshot quality gate failed")
        if snapshot.get("state") != "staged" or database.active_snapshot() is not None:
            raise ValueError("global OSV snapshot must remain staged and inactive")
        if snapshot.get("source_digest") != source.get("sha256"):
            raise ValueError("snapshot source digest does not match global OSV source")
        non_digest_only = int(database.connection.execute(
            "SELECT COUNT(*) FROM source_records "
            "WHERE json_extract(record_json, '$._payload_omitted') IS NOT 1"
        ).fetchone()[0])
        if non_digest_only:
            raise ValueError("source record evidence mode mismatch")
        source_records = int(database.connection.execute("SELECT COUNT(*) FROM source_records WHERE source_id = 'osv'").fetchone()[0])
        if source_records != source_records_expected or database.advisory_count() != source_records_expected:
            raise ValueError("source record count does not match manifest")
        return {
            "advisory_count": actual_manifest["advisory_count"],
            "affected_package_count": actual_manifest["affected_package_count"],
            "content_digest": actual_manifest["content_digest"],
            "database_bytes": database_path.stat().st_size,
            "database_sha256": actual_database_digest,
            "foreign_key_errors": foreign_key_errors,
            "integrity_check": integrity,
            "profile": manifest["profile"],
            "snapshot_id": snapshot_id,
            "state": snapshot["state"],
        }
    finally:
        database.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--minimum-records", type=int, default=1)
    args = parser.parse_args()
    print(json.dumps(verify_global_osv_snapshot(args.database, args.manifest, minimum_records=args.minimum_records), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
