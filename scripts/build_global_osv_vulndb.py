#!/usr/bin/env python3
"""Build a staged, global-OSV SQLite snapshot without expanding the ZIP."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import tempfile
from pathlib import Path
from typing import Any

from src.vulnerability.database import VulnerabilityDatabase
from src.vulnerability.full_snapshot import import_osv_zip

_SOURCE_MANIFEST_LIMIT = 1024 * 1024


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _sha256_descriptor(descriptor: int) -> str:
    digest = hashlib.sha256()
    os.lseek(descriptor, 0, os.SEEK_SET)
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return "sha256:" + digest.hexdigest()


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino, left.st_size) == (right.st_dev, right.st_ino, right.st_size)


def _link_verified(source: Path, destination: Path) -> None:
    descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        identity = os.fstat(descriptor)
        os.link(source, destination, follow_symlinks=False)
        if not _same_file(identity, os.stat(destination, follow_symlinks=False)):
            destination.unlink()
            raise OSError("published artifact identity changed during no-overwrite link")
    finally:
        os.close(descriptor)


def _read_regular_json(path: Path) -> dict[str, Any]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_size <= 0 or file_stat.st_size > _SOURCE_MANIFEST_LIMIT:
            raise ValueError("source manifest must be a bounded regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(_SOURCE_MANIFEST_LIMIT + 1)
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise ValueError("source manifest must be a JSON object")
        return payload
    finally:
        os.close(descriptor)


def _write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def _write_private_temp(parent: Path, prefix: str, payload: bytes) -> Path:
    fd, name = tempfile.mkstemp(prefix=prefix, suffix=".tmp", dir=str(parent))
    path = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        return path
    except BaseException:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def build_global_osv_snapshot(
    archive: Path,
    source_manifest: Path,
    output: Path,
    manifest_output: Path,
    sha256_output: Path,
    *,
    snapshot_id: str,
    maximum_database_bytes: int = 8_500_000_000,
    reserve_free_bytes: int = 3_000_000_000,
    max_import_errors: int = 0,
) -> dict[str, Any]:
    ready_output = output.with_suffix(output.suffix + ".ready.json")
    if len({output.parent.resolve(), manifest_output.parent.resolve(), sha256_output.parent.resolve()}) != 1:
        raise ValueError("database, manifest, and checksum must share one publication directory")
    if not snapshot_id or len(snapshot_id) > 128:
        raise ValueError("snapshot_id is required and must be bounded")
    if maximum_database_bytes <= 0 or reserve_free_bytes <= 0 or max_import_errors < 0:
        raise ValueError("build limits are invalid")
    output.parent.mkdir(parents=True, exist_ok=True)
    for path in (output, manifest_output, sha256_output, ready_output):
        if path.exists() or path.is_symlink():
            raise FileExistsError(f"refusing to overwrite output: {path}")
    source = _read_regular_json(source_manifest)
    expected_digest = source.get("sha256")
    expected_records = source.get("records")
    expected_uncompressed = source.get("uncompressed_bytes")
    if (
        not isinstance(expected_digest, str)
        or not expected_digest.startswith("sha256:")
        or len(expected_digest) != 71
        or type(expected_records) is not int
        or expected_records <= 0
        or type(expected_uncompressed) is not int
        or expected_uncompressed <= 0
    ):
        raise ValueError("source manifest lacks pinned digest/count/size")
    required_free = maximum_database_bytes + reserve_free_bytes
    free_bytes = shutil.disk_usage(output.parent).free
    if free_bytes < required_free:
        raise OSError(f"insufficient free disk space: {free_bytes} < {required_free}")
    fd, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", suffix=".tmp", dir=str(output.parent))
    os.close(fd)
    temporary = Path(temporary_name)
    temporary.unlink()
    temporary_manifest: Path | None = None
    temporary_sha: Path | None = None
    temporary_ready: Path | None = None
    published: list[Path] = []
    progress_path = output.with_suffix(output.suffix + ".progress.json")
    error_path = output.with_suffix(output.suffix + ".error.json")
    try:
        def progress(members_seen: int, advisories_imported: int) -> None:
            database_bytes = temporary.stat().st_size if temporary.exists() else 0
            current_free = shutil.disk_usage(output.parent).free
            if database_bytes > maximum_database_bytes:
                raise OSError("SQLite database exceeded the configured byte limit")
            if current_free < reserve_free_bytes:
                raise OSError("free disk reserve was exhausted during build")
            _write_json_atomic(progress_path, {
                "advisories_imported": advisories_imported,
                "database_bytes": database_bytes,
                "free_bytes": current_free,
                "members_seen": members_seen,
                "snapshot_id": snapshot_id,
                "state": "building",
            })

        with VulnerabilityDatabase(str(temporary)) as database:
            database.connection.execute("PRAGMA journal_mode=OFF")
            database.connection.execute("PRAGMA synchronous=OFF")
            database.connection.execute("PRAGMA temp_store=FILE")
            database.connection.execute("PRAGMA cache_size=-65536")
            report = import_osv_zip(
                database,
                archive,
                expected_archive_sha256=expected_digest,
                expected_payload_members=expected_records,
                expected_uncompressed_bytes=expected_uncompressed,
                max_errors=max_import_errors,
                source_record_mode="digest-only",
                progress=progress,
            )
            if report.error_count > max_import_errors:
                raise ValueError(f"OSV import errors exceeded limit: {report.error_count} > {max_import_errors}")
            database.correlate_aliases()
            advisory_count = database.advisory_count()
            source_record_count = int(database.connection.execute(
                "SELECT COUNT(*) FROM source_records WHERE source_id = 'osv'"
            ).fetchone()[0])
            if not (
                report.members_seen == expected_records
                and report.advisories_imported == expected_records
                and advisory_count == expected_records
                and source_record_count == expected_records
            ):
                raise ValueError("OSV completeness gate failed for members/advisories/source records")
            database.connection.execute(
                "INSERT INTO source_snapshots "
                "(snapshot_id, source_id, content_digest, observed_at, record_count, status, metadata_json) "
                "VALUES (?, 'osv-global', ?, NULL, ?, 'complete', ?)",
                (
                    snapshot_id,
                    expected_digest,
                    report.advisories_imported,
                    json.dumps({
                        "archive_bytes": report.archive_bytes,
                        "declared_uncompressed_bytes": report.declared_uncompressed_bytes,
                        "source_record_mode": "digest-only",
                        "url": source.get("url"),
                    }, sort_keys=True, separators=(",", ":")),
                ),
            )
            database.connection.execute(
                "INSERT INTO quality_metrics(snapshot_id, metric_name, metric_value, details_json) VALUES (?, 'import_errors', ?, '{}')",
                (snapshot_id, float(report.error_count)),
            )
            database.connection.execute(
                "INSERT INTO quality_metrics(snapshot_id, metric_name, metric_value, details_json) VALUES (?, 'unmapped_affected_entries', ?, ?)",
                (snapshot_id, float(report.unmapped_affected_entries), json.dumps({"reason": "OSV affected entry has no package ecosystem/name"}, sort_keys=True)),
            )
            database.connection.commit()
            integrity = database.connection.execute("PRAGMA integrity_check").fetchone()[0]
            foreign_key_errors = len(database.connection.execute("PRAGMA foreign_key_check").fetchall())
            if integrity != "ok" or foreign_key_errors:
                raise ValueError("SQLite integrity or foreign-key verification failed")
            sources = {
                "osv-global": {
                    "archive_bytes": report.archive_bytes,
                    "declared_uncompressed_bytes": report.declared_uncompressed_bytes,
                    "members_seen": report.members_seen,
                    "records": report.advisories_imported,
                    "sha256": expected_digest,
                    "status": "complete",
                    "unmapped_affected_entries": report.unmapped_affected_entries,
                    "url": source.get("url"),
                }
            }
            provenance = {
                "profile": "global-osv",
                "completeness": "full-osv-source",
                "production_full_database": False,
                "snapshot_id": snapshot_id,
                "source_digest": expected_digest,
                "source_record_mode": "digest-only",
                "sources": sources,
            }
            manifest = database.build_compact_snapshot_manifest(provenance)
            manifest.update(provenance)
            manifest["quality"] = {
                "foreign_key_errors": foreign_key_errors,
                "import_errors": report.error_count,
                "integrity_check": integrity,
                "unmapped_affected_entries": report.unmapped_affected_entries,
            }
            database.stage_snapshot(snapshot_id, expected_digest, manifest)
        database_descriptor = os.open(
            temporary,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            database_identity = os.fstat(database_descriptor)
            database_bytes = database_identity.st_size
            current_free = shutil.disk_usage(output.parent).free
            if database_bytes > maximum_database_bytes or current_free < reserve_free_bytes:
                raise OSError("final SQLite size/free-space gate failed")
            os.fsync(database_descriptor)
            database_digest = _sha256_descriptor(database_descriptor)
            manifest["database_bytes"] = database_bytes
            manifest["database_sha256"] = database_digest
            manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
            sha_bytes = f"{database_digest.removeprefix('sha256:')}  {output.name}\n".encode("ascii")
            ready = {
                "schema": "coderisktools.vulnerability.release-set-ready.v1",
                "snapshot_id": snapshot_id,
                "database": {"name": output.name, "bytes": database_bytes, "sha256": database_digest},
                "manifest": {"name": manifest_output.name, "sha256": "sha256:" + hashlib.sha256(manifest_bytes).hexdigest()},
                "checksum": {"name": sha256_output.name, "sha256": "sha256:" + hashlib.sha256(sha_bytes).hexdigest()},
            }
            ready_bytes = (json.dumps(ready, indent=2, sort_keys=True) + "\n").encode("utf-8")
            temporary_manifest = _write_private_temp(output.parent, f".{manifest_output.name}.", manifest_bytes)
            temporary_sha = _write_private_temp(output.parent, f".{sha256_output.name}.", sha_bytes)
            temporary_ready = _write_private_temp(output.parent, f".{ready_output.name}.", ready_bytes)
            _link_verified(temporary_manifest, manifest_output)
            published.append(manifest_output)
            _link_verified(temporary_sha, sha256_output)
            published.append(sha256_output)
            os.link(temporary, output, follow_symlinks=False)
            if not _same_file(database_identity, os.stat(output, follow_symlinks=False)):
                output.unlink()
                raise OSError("database identity changed between verification and publication")
            published.append(output)
            _link_verified(temporary_ready, ready_output)
            published.append(ready_output)
            _fsync_directory(output.parent)
        finally:
            os.close(database_descriptor)
        for path in (temporary, temporary_manifest, temporary_sha, temporary_ready):
            path.unlink()
        if progress_path.exists():
            progress_path.unlink()
        if error_path.exists():
            error_path.unlink()
        return manifest
    except BaseException as exc:
        for path in reversed(published):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        for path in (temporary, temporary_manifest, temporary_sha, temporary_ready):
            if path is not None:
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
        _write_json_atomic(error_path, {"error": f"{type(exc).__name__}: {exc}", "snapshot_id": snapshot_id, "state": "rejected"})
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--source-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest-output", type=Path, required=True)
    parser.add_argument("--sha256-output", type=Path, required=True)
    parser.add_argument("--snapshot-id", required=True)
    parser.add_argument("--max-import-errors", type=int, default=0)
    args = parser.parse_args()
    manifest = build_global_osv_snapshot(
        args.archive,
        args.source_manifest,
        args.output,
        args.manifest_output,
        args.sha256_output,
        snapshot_id=args.snapshot_id,
        max_import_errors=args.max_import_errors,
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
