#!/usr/bin/env python3
"""Create and sign a deterministic single-SQLite GitHub Release ZIP."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from scripts.verify_global_osv_vulndb import _read_bounded_regular, verify_global_osv_snapshot
from src.vulnerability.manifest_signing import sign_manifest

_GITHUB_RELEASE_ASSET_LIMIT = 2 * 1024 * 1024 * 1024


def _sha256_stream(stream: Any) -> str:
    digest = hashlib.sha256()
    stream.seek(0)
    while chunk := stream.read(1024 * 1024):
        digest.update(chunk)
    stream.seek(0)
    return "sha256:" + digest.hexdigest()


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino, left.st_size) == (right.st_dev, right.st_ino, right.st_size)


def _write_temp(parent: Path, prefix: str, content: bytes) -> Path:
    descriptor, name = tempfile.mkstemp(prefix=prefix, suffix=".tmp", dir=str(parent))
    path = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        return path
    except BaseException:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise


def _link_verified(source: Path, destination: Path) -> None:
    descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        identity = os.fstat(descriptor)
        os.link(source, destination, follow_symlinks=False)
        if not _same_file(identity, os.stat(destination, follow_symlinks=False)):
            destination.unlink()
            raise OSError("release artifact identity changed during publication")
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _read_private_key(path: Path) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_size != 32:
            raise ValueError("Ed25519 private key must be one 32-byte regular file")
        key = os.read(descriptor, 33)
        if len(key) != 32:
            raise ValueError("Ed25519 private key changed while being read")
        return key
    finally:
        os.close(descriptor)


def package_global_osv_release(
    database: Path,
    build_manifest_path: Path,
    zip_output: Path,
    release_manifest_output: Path,
    signature_output: Path,
    private_key_path: Path,
    *,
    key_id: str,
    minimum_records: int = 800_000,
) -> dict[str, Any]:
    output_parent = zip_output.parent
    ready_output = zip_output.with_suffix(zip_output.suffix + ".ready.json")
    if len({path.parent.resolve() for path in (zip_output, release_manifest_output, signature_output, ready_output)}) != 1:
        raise ValueError("release outputs must share one directory")
    for candidate in (zip_output, release_manifest_output, signature_output, ready_output):
        if candidate.exists() or candidate.is_symlink():
            raise FileExistsError(f"refusing to overwrite release artifact: {candidate}")
    output_parent.mkdir(parents=True, exist_ok=True)
    database_descriptor = os.open(database, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    temporary_zip: Path | None = None
    temporary_manifest: Path | None = None
    temporary_signature: Path | None = None
    temporary_ready: Path | None = None
    published: list[Path] = []
    try:
        database_identity = os.fstat(database_descriptor)
        if not stat.S_ISREG(database_identity.st_mode):
            raise ValueError("database must be a regular non-symlink file")
        manifest_raw = _read_bounded_regular(build_manifest_path, "build manifest")
        manifest_identity = os.stat(build_manifest_path, follow_symlinks=False)
        private_key = _read_private_key(private_key_path)
        verify_global_osv_snapshot(database, build_manifest_path, minimum_records=minimum_records)
        if not _same_file(database_identity, os.stat(database, follow_symlinks=False)):
            raise OSError("database changed during release verification")
        if manifest_raw != _read_bounded_regular(build_manifest_path, "build manifest") or not _same_file(manifest_identity, os.stat(build_manifest_path, follow_symlinks=False)):
            raise OSError("build manifest changed during release verification")
        manifest = json.loads(manifest_raw)
        with os.fdopen(os.dup(database_descriptor), "rb") as pinned_database:
            if _sha256_stream(pinned_database) != manifest.get("database_sha256"):
                raise ValueError("pinned database does not match the verified build manifest")
        member = database.name
        zip_descriptor, zip_name = tempfile.mkstemp(prefix=f".{zip_output.name}.", suffix=".tmp", dir=str(output_parent))
        os.close(zip_descriptor)
        temporary_zip = Path(zip_name)
        temporary_zip.unlink()
        with zipfile.ZipFile(temporary_zip, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9, allowZip64=True) as archive:
            info = zipfile.ZipInfo(member, date_time=(2026, 7, 23, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.file_size = database_identity.st_size
            with os.fdopen(os.dup(database_descriptor), "rb") as source, archive.open(info, "w", force_zip64=True) as target:
                source.seek(0)
                while chunk := source.read(1024 * 1024):
                    target.write(chunk)
        if not _same_file(database_identity, os.fstat(database_descriptor)):
            raise OSError("database changed while the release ZIP was created")
        asset_bytes = temporary_zip.stat().st_size
        if asset_bytes > _GITHUB_RELEASE_ASSET_LIMIT:
            raise ValueError("SQLite ZIP exceeds the 2 GiB GitHub Release asset limit")
        zip_read_descriptor = os.open(
            temporary_zip,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(zip_read_descriptor)
            with os.fdopen(os.dup(zip_read_descriptor), "rb") as stream:
                asset_sha256 = _sha256_stream(stream)
        finally:
            os.close(zip_read_descriptor)
        manifest.update({"archive_member": member, "asset_bytes": asset_bytes, "asset_sha256": asset_sha256})
        manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
        envelope = sign_manifest(manifest, key_id, private_key)
        signature_bytes = (json.dumps(envelope, indent=2, sort_keys=True) + "\n").encode("utf-8")
        ready = {
            "schema": "coderisktools.vulnerability.github-release-ready.v1",
            "snapshot_id": manifest["snapshot_id"],
            "asset": {"name": zip_output.name, "bytes": asset_bytes, "sha256": asset_sha256},
            "manifest": {"name": release_manifest_output.name, "sha256": "sha256:" + hashlib.sha256(manifest_bytes).hexdigest()},
            "signature": {"name": signature_output.name, "sha256": "sha256:" + hashlib.sha256(signature_bytes).hexdigest()},
        }
        ready_bytes = (json.dumps(ready, indent=2, sort_keys=True) + "\n").encode("utf-8")
        temporary_manifest = _write_temp(output_parent, f".{release_manifest_output.name}.", manifest_bytes)
        temporary_signature = _write_temp(output_parent, f".{signature_output.name}.", signature_bytes)
        temporary_ready = _write_temp(output_parent, f".{ready_output.name}.", ready_bytes)
        _link_verified(temporary_signature, signature_output)
        published.append(signature_output)
        _link_verified(temporary_manifest, release_manifest_output)
        published.append(release_manifest_output)
        _link_verified(temporary_zip, zip_output)
        published.append(zip_output)
        _fsync_directory(output_parent)
        _link_verified(temporary_ready, ready_output)
        published.append(ready_output)
        _fsync_directory(output_parent)
        for temporary in (temporary_zip, temporary_manifest, temporary_signature, temporary_ready):
            temporary.unlink()
        _fsync_directory(output_parent)
        return {
            "asset": str(zip_output),
            "asset_bytes": asset_bytes,
            "asset_sha256": asset_sha256,
            "database_bytes": manifest["database_bytes"],
            "database_sha256": manifest["database_sha256"],
            "manifest": str(release_manifest_output),
            "ready": str(ready_output),
            "signature": str(signature_output),
            "signing_key_id": key_id,
        }
    except BaseException:
        for candidate in reversed(published):
            try:
                candidate.unlink()
            except FileNotFoundError:
                pass
        for temporary in (temporary_zip, temporary_manifest, temporary_signature, temporary_ready):
            if temporary is not None:
                try:
                    temporary.unlink()
                except FileNotFoundError:
                    pass
        raise
    finally:
        os.close(database_descriptor)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--build-manifest", type=Path, required=True)
    parser.add_argument("--zip-output", type=Path, required=True)
    parser.add_argument("--release-manifest-output", type=Path, required=True)
    parser.add_argument("--signature-output", type=Path, required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--key-id", default="coderisktools-vulndb-2026")
    parser.add_argument("--minimum-records", type=int, default=800_000)
    args = parser.parse_args()
    report = package_global_osv_release(
        args.database,
        args.build_manifest,
        args.zip_output,
        args.release_manifest_output,
        args.signature_output,
        args.private_key,
        key_id=args.key_id,
        minimum_records=args.minimum_records,
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
