#!/usr/bin/env python3
"""Verify a seed SQLite and its manifest without activation."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.vulnerability.database import VulnerabilityDatabase
from src.vulnerability.seed import validate_seed_manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", required=True)
    parser.add_argument("--manifest", required=True)
    args = parser.parse_args()
    database_path = Path(args.database)
    manifest_path = Path(args.manifest)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    validate_seed_manifest(manifest)
    expected_db = manifest.get("database_sha256")
    actual_db = "sha256:" + hashlib.sha256(database_path.read_bytes()).hexdigest()
    if expected_db != actual_db:
        raise SystemExit(f"database hash mismatch: expected {expected_db}, got {actual_db}")
    with VulnerabilityDatabase.read_only(str(database_path)) as database:
        integrity = database.integrity_check()
        foreign_keys = database.connection.execute("PRAGMA foreign_key_check").fetchall()
        if integrity != "ok" or foreign_keys:
            raise SystemExit(f"database integrity failed: {integrity}, foreign_keys={len(foreign_keys)}")
        actual = database.build_snapshot_manifest()
    for key in ("content_digest", "advisory_count", "affected_package_count"):
        if actual.get(key) != manifest.get(key):
            raise SystemExit(f"manifest mismatch: {key}")
    print(json.dumps({"state": "verified", "profile": "seed", "completeness": "partial", "database_sha256": actual_db, "advisory_count": actual["advisory_count"], "affected_package_count": actual["affected_package_count"]}, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
