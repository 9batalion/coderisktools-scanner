"""RED tests for V9f offline vulnerability scan CLI."""

import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from src.vulnerability.database import VulnerabilityDatabase


RECORD = {
    "id": "OSV-V9F-1",
    "aliases": ["CVE-2026-9001"],
    "summary": "V9f fixture",
    "database_specific": {"severity": "high"},
    "affected": [{
        "package": {"ecosystem": "PyPI", "name": "demo"},
        "versions": ["1.0.0"],
    }],
}


class TestV9fOfflineVulnerabilityScanCli(unittest.TestCase):
    def test_scans_against_active_local_db_and_preserves_finding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            db_path = root / "vulnerability.sqlite"
            db = VulnerabilityDatabase(str(db_path))
            db.import_osv_records([RECORD])
            manifest = db.build_snapshot_manifest()
            db.stage_snapshot("snapshot-osv", "sha256:" + "a" * 64, manifest)
            db.activate_snapshot("snapshot-osv")
            db.close()
            (root / "requirements.txt").write_text("demo==1.0.0\n", encoding="utf-8")
            before = sqlite3.connect(db_path).execute("SELECT COUNT(*) FROM matches").fetchone()[0]
            result = subprocess.run(
                [sys.executable, "-m", "src", "vuln", "scan", "--root", str(root), "--database", str(db_path), "--format", "json"],
                capture_output=True,
                text=True,
                check=False,
            )
            after = sqlite3.connect(db_path).execute("SELECT COUNT(*) FROM matches").fetchone()[0]
            self.assertEqual(result.returncode, 1, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["finding_count"], 1)
            self.assertEqual(report["findings"][0]["advisory_id"], "OSV-V9F-1")
            self.assertEqual(report["findings"][0]["snapshot_id"], "snapshot-osv")
            self.assertEqual(before, after)

    def test_requires_active_local_database_and_never_accepts_url(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [sys.executable, "-m", "src", "vuln", "scan", "--root", directory, "--database", "https://example.invalid/db", "--format", "json"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 3)
            self.assertEqual(json.loads(result.stderr)["state"], "rejected")


if __name__ == "__main__":
    unittest.main()
