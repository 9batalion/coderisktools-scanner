import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.vulnerability.updater import run_full_update


class TestFullUpdatePipeline(unittest.TestCase):
    def test_full_update_builds_staged_snapshot_and_does_not_activate_by_default(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "vuln-db"
            config = Path(directory) / "sources.json"
            config.write_text(json.dumps({"sources": [{"source_id": "osv", "url": "https://osv.dev/feed.json", "allowed_hosts": ["osv.dev"], "format": "osv"}]}), encoding="utf-8")
            with patch("src.vulnerability.updater.fetch_json_artifact") as fetch:
                fetch.return_value.payload = json.dumps([]).encode()
                fetch.return_value.not_modified = False
                fetch.return_value.requested_url = "https://osv.dev/feed.json"
                fetch.return_value.final_url = "https://osv.dev/feed.json"
                fetch.return_value.etag = None
                fetch.return_value.last_modified = None
                fetch.return_value.content_type = "application/json"
                result = run_full_update(config, root)
            self.assertEqual(result["state"], "staged")
            self.assertFalse(result["activated"])
            self.assertTrue((root / "snapshots" / result["snapshot_id"] / "snapshot.sqlite3").is_file())
            self.assertTrue((root / "snapshots" / result["snapshot_id"] / "manifest.json").is_file())
            self.assertFalse((root / "active").exists())
