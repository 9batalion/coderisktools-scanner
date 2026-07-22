import json
import tempfile
import unittest
from pathlib import Path

from src.vulnerability.updater import stage_json_artifacts, verify_staged_artifact


class TestV8MultiSourceStaging(unittest.TestCase):
    def test_stages_sorted_manifest_for_multiple_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            result = stage_json_artifacts(
                [("zsource", b'{"z": 1}'), ("asource", b'[{"a": 1}]')],
                directory,
            )
            self.assertEqual([item["source_id"] for item in result["entries"]], ["asource", "zsource"])
            self.assertEqual(verify_staged_artifact(Path(directory) / "asource.json")["source_id"], "asource")
            manifest = json.loads((Path(directory) / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest, result)

    def test_rejects_duplicate_source_before_writing_any_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "duplicate"):
                stage_json_artifacts([("same", b"{}"), ("same", b"[]")], directory)
            self.assertEqual(list(Path(directory).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
