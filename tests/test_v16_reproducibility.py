import tempfile
import unittest
from pathlib import Path

from src.vulnerability.release import reproducibility_report


class TestV16Reproducibility(unittest.TestCase):
    def test_identical_artifact_sets_are_reproducible(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "manifest.json").write_text('{"version":1}\n', encoding="utf-8")
            (root / "snapshot.sqlite").write_bytes(b"snapshot")
            report = reproducibility_report([root / "manifest.json", root / "snapshot.sqlite"], [root / "manifest.json", root / "snapshot.sqlite"])
            self.assertTrue(report["reproducible"])
            self.assertEqual(report["failed"], [])

    def test_changed_artifact_is_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first" / "artifact.bin"
            second = root / "second" / "artifact.bin"
            first.parent.mkdir()
            second.parent.mkdir()
            first.write_bytes(b"one")
            second.write_bytes(b"two")
            report = reproducibility_report([first], [second])
            self.assertFalse(report["reproducible"])
            self.assertIn("digest_mismatch", report["failed"])
