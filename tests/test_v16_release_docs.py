from pathlib import Path
import unittest


class TestV16ReleaseDocumentation(unittest.TestCase):
    def test_release_boundary_documents_exist_and_state_limits(self):
        root = Path(__file__).parents[1] / "docs"
        release = (root / "RELEASE-NOTES-3.0.1.md").read_text(encoding="utf-8")
        limits = (root / "KNOWN-LIMITATIONS.md").read_text(encoding="utf-8")
        self.assertIn("# CodeRiskTools Scanner 3.0.1", release)
        self.assertIn("# Known limitations", limits)
        self.assertIn("bounded", limits)
        self.assertIn("not a security audit", limits)
        self.assertIn("does not execute", release)
