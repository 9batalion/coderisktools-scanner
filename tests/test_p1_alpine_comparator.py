import unittest

from src.vulnerability.versions import compare_alpine_version


class TestP1AlpineComparator(unittest.TestCase):
    def test_alpine_revision_and_tilde_ordering(self):
        self.assertLess(compare_alpine_version("1.0-r1", "1.0-r2"), 0)
        self.assertLess(compare_alpine_version("1.0~rc1-r1", "1.0-r1"), 0)

    def test_invalid_alpine_version_fails_closed(self):
        with self.assertRaises(ValueError):
            compare_alpine_version("1::2", "1.0")
