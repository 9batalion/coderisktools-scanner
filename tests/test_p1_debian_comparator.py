import unittest

from src.vulnerability.versions import compare_debian_version


class TestP1DebianComparator(unittest.TestCase):
    def test_epoch_and_tilde_ordering(self):
        self.assertGreater(compare_debian_version("1:1.0", "2.0"), 0)
        self.assertLess(compare_debian_version("1.0~rc1-1", "1.0-1"), 0)
        self.assertLess(compare_debian_version("1.0-1", "1.0-2"), 0)

    def test_invalid_debian_version_fails_closed(self):
        with self.assertRaises(ValueError):
            compare_debian_version("1::2", "1.0")
