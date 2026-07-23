import unittest

from src.vulnerability.versions import compare_rpm_version


class TestP1RpmComparator(unittest.TestCase):
    def test_epoch_release_and_tilde_ordering(self):
        self.assertGreater(compare_rpm_version("1:2.0-1", "2.0-9"), 0)
        self.assertLess(compare_rpm_version("2.0~rc1-1", "2.0-1"), 0)
        self.assertLess(compare_rpm_version("2.0-1", "2.0-2"), 0)

    def test_invalid_rpm_version_fails_closed(self):
        with self.assertRaises(ValueError):
            compare_rpm_version("1::2", "1.0")
