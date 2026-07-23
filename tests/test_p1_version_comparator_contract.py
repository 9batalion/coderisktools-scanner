import unittest

from src.vulnerability.versions import compare_bounded_version, osv_events_match


class TestP1VersionComparatorContract(unittest.TestCase):
    def test_bounded_numeric_comparator_preserves_existing_ordering(self):
        self.assertLess(compare_bounded_version("1.9.0", "1.10.0"), 0)
        self.assertEqual(compare_bounded_version("v2.0", "2.0"), 0)
        self.assertGreater(compare_bounded_version("2.1.0", "2.0.9"), 0)

    def test_osv_events_match_introduced_fixed_and_last_affected(self):
        fixed = [{"introduced": "0"}, {"fixed": "2.0.0"}]
        last_affected = [{"introduced": "1.0.0"}, {"last_affected": "1.5.0"}]
        self.assertTrue(osv_events_match("1.9.0", fixed))
        self.assertFalse(osv_events_match("2.0.0", fixed))
        self.assertTrue(osv_events_match("1.5.0", last_affected))
        self.assertFalse(osv_events_match("1.5.1", last_affected))


if __name__ == "__main__":
    unittest.main()
