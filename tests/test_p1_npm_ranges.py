import unittest

from src.vulnerability.versions import matches_npm_range


class TestP1NpmRangeContract(unittest.TestCase):
    def test_exact_partial_and_wildcard_ranges(self):
        self.assertTrue(matches_npm_range("1.2.3", "1.2.3"))
        self.assertTrue(matches_npm_range("1.2.9", "1.2"))
        self.assertFalse(matches_npm_range("1.3.0", "1.2"))
        self.assertTrue(matches_npm_range("9.0.0", "*"))

    def test_comparator_and_or_ranges(self):
        self.assertTrue(matches_npm_range("1.5.0", ">=1.0.0 <2.0.0"))
        self.assertFalse(matches_npm_range("2.0.0", ">=1.0.0 <2.0.0"))
        self.assertTrue(matches_npm_range("3.1.0", "<2.0.0 || >=3.0.0"))

    def test_caret_and_tilde_ranges(self):
        self.assertTrue(matches_npm_range("1.2.9", "^1.2.3"))
        self.assertFalse(matches_npm_range("2.0.0", "^1.2.3"))
        self.assertTrue(matches_npm_range("1.2.9", "~1.2.3"))
        self.assertFalse(matches_npm_range("1.3.0", "~1.2.3"))
        self.assertFalse(matches_npm_range("0.0.4", "^0.0.3"))

    def test_invalid_expression_fails_closed(self):
        with self.assertRaises(ValueError):
            matches_npm_range("1.2.3", "not-a-range")


if __name__ == "__main__":
    unittest.main()
