import unittest

from src.vulnerability.database import VulnerabilityDatabase
from src.vulnerability.models import Component
from src.vulnerability.versions import compare_rubygems_version


class TestP1RubyGemsComparator(unittest.TestCase):
    def test_rubygems_numeric_and_prerelease_ordering(self):
        self.assertEqual(compare_rubygems_version("1.0", "1.0.0"), 0)
        self.assertLess(compare_rubygems_version("1.0.pre", "1.0"), 0)
        self.assertLess(compare_rubygems_version("1.2.9", "1.10.0"), 0)

    def test_rubygems_matching_uses_rubygems_ordering(self):
        database = VulnerabilityDatabase(":memory:")
        try:
            database.import_osv_records([{
                "id": "OSV-P1-RUBYGEMS-1",
                "affected": [{
                    "package": {"ecosystem": "RubyGems", "name": "demo"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0"}]}],
                }],
            }])
            self.assertEqual(len(database.match_component(Component("rubygems", "demo", "1.0.pre", purl="pkg:gem/demo@1.0.pre"))), 1)
            self.assertEqual(database.match_component(Component("rubygems", "demo", "1.0", purl="pkg:gem/demo@1.0")), [])
        finally:
            database.close()

    def test_invalid_rubygems_version_fails_closed(self):
        with self.assertRaises(ValueError):
            compare_rubygems_version("1..0", "1.0")
