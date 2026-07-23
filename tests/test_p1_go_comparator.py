import unittest

from src.vulnerability.database import VulnerabilityDatabase
from src.vulnerability.models import Component
from src.vulnerability.versions import compare_go_version


class TestP1GoComparator(unittest.TestCase):
    def test_go_semver_and_v_prefix(self):
        self.assertEqual(compare_go_version("v1.2.3", "1.2.3"), 0)
        self.assertLess(compare_go_version("v1.2.3-rc.1", "v1.2.3"), 0)
        self.assertEqual(compare_go_version("v1.2.3+incompatible", "v1.2.3"), 0)

    def test_go_matching_uses_go_ordering(self):
        database = VulnerabilityDatabase(":memory:")
        try:
            database.import_osv_records([{
                "id": "OSV-P1-GO-1",
                "affected": [{
                    "package": {"ecosystem": "Go", "name": "example.com/demo"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "v1.2.3"}]}],
                }],
            }])
            self.assertEqual(len(database.match_component(Component("go", "example.com/demo", "v1.2.3-rc.1", purl="pkg:golang/example.com/demo@v1.2.3-rc.1"))), 1)
            self.assertEqual(database.match_component(Component("go", "example.com/demo", "v1.2.3", purl="pkg:golang/example.com/demo@v1.2.3")), [])
        finally:
            database.close()

    def test_invalid_go_version_fails_closed(self):
        with self.assertRaises(ValueError):
            compare_go_version("v1.2", "v1.2.3")
