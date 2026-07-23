import unittest

from src.vulnerability.database import VulnerabilityDatabase
from src.vulnerability.models import Component
from src.vulnerability.versions import compare_maven_version


class TestP1MavenComparator(unittest.TestCase):
    def test_maven_qualifier_ordering(self):
        ordered = [
            "1.0-alpha1",
            "1.0-beta1",
            "1.0-M1",
            "1.0-rc1",
            "1.0-SNAPSHOT",
            "1.0",
            "1.0-sp1",
        ]
        for left, right in zip(ordered, ordered[1:]):
            self.assertLess(compare_maven_version(left, right), 0, (left, right))

    def test_maven_normalization_and_unknown_qualifier(self):
        self.assertEqual(compare_maven_version("1.0", "1.0.0"), 0)
        self.assertEqual(compare_maven_version("1.0.Final", "1.0"), 0)
        self.assertLess(compare_maven_version("1.0-custom1", "1.0-custom2"), 0)

    def test_maven_matching_uses_maven_ordering(self):
        database = VulnerabilityDatabase(":memory:")
        try:
            database.import_osv_records(
                [{
                    "id": "OSV-P1-MAVEN-1",
                    "affected": [{
                        "package": {"ecosystem": "Maven", "name": "demo"},
                        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0"}]}],
                    }],
                }]
            )
            snapshot = Component("maven", "demo", "1.0-rc1", purl="pkg:maven/demo@1.0-rc1")
            fixed = Component("maven", "demo", "1.0", purl="pkg:maven/demo@1.0")
            self.assertEqual(len(database.match_component(snapshot)), 1)
            self.assertEqual(database.match_component(fixed), [])
        finally:
            database.close()

    def test_invalid_maven_version_fails_closed(self):
        with self.assertRaises(ValueError):
            compare_maven_version("1..0", "1.0")


if __name__ == "__main__":
    unittest.main()
