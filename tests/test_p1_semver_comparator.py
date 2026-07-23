import unittest

from src.vulnerability.database import VulnerabilityDatabase
from src.vulnerability.models import Component
from src.vulnerability.versions import compare_semver_version


class TestP1SemverComparator(unittest.TestCase):
    def test_semver_prerelease_ordering(self):
        ordered = [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
        ]
        for left, right in zip(ordered, ordered[1:]):
            self.assertLess(compare_semver_version(left, right), 0, (left, right))

    def test_build_metadata_does_not_change_precedence(self):
        self.assertEqual(compare_semver_version("1.2.3+build.1", "1.2.3+build.2"), 0)
        self.assertEqual(compare_semver_version("v1.2.3", "1.2.3"), 0)

    def test_invalid_semver_fails_closed(self):
        with self.assertRaises(ValueError):
            compare_semver_version("1.2", "1.2.0")
        with self.assertRaises(ValueError):
            compare_semver_version("1.2.3-01", "1.2.3-1")

    def test_npm_matching_uses_semver_for_prerelease_before_fixed_release(self):
        database = VulnerabilityDatabase(":memory:")
        try:
            database.import_osv_records(
                [{
                    "id": "OSV-P1-SEMVER-1",
                    "affected": [{
                        "package": {"ecosystem": "npm", "name": "demo"},
                        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0.0.0"}, {"fixed": "1.0.0"}]}],
                    }],
                }]
            )
            prerelease = Component("npm", "demo", "1.0.0-rc.1", purl="pkg:npm/demo@1.0.0-rc.1")
            fixed = Component("npm", "demo", "1.0.0", purl="pkg:npm/demo@1.0.0")
            self.assertEqual(len(database.match_component(prerelease)), 1)
            self.assertEqual(database.match_component(fixed), [])
        finally:
            database.close()


if __name__ == "__main__":
    unittest.main()
