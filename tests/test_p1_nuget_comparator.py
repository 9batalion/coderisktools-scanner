import unittest

from src.vulnerability.database import VulnerabilityDatabase
from src.vulnerability.models import Component
from src.vulnerability.versions import compare_nuget_version


class TestP1NugetComparator(unittest.TestCase):
    def test_nuget_normalizes_numeric_release_segments(self):
        self.assertEqual(compare_nuget_version("1.0", "1.0.0.0"), 0)
        self.assertEqual(compare_nuget_version("01.02.003", "1.2.3"), 0)

    def test_nuget_prerelease_and_build_ordering(self):
        self.assertLess(compare_nuget_version("1.0.0-alpha", "1.0.0-beta"), 0)
        self.assertLess(compare_nuget_version("1.0.0-rc.1", "1.0.0"), 0)
        self.assertEqual(compare_nuget_version("1.0.0+build.1", "1.0.0+build.2"), 0)

    def test_nuget_matching_uses_nuget_ordering(self):
        database = VulnerabilityDatabase(":memory:")
        try:
            database.import_osv_records(
                [{
                    "id": "OSV-P1-NUGET-1",
                    "affected": [{
                        "package": {"ecosystem": "NuGet", "name": "Demo"},
                        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0.0"}, {"fixed": "1.0.0"}]}],
                    }],
                }]
            )
            prerelease = Component("nuget", "demo", "1.0.0-rc.1", purl="pkg:nuget/demo@1.0.0-rc.1")
            fixed = Component("nuget", "demo", "1.0.0", purl="pkg:nuget/demo@1.0.0")
            self.assertEqual(len(database.match_component(prerelease)), 1)
            self.assertEqual(database.match_component(fixed), [])
        finally:
            database.close()

    def test_invalid_nuget_version_fails_closed(self):
        with self.assertRaises(ValueError):
            compare_nuget_version("1.2.3.4.5", "1.2.3")


if __name__ == "__main__":
    unittest.main()
