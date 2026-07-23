import unittest

from src.vulnerability.database import VulnerabilityDatabase
from src.vulnerability.models import Component
from src.vulnerability.versions import compare_pep440_version


class TestP1Pep440Comparator(unittest.TestCase):
    def test_release_prerelease_post_and_dev_ordering(self):
        ordered = [
            "1.0.dev1",
            "1.0a1",
            "1.0b1",
            "1.0rc1",
            "1.0",
            "1.0.post1",
        ]
        for left, right in zip(ordered, ordered[1:]):
            self.assertLess(compare_pep440_version(left, right), 0, (left, right))

    def test_pep440_normalization_and_epoch(self):
        self.assertEqual(compare_pep440_version("v1.0-rc1", "1.0rc1"), 0)
        self.assertGreater(compare_pep440_version("1!1.0", "2.0"), 0)
        self.assertEqual(compare_pep440_version("1.0+linux.1", "1.0+linux.2"), -1)

    def test_invalid_versions_fail_closed(self):
        with self.assertRaises(ValueError):
            compare_pep440_version("not a version", "1.0")

    def test_pypi_matching_uses_pep440_for_prerelease_before_fixed_release(self):
        database = VulnerabilityDatabase(":memory:")
        try:
            database.import_osv_records(
                [{
                    "id": "OSV-P1-PEP440-1",
                    "affected": [{
                        "package": {"ecosystem": "PyPI", "name": "demo"},
                        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0"}]}],
                    }],
                }]
            )
            prerelease = Component("pypi", "demo", "1.0rc2", purl="pkg:pypi/demo@1.0rc2")
            fixed = Component("pypi", "demo", "1.0", purl="pkg:pypi/demo@1.0")
            self.assertEqual(len(database.match_component(prerelease)), 1)
            self.assertEqual(database.match_component(fixed), [])
        finally:
            database.close()


if __name__ == "__main__":
    unittest.main()
