import unittest

from src.vulnerability.database import VulnerabilityDatabase
from src.vulnerability.models import Component
from src.vulnerability.versions import compare_composer_version


class TestP1ComposerComparator(unittest.TestCase):
    def test_composer_stability_ordering(self):
        self.assertLess(compare_composer_version("1.0-dev", "1.0-alpha1"), 0)
        self.assertLess(compare_composer_version("1.0-beta1", "1.0-RC1"), 0)
        self.assertLess(compare_composer_version("1.0-RC1", "1.0"), 0)
        self.assertLess(compare_composer_version("1.0", "1.0-p1"), 0)

    def test_composer_matching_uses_composer_ordering(self):
        database = VulnerabilityDatabase(":memory:")
        try:
            database.import_osv_records([{
                "id": "OSV-P1-COMPOSER-1",
                "affected": [{
                    "package": {"ecosystem": "Packagist", "name": "vendor/demo"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0"}]}],
                }],
            }])
            self.assertEqual(len(database.match_component(Component("composer", "vendor/demo", "1.0-RC1", purl="pkg:composer/vendor/demo@1.0-RC1"))), 1)
            self.assertEqual(database.match_component(Component("composer", "vendor/demo", "1.0", purl="pkg:composer/vendor/demo@1.0")), [])
        finally:
            database.close()

    def test_invalid_composer_version_fails_closed(self):
        with self.assertRaises(ValueError):
            compare_composer_version("1..0", "1.0")
