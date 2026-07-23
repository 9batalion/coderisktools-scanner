import unittest

from src.vulnerability.feed_catalog import feed_catalog, feed_catalog_report


class TestFeedCatalog(unittest.TestCase):
    def test_catalog_is_deterministic_and_not_ready_without_full_adapters(self):
        feeds = feed_catalog()
        self.assertEqual(len({item.source_id for item in feeds}), len(feeds))
        self.assertTrue(all(item.endpoint is None or item.endpoint.startswith("https://") for item in feeds))
        report = feed_catalog_report()
        self.assertEqual(report["source_count"], len(feeds))
        self.assertFalse(report["full_coverage_ready"])
        self.assertNotIn("ready", report["counts"])
