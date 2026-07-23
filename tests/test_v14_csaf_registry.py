import unittest

from src.vulnerability.sources.csaf_registry import CsafProviderRegistry


class TestV14CsafRegistry(unittest.TestCase):
    def test_provider_registry_and_health_are_deterministic(self):
        registry = CsafProviderRegistry()
        registry.register("example", "https://example.invalid/csaf", enabled=True)
        registry.record_result("example", success=True, records=3, digest="sha256:abc")
        report = registry.health_report("example")
        self.assertEqual(report["provider_id"], "example")
        self.assertEqual(report["status"], "healthy")
        self.assertEqual(report["last_records"], 3)
        self.assertEqual(report["last_digest"], "sha256:abc")
        self.assertEqual(registry.list_providers()[0]["provider_id"], "example")
