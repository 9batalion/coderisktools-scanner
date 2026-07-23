import unittest

from src.vulnerability.update_config import default_update_config


class TestDefaultUpdateConfig(unittest.TestCase):
    def test_active_sources_are_supported_and_extended_sources_are_explicitly_disabled(self):
        sources = default_update_config()["sources"]
        active = {item["source_id"] for item in sources if item.get("enabled", True)}
        disabled = {item["source_id"] for item in sources if item.get("enabled") is False}
        self.assertEqual(active, {"nvd", "cisa-kev", "epss", "github-advisories"})
        self.assertTrue({"osv", "cve-v5", "debian-security", "ubuntu-security", "rustsec"} <= disabled)
