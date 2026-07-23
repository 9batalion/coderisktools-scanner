import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from src.vulnerability.seed import SEED_ECOSYSTEMS, build_seed_manifest, validate_seed_manifest
from src.vulnerability.update_profiles import annotate_config, profile_source_ids, validate_profile


class SeedProfileTests(unittest.TestCase):
    def test_seed_profile_is_partial_and_requires_core_sources(self):
        self.assertEqual(validate_profile("seed"), "seed")
        self.assertEqual(
            profile_source_ids("seed"),
            {"osv", "github-advisories", "cisa-kev", "epss"},
        )
        self.assertEqual(SEED_ECOSYSTEMS, ("PyPI", "npm", "Go", "crates.io", "Maven", "NuGet", "Packagist"))

    def test_seed_manifest_is_explicitly_partial(self):
        manifest = build_seed_manifest(
            {"cisa-kev": {"status": "complete", "records": 1}, "epss": {"status": "bounded", "records": 1}, "ghsa": {"status": "bounded", "records": 1}, "osv": {"status": "partial", "successful_ecosystems": ["PyPI", "npm", "Go", "Maven"], "failed_ecosystems": []}},
            {"advisory_count": 2, "affected_package_count": 1, "content_digest": "sha256:" + "a" * 64},
        )
        self.assertEqual(manifest["profile"], "seed")
        self.assertEqual(manifest["completeness"], "partial")
        self.assertFalse(manifest["production_full_database"])
        validate_seed_manifest(manifest)

    def test_seed_manifest_rejects_missing_required_source(self):
        with self.assertRaises(ValueError):
            validate_seed_manifest({"profile": "seed", "completeness": "partial", "production_full_database": False, "sources": {}})


if __name__ == "__main__":
    unittest.main()
