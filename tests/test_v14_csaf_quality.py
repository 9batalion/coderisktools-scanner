import unittest

from src.vulnerability.sources.csaf_quality import csaf_quality_gate


class TestV14CsafQuality(unittest.TestCase):
    def test_quality_gate_accepts_valid_and_reports_provider_extensions(self):
        report = csaf_quality_gate({
            "source_id": "csaf-security",
            "source_digest": "sha256:abc",
            "advisories": [{
                "id": "CVE-2026-1",
                "affected_product_ids": ["p1"],
                "not_affected_product_ids": [],
                "products": {"p1": ("PyPI", "example", "1.0.0")},
                "vendor_status": {"p1": {"status": "under_investigation", "provider_extension": {"foo": "bar"}}},
                "remediations": [{"category": "vendor_fix", "details": "upgrade", "product_ids": ["p1"]}],
            }],
            "provenance": {"schema": "csaf_security_advisory", "version": "2.0"},
        })
        self.assertTrue(report["passed"])
        self.assertEqual(report["provider_extension_count"], 1)
        self.assertEqual(report["remediation_count"], 1)
