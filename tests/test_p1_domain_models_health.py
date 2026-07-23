import unittest

from src.vulnerability.database import VulnerabilityDatabase
from src.vulnerability.models import (
    AffectedRange,
    ConflictRecord,
    DatabaseHealth,
    EpssScore,
    LicenseRecord,
    KevEntry,
    Remediation,
    SeverityMetric,
    SsvcAssessment,
    VulnerabilityFinding,
    Weakness,
)


class TestP1DomainModelsHealth(unittest.TestCase):
    def test_domain_models_are_immutable_and_serializable(self):
        values = [
            AffectedRange(range_type="ECOSYSTEM", events=({"introduced": "0"},)),
            SeverityMetric(version="3.1", score=7.5, vector="CVSS:3.1/AV:N"),
            Weakness(cwe_id="CWE-79", source="nvd"),
            KevEntry(cve_id="CVE-2024-1", date_added="2024-01-01"),
            EpssScore(cve_id="CVE-2024-1", score=0.4, percentile=0.8),
            SsvcAssessment(assessment="track", source="cisa"),
            Remediation(advisory_id="CVE-2024-1", guidance="upgrade"),
            VulnerabilityFinding(advisory_id="CVE-2024-1", component_purl="pkg:pypi/demo@1.0"),
            ConflictRecord(advisory_id="CVE-2024-1", fields=("summary",)),
            LicenseRecord(component_purl="pkg:pypi/demo@1.0", license_id="MIT"),
        ]
        for value in values:
            self.assertIsInstance(value.to_dict(), dict)
        with self.assertRaises((AttributeError, TypeError)):
            values[0].range_type = "OTHER"

    def test_snapshot_health_reports_integrity(self):
        database = VulnerabilityDatabase(":memory:")
        try:
            health = database.snapshot_health()
            self.assertIsInstance(health, DatabaseHealth)
            self.assertTrue(health.healthy)
            self.assertEqual(health.checks["sqlite_integrity"], "ok")
        finally:
            database.close()
