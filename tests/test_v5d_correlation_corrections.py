"""RED tests for the V5 manual correlation correction file contract."""

import copy
import unittest

from src.vulnerability.database import VulnerabilityDatabase


RECORD_A = {"id": "OSV-V5-CORR-A", "aliases": ["CVE-2025-4444"], "affected": []}
RECORD_B = {"id": "OSV-V5-CORR-B", "aliases": ["CVE-2025-4444"], "affected": []}


class TestV5CorrelationCorrections(unittest.TestCase):
    def _database_with_conflict(self):
        database = VulnerabilityDatabase(":memory:")
        database.import_osv_records([RECORD_A, RECORD_B])
        return database

    def test_export_is_versioned_deterministic_and_import_does_not_apply(self):
        source = self._database_with_conflict()
        source.record_merge_decision("merge", ["OSV-V5-CORR-A", "OSV-V5-CORR-B"], "same CVE alias", ["CVE-2025-4444"])
        exported = source.export_merge_corrections()
        self.assertEqual(exported["schema"], "coderisktools.vulnerability.correlation-corrections")
        self.assertEqual(exported["version"], 1)
        self.assertTrue(exported["content_digest"].startswith("sha256:"))

        target = self._database_with_conflict()
        imported = target.import_merge_corrections(copy.deepcopy(exported))
        self.assertEqual(imported["imported_count"], 1)
        self.assertEqual(target.merge_decision_count(), 1)
        self.assertEqual(target.advisory_relation_count(active_only=True), 0)
        self.assertEqual(target.export_merge_corrections(), exported)

    def test_import_rejects_tampered_digest_and_unknown_advisory(self):
        source = self._database_with_conflict()
        source.record_merge_decision("merge", ["OSV-V5-CORR-A", "OSV-V5-CORR-B"], "same CVE alias", ["CVE-2025-4444"])
        exported = source.export_merge_corrections()
        tampered = copy.deepcopy(exported)
        tampered["corrections"][0]["reason"] = "changed"
        with self.assertRaisesRegex(ValueError, "digest"):
            self._database_with_conflict().import_merge_corrections(tampered)

        unknown = copy.deepcopy(exported)
        unknown["corrections"][0]["advisory_ids"] = ["OSV-MISSING", "OSV-V5-CORR-A"]
        unsigned = dict(unknown)
        unsigned.pop("content_digest")
        from src.vulnerability.canonical import canonical_json_bytes
        import hashlib
        unknown["content_digest"] = "sha256:" + hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()
        with self.assertRaisesRegex(ValueError, "unknown advisory"):
            self._database_with_conflict().import_merge_corrections(unknown)


if __name__ == "__main__":
    unittest.main()
