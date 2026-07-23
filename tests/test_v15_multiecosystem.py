import tempfile
import unittest
from pathlib import Path

from src.vulnerability.benchmark import load_benchmark_fixture, run_database_benchmark
from src.vulnerability.database import VulnerabilityDatabase


class TestV15Multiecosystem(unittest.TestCase):
    def test_multiecosystem_fixture_meets_golden_thresholds(self):
        fixture = load_benchmark_fixture(Path("tests/fixtures/v15_multiecosystem.json"))
        with tempfile.TemporaryDirectory() as directory:
            database = VulnerabilityDatabase(str(Path(directory) / "db.sqlite"))
            try:
                records = []
                for item in fixture["records"]:
                    records.append({"id": item["id"], "affected": [{"package": {"ecosystem": item["ecosystem"], "name": item["name"]}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": item["fixed"]}]}]}]})
                database.import_osv_records(records, source="v15-fixture")
                report = run_database_benchmark(database, fixture["cases"])
                self.assertGreaterEqual(report["summary"]["precision"], fixture["golden"]["min_precision"])
                self.assertGreaterEqual(report["summary"]["recall"], fixture["golden"]["min_recall"])
                self.assertGreaterEqual(report["summary"]["f1"], fixture["golden"]["min_f1"])
            finally:
                database.close()
