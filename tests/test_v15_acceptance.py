import unittest

from src.vulnerability.benchmark import run_fixture_benchmark


class TestV15Acceptance(unittest.TestCase):
    def test_runner_passes_golden_acceptance_gates(self):
        report = run_fixture_benchmark(
            "tests/fixtures/v15_public_benchmark.json",
            min_precision=1.0,
            min_recall=0.5,
            min_f1=0.66,
            max_p95_ms=3.0,
        )
        self.assertTrue(report["passed"])
        self.assertEqual(report["acceptance"]["failed"], [])

    def test_runner_reports_failed_gate_without_raising(self):
        report = run_fixture_benchmark("tests/fixtures/v15_public_benchmark.json", min_recall=0.9)
        self.assertFalse(report["passed"])
        self.assertIn("recall", report["acceptance"]["failed"])
