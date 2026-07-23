import unittest

from src.vulnerability.benchmark import build_quality_suites_report, benchmark_regression_gate


class TestV15QualitySuites(unittest.TestCase):
    def test_quality_suites_partition_results_and_regression_gate(self):
        cases = [
            {"case_id": "tp", "expected": True, "observed": True, "elapsed_ms": 1.0},
            {"case_id": "tn", "expected": False, "observed": False, "elapsed_ms": 1.0},
            {"case_id": "fp", "expected": False, "observed": True, "elapsed_ms": 1.0},
            {"case_id": "fn", "expected": True, "observed": False, "elapsed_ms": 1.0},
        ]
        report = build_quality_suites_report(cases)
        self.assertEqual(report["precision_suite"]["count"], 2)
        self.assertEqual(report["recall_suite"]["count"], 2)
        self.assertEqual(report["false_positive_suite"]["count"], 1)
        self.assertEqual(report["false_negative_suite"]["count"], 1)
        gate = benchmark_regression_gate(report, report)
        self.assertTrue(gate["passed"])

    def test_regression_gate_rejects_new_false_negative(self):
        baseline = {"false_positive_suite": {"case_ids": []}, "false_negative_suite": {"case_ids": []}}
        current = {"false_positive_suite": {"case_ids": []}, "false_negative_suite": {"case_ids": ["new-fn"]}}
        gate = benchmark_regression_gate(current, baseline)
        self.assertFalse(gate["passed"])
        self.assertEqual(gate["failed"], ["false_negative_regression"])
