import unittest

from src.vulnerability.benchmark import BenchmarkCase, evaluate_cases, summarize_metrics


class TestV15Benchmark(unittest.TestCase):
    def test_precision_recall_and_latency_summary(self):
        cases = [
            BenchmarkCase("affected", expected=True, observed=True, elapsed_ms=2.0),
            BenchmarkCase("clean", expected=False, observed=False, elapsed_ms=1.0),
            BenchmarkCase("miss", expected=True, observed=False, elapsed_ms=3.0),
        ]
        metrics = evaluate_cases(cases)
        summary = summarize_metrics(metrics, cases)
        self.assertEqual(metrics["true_positive"], 1)
        self.assertEqual(metrics["false_negative"], 1)
        self.assertEqual(summary["precision"], 1.0)
        self.assertEqual(summary["recall"], 0.5)
        self.assertEqual(summary["f1"], 2 / 3)
        self.assertEqual(summary["latency_ms"]["p95"], 3.0)
