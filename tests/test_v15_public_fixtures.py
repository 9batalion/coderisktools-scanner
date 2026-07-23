import json
import unittest
from pathlib import Path

from src.vulnerability.benchmark import load_benchmark_fixture


class TestV15PublicFixtures(unittest.TestCase):
    def test_versioned_public_fixture_has_golden_results(self):
        fixture = load_benchmark_fixture(Path("tests/fixtures/v15_public_benchmark.json"))
        self.assertEqual(fixture["schema"], "coderisktools.vulnerability.benchmark")
        self.assertEqual(fixture["version"], 1)
        self.assertEqual(len(fixture["cases"]), 3)
        self.assertEqual(fixture["golden"]["precision"], 1.0)
        self.assertEqual(fixture["golden"]["recall"], 0.5)
