import hashlib
import json
import unittest
from pathlib import Path

from src.patterns import match_context_rules, match_rules


MANIFEST = Path(__file__).parent / "corpora" / "golden" / "manifest.json"


class GoldenParityCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = json.loads(MANIFEST.read_text(encoding="utf-8"))

    def test_manifest_is_complete_and_secret_safe(self):
        self.assertEqual(self.document["counts"], {"covered": 195, "expected_detectors": 195, "unreachable": 0})
        self.assertEqual(len(self.document["cases"]), 195)
        self.assertEqual(self.document["known_unreachable"], [])
        raw_cases = json.dumps(self.document["cases"], ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        self.assertEqual(hashlib.sha256(raw_cases).hexdigest(), self.document["fixture_sha256"])
        serialized = MANIFEST.read_text(encoding="utf-8")
        self.assertNotIn("/workspace", serialized)
        self.assertNotIn("timestamp", serialized)

    def test_legacy_matcher_replays_exact_detector_ids(self):
        for case in self.document["cases"]:
            with self.subTest(case=case["case_id"]):
                if case["type"] == "synthetic-line":
                    lines = [(number, content) for number, content in case["lines"]]
                    found = match_rules(lines[0][1], case["filepath"])
                    ids = sorted(rule.rule_id for rule, _match in found)
                else:
                    lines = [(number, content) for number, content in case["lines"]]
                    found = match_context_rules(lines, case["filepath"])
                    ids = sorted(item.rule.rule_id for item in found)
                self.assertEqual(ids, case["expected_rule_ids"])


if __name__ == "__main__":
    unittest.main()
