import re
import unittest

from src.patterns import DEFAULT_DETECTION_RULES


class PaddleApiKeyDetectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rule = next(rule for rule in DEFAULT_DETECTION_RULES if rule.rule_id == "CRT-SEC-180")

    @staticmethod
    def token(environment="live"):
        return f"pdl_{environment}_apikey_" + "a1" * 13 + "_" + "Ab3x" * 5 + "Ab" + "_" + "Q7x"

    def test_live_positive(self):
        match = self.rule.compiled.search(self.token("live"))
        self.assertIsNotNone(match)
        if match is not None:
            self.assertEqual(match.group(0), self.token("live"))

    def test_sandbox_positive(self):
        match = self.rule.compiled.search(self.token("sdbx"))
        self.assertIsNotNone(match)
        if match is not None:
            self.assertEqual(match.group(0), self.token("sdbx"))

    def test_environment_in_assignment(self):
        self.assertIsNotNone(self.rule.compiled.search("PADDLE_API_KEY=" + self.token()))

    def test_embedded_in_json(self):
        self.assertIsNotNone(self.rule.compiled.search('{"key": "' + self.token() + '"}'))

    def test_too_short_component(self):
        value = self.token().replace("a1" * 13, "a1" * 12 + "a")
        self.assertIsNone(self.rule.compiled.search(value))

    def test_too_long_component(self):
        value = self.token().replace("a1" * 13, "a1" * 13 + "a")
        self.assertIsNone(self.rule.compiled.search(value))

    def test_wrong_prefix(self):
        self.assertIsNone(self.rule.compiled.search("pdx_live_apikey_" + self.token().split("_apikey_", 1)[1]))

    def test_wrong_alphabet(self):
        self.assertIsNone(self.rule.compiled.search(self.token().replace("Q7x", "Q7-")))

    def test_embedded_in_larger_identifier(self):
        self.assertIsNone(self.rule.compiled.search("X" + self.token()))
        self.assertIsNone(self.rule.compiled.search(self.token() + "_suffix"))

    def test_placeholder_and_redaction(self):
        self.assertIsNone(self.rule.compiled.search("pdl_live_apikey_<project>_<secret>_<sig>"))
        self.assertNotIn("a1a1", "[REDACTED]")


if __name__ == "__main__":
    unittest.main()
