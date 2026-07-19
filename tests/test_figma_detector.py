import unittest

from src.scanner import SecretScanner


class FigmaStableDetectorTests(unittest.TestCase):
    def test_detects_figma_pat_and_rejects_short_near_miss(self):
        token = "figd_" + "A" * 40
        diff = f"""--- a/config.py
+++ b/config.py
@@ -1,0 +1,2 @@
+FIGMA_TOKEN={token}
+FIGMA_TOKEN=figd_{{'A' * 20}}
"""
        result = SecretScanner(config_check=False).scan_diff_text(diff)
        ids = [finding.rule_id for finding in result.findings]
        self.assertEqual(ids.count("CRT-SEC-135"), 1)


if __name__ == "__main__":
    unittest.main()
