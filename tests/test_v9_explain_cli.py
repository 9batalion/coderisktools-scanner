import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class TestV9ExplainCli(unittest.TestCase):
    def test_explain_returns_persisted_match_explanation(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "vuln.sqlite"
            connection = sqlite3.connect(database_path)
            connection.execute("CREATE TABLE matches (fingerprint TEXT PRIMARY KEY, explanation_json TEXT NOT NULL)")
            explanation = {"status": "affected", "method": "exact-purl", "confidence": "high", "matches": []}
            connection.execute("INSERT INTO matches VALUES (?, ?)", ("sha256:test-fingerprint", json.dumps(explanation)))
            connection.commit()
            connection.close()
            result = subprocess.run(
                [sys.executable, "-m", "src", "vuln-db", "explain", "--database", str(database_path), "--fingerprint", "sha256:test-fingerprint"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), explanation)

    def test_explain_unknown_fingerprint_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "vuln.sqlite"
            connection = sqlite3.connect(database_path)
            connection.execute("CREATE TABLE matches (fingerprint TEXT PRIMARY KEY, explanation_json TEXT NOT NULL)")
            connection.commit()
            connection.close()
            result = subprocess.run(
                [sys.executable, "-m", "src", "vuln-db", "explain", "--database", str(database_path), "--fingerprint", "sha256:missing"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 3)
            self.assertIn("unknown vulnerability match fingerprint", result.stderr)


if __name__ == "__main__":
    unittest.main()
