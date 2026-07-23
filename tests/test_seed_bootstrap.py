import hashlib
import tempfile
import unittest
from pathlib import Path

from src.vulnerability.bootstrap import verify_asset_sha256


class SeedBootstrapTests(unittest.TestCase):
    def test_verify_asset_sha256_accepts_exact_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "seed.sqlite"
            path.write_bytes(b"real-seed-bytes")
            digest = "sha256:" + hashlib.sha256(b"real-seed-bytes").hexdigest()
            self.assertEqual(verify_asset_sha256(path, digest), digest)

    def test_verify_asset_sha256_rejects_tampering(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "seed.sqlite"
            path.write_bytes(b"tampered")
            with self.assertRaises(ValueError):
                verify_asset_sha256(path, "sha256:" + "0" * 64)


if __name__ == "__main__":
    unittest.main()
