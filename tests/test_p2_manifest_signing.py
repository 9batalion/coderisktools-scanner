import unittest

from src.vulnerability.database import VulnerabilityDatabase
from src.vulnerability.manifest_signing import sign_manifest, verify_manifest


class TestP2ManifestSigning(unittest.TestCase):
    @unittest.skipUnless(__import__('importlib').util.find_spec('cryptography'), 'optional cryptography backend unavailable')
    def test_sign_and_verify_manifest(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        private = Ed25519PrivateKey.generate()
        public = private.public_key().public_bytes_raw()
        raw_private = private.private_bytes_raw()
        manifest = {"schema_version": "2", "content_digest": "sha256:demo", "advisory_count": 0, "affected_package_count": 0}
        envelope = sign_manifest(manifest, "fixture-key", raw_private)
        self.assertEqual(verify_manifest(envelope, public), manifest)
        self.assertEqual(envelope["schema"], "coderisktools.vulnerability.signed-manifest")

    @unittest.skipUnless(__import__('importlib').util.find_spec('cryptography'), 'optional cryptography backend unavailable')
    def test_database_rejects_tampered_manifest(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        private = Ed25519PrivateKey.generate()
        public = private.public_key().public_bytes_raw()
        envelope = sign_manifest({"content_digest": "sha256:x", "advisory_count": 0, "affected_package_count": 0}, "fixture-key", private.private_bytes_raw())
        envelope["manifest"]["advisory_count"] = 1
        database = VulnerabilityDatabase(":memory:")
        try:
            with self.assertRaises(ValueError):
                database.stage_signed_snapshot("signed", "sha256:source", envelope, public)
        finally:
            database.close()
