import io
import tempfile
import unittest
from pathlib import Path
from urllib.request import OpenerDirector

from src.vulnerability.updater import FetchPolicy, stream_json_artifact_to_file


class _Headers(dict):
    def get_content_length(self):
        value = self.get("Content-Length")
        return None if value is None else int(value)


class _Response(io.BytesIO):
    def __init__(self, payload):
        super().__init__(payload)
        self.headers = _Headers({"Content-Type": "application/json"})

    def geturl(self):
        return "https://feeds.example.test/data.json"

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class _Opener:
    def __init__(self, payload):
        self.payload = payload

    def open(self, request, timeout):
        return _Response(self.payload)


class TestP2StreamingArtifact(unittest.TestCase):
    def test_streams_bounded_payload_without_returning_payload_bytes(self):
        payload = b'{"advisories": []}'
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "artifact.json"
            result = stream_json_artifact_to_file(
                "https://feeds.example.test/data.json",
                target,
                FetchPolicy(frozenset({"feeds.example.test"}), max_bytes=1024),
                opener=_Opener(payload),
            )
            self.assertEqual(target.read_bytes(), payload)
            self.assertEqual(result["state"], "downloaded")
            self.assertEqual(result["bytes_written"], len(payload))
            self.assertEqual(result["payload_sha256"], "sha256:e6f6cd64a64dad928e0b5a6b2f8266f109b57534084f33758da78af96b8bb4e1")

    def test_limit_failure_preserves_existing_target(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "artifact.json"
            target.write_bytes(b"old")
            with self.assertRaises(ValueError):
                stream_json_artifact_to_file(
                    "https://feeds.example.test/data.json",
                    target,
                    FetchPolicy(frozenset({"feeds.example.test"}), max_bytes=4),
                    opener=_Opener(b"too large"),
                )
            self.assertEqual(target.read_bytes(), b"old")
