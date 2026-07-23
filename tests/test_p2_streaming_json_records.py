import json
import tempfile
import unittest
from pathlib import Path

from src.vulnerability.updater import JsonRecordLimits, iter_json_records_from_file


class TestP2StreamingJsonRecords(unittest.TestCase):
    def test_iterates_json_array_and_jsonl(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            array = root / "array.json"
            array.write_text('[{"id": 1}, {"id": 2}]', encoding="utf-8")
            self.assertEqual(list(iter_json_records_from_file(array)), [{"id": 1}, {"id": 2}])
            lines = root / "records.jsonl"
            lines.write_text('{"id": 3}\n{"id": 4}\n', encoding="utf-8")
            self.assertEqual(list(iter_json_records_from_file(lines)), [{"id": 3}, {"id": 4}])

    def test_record_and_count_limits_are_enforced(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "records.jsonl"
            path.write_text('{"id": 1}\n{"id": 2}\n', encoding="utf-8")
            with self.assertRaises(ValueError):
                list(iter_json_records_from_file(path, JsonRecordLimits(max_records=1)))
            with self.assertRaises(ValueError):
                list(iter_json_records_from_file(path, JsonRecordLimits(max_record_bytes=3)))

    def test_records_must_be_objects(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.json"
            path.write_text('[1]', encoding="utf-8")
            with self.assertRaises(ValueError):
                list(iter_json_records_from_file(path))
