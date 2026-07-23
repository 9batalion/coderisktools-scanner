import tempfile
import unittest
from pathlib import Path

from src.vulnerability.database import VulnerabilityDatabase
from src.vulnerability.models import Component
from src.vulnerability.sources.elixir import ELIXIR_SOURCE_ID, ingest_file, ingest_file_to_database


class TestV13ElixirSource(unittest.TestCase):
    def test_elixir_fixture_staging_and_fixed_boundary(self):
        payload = '{"schema":"coderisktools.vulnerability.elixir-feed","version":1,"advisories":[{"id":"CVE-2026-6","package":"plug","fixed":"1.15.3","severity":"high"}]}'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            feed = root / "elixir.json"
            feed.write_text(payload, encoding="utf-8")
            parsed = ingest_file(str(feed))
            self.assertEqual(parsed["source_id"], ELIXIR_SOURCE_ID)
            database = VulnerabilityDatabase(str(root / "db.sqlite"))
            try:
                report = ingest_file_to_database(str(feed), database, "elixir-1")
                self.assertEqual(report["state"], "staged")
                affected = database.evaluate_component(Component(ecosystem="Hex", name="plug", version="1.15.2"))
                fixed = database.evaluate_component(Component(ecosystem="Hex", name="plug", version="1.15.3"))
                self.assertEqual(affected["status"], "affected")
                self.assertEqual(fixed["status"], "not_affected")
            finally:
                database.close()
