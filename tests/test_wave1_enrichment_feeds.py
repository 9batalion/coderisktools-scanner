import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from src.vulnerability.sources.epss import ingest_file as ingest_epss
from src.vulnerability.sources.ghsa import ingest_file as ingest_ghsa
from src.vulnerability.sources.kev import ingest_file as ingest_kev
from src.vulnerability.database import ImportStats


class TestWave1EnrichmentFeeds(unittest.TestCase):
    def test_kev_epss_and_ghsa_file_contracts_are_bounded_and_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            kev_path = root / "kev.json"
            kev_path.write_text(json.dumps({"vulnerabilities": [{}]}), encoding="utf-8")
            epss_path = root / "epss.json"
            epss_path.write_text(json.dumps({"data": [{}]}), encoding="utf-8")
            ghsa_path = root / "ghsa.json"
            ghsa_path.write_text(json.dumps({"advisories": [{}]}), encoding="utf-8")
            db = Mock()
            db.import_kev_json.return_value = ImportStats(1, 1, 0)
            db.import_epss_json.return_value = ImportStats(1, 1, 0)
            db.import_ghsa_json.return_value = ImportStats(1, 1, 1)
            reports = [
                ingest_kev(str(kev_path), db, "snapshot-kev"),
                ingest_epss(str(epss_path), db, "snapshot-epss"),
                ingest_ghsa(str(ghsa_path), db, "snapshot-ghsa"),
            ]
            self.assertEqual([report["state"] for report in reports], ["staged"] * 3)
            self.assertTrue(all(not report["activated"] for report in reports))
            self.assertTrue(all(report["source_digest"].startswith("sha256:") for report in reports))
