import tempfile
import unittest
from pathlib import Path

from src.vulnerability.sources.alpine import ingest_file as ingest_alpine
from src.vulnerability.sources.debian import ingest_file as ingest_debian
from src.vulnerability.sources.redhat import ingest_file as ingest_redhat
from src.vulnerability.sources.suse import ingest_file as ingest_suse
from src.vulnerability.sources.ubuntu import ingest_file as ingest_ubuntu


class TestV12BackportContract(unittest.TestCase):
    def test_all_linux_adapters_preserve_bounded_backport_metadata(self):
        fixtures = [
            (ingest_debian, "coderisktools.vulnerability.debian-feed", "bookworm", "DSA-1", "3.0.11-1~deb12u2"),
            (ingest_ubuntu, "coderisktools.vulnerability.ubuntu-feed", "jammy", "USN-1", "3.0.11-1ubuntu2.1"),
            (ingest_redhat, "coderisktools.vulnerability.redhat-feed", "rhel-9", "RHSA-1", "3.0.7-25.el9_2"),
            (ingest_suse, "coderisktools.vulnerability.suse-feed", "sles-15", "SUSE-1", "3.0.8-1.2"),
            (ingest_alpine, "coderisktools.vulnerability.alpine-feed", "v3.18", "CVE-1", "3.1.4-r2"),
        ]
        with tempfile.TemporaryDirectory() as directory:
            for index, (parser, schema, release, advisory_id, fixed) in enumerate(fixtures):
                path = Path(directory) / f"feed-{index}.json"
                path.write_text("{" + f'"schema":"{schema}","version":1,"release":"{release}","advisories":[{{"id":"{advisory_id}","package":"openssl","fixed":"{fixed}","binary_packages":["openssl-bin"],"backport":true}}]' + "}", encoding="utf-8")
                result = parser(str(path))
                self.assertTrue(result["advisories"][0]["backport"])
                self.assertEqual(result["advisories"][0]["fixed"], fixed)
                self.assertEqual(result["provenance"]["source_digest"], result["source_digest"])
