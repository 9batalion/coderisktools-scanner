import gzip
import io
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from src.vulnerability.updater import ArchiveLimits, extract_archive_to_directory


class TestP2SafeArchives(unittest.TestCase):
    def test_zip_extracts_to_atomic_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "feed.zip"
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("nested/feed.json", b'{"ok": true}')
            output = root / "extracted"
            report = extract_archive_to_directory(archive, output)
            self.assertEqual(report["state"], "extracted")
            self.assertEqual((output / "nested/feed.json").read_bytes(), b'{"ok": true}')

    def test_zip_path_traversal_is_rejected_without_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "evil.zip"
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("../outside.json", b"bad")
            output = root / "extracted"
            with self.assertRaises(ValueError):
                extract_archive_to_directory(archive, output)
            self.assertFalse(output.exists())
            self.assertFalse((root / "outside.json").exists())

    def test_gzip_enforces_decompressed_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "feed.json.gz"
            archive.write_bytes(gzip.compress(b"0123456789"))
            with self.assertRaises(ValueError):
                extract_archive_to_directory(archive, root / "extracted", ArchiveLimits(max_total_bytes=5))

    def test_tar_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "feed.tar"
            with tarfile.open(archive, "w") as handle:
                info = tarfile.TarInfo("link")
                info.type = tarfile.SYMTYPE
                info.linkname = "/etc/passwd"
                handle.addfile(info)
            with self.assertRaises(ValueError):
                extract_archive_to_directory(archive, root / "extracted")
