import gzip
import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from scripts.normalize_sdist import normalize_sdist


class ReproducibleSdistTests(unittest.TestCase):
    @staticmethod
    def _source(path: Path, mtime: int) -> None:
        with tarfile.open(path, "w:gz") as archive:
            info = tarfile.TarInfo("package/file.txt")
            info.size = 7
            info.mode = 0o640
            info.mtime = mtime
            archive.addfile(info, io.BytesIO(b"payload"))

    def test_normalization_removes_build_time_without_changing_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first_source = root / "first.tar.gz"
            second_source = root / "second.tar.gz"
            first = root / "first.normalized.tar.gz"
            second = root / "second.normalized.tar.gz"
            self._source(first_source, 100)
            self._source(second_source, 200)

            normalize_sdist(first_source, first, epoch=123456789)
            normalize_sdist(second_source, second, epoch=123456789)

            self.assertEqual(first.read_bytes(), second.read_bytes())
            with gzip.open(first, "rb") as stream:
                with tarfile.open(fileobj=stream, mode="r:") as archive:
                    member = archive.getmember("package/file.txt")
                    self.assertEqual(member.mtime, 123456789)
                    self.assertEqual(member.mode, 0o640)
                    self.assertEqual(archive.extractfile(member).read(), b"payload")


if __name__ == "__main__":
    unittest.main()
