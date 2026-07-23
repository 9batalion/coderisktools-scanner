#!/usr/bin/env python3
"""Normalize a Python sdist tar.gz to deterministic release bytes."""
from __future__ import annotations

import argparse
import copy
import gzip
import os
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

MAX_MEMBERS = 10_000
MAX_TOTAL_BYTES = 256 * 1024 * 1024


def _safe_name(name: str) -> None:
    path = PurePosixPath(name)
    if not name or path.is_absolute() or ".." in path.parts or "\\" in name or "\x00" in name:
        raise ValueError("sdist contains an unsafe member path")


def normalize_sdist(source: str | os.PathLike[str], destination: str | os.PathLike[str], *, epoch: int) -> None:
    """Rewrite a regular-file/directory sdist with fixed metadata and gzip header."""
    if type(epoch) is not int or epoch < 0:
        raise ValueError("epoch must be a non-negative integer")
    source_path = Path(source)
    destination_path = Path(destination)
    if source_path.is_symlink() or not source_path.is_file():
        raise ValueError("source sdist must be a regular non-symlink file")
    if destination_path.is_symlink() or source_path.resolve() == destination_path.resolve(strict=False):
        raise ValueError("destination must be a distinct non-symlink path")
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{destination_path.name}.", dir=str(destination_path.parent))
    os.close(fd)
    temporary = Path(temp_name)
    seen: set[str] = set()
    total = 0
    try:
        with tarfile.open(source_path, "r:gz") as input_archive:
            members = input_archive.getmembers()
            if not members or len(members) > MAX_MEMBERS:
                raise ValueError("sdist member count is outside the allowed range")
            with temporary.open("wb") as raw_output:
                with gzip.GzipFile(filename="", mode="wb", fileobj=raw_output, compresslevel=9, mtime=epoch) as gzip_output:
                    with tarfile.open(fileobj=gzip_output, mode="w", format=tarfile.PAX_FORMAT) as output_archive:
                        for original in members:
                            _safe_name(original.name)
                            if original.name in seen:
                                raise ValueError("sdist contains duplicate member paths")
                            seen.add(original.name)
                            if not (original.isfile() or original.isdir()):
                                raise ValueError("sdist contains an unsupported member type")
                            total += original.size
                            if total > MAX_TOTAL_BYTES:
                                raise ValueError("sdist payload exceeds the byte limit")
                            member = copy.copy(original)
                            member.mtime = epoch
                            member.uid = 0
                            member.gid = 0
                            member.uname = ""
                            member.gname = ""
                            member.pax_headers = {}
                            if member.isfile():
                                stream = input_archive.extractfile(original)
                                if stream is None:
                                    raise ValueError("sdist regular member cannot be read")
                                output_archive.addfile(member, stream)
                            else:
                                output_archive.addfile(member)
                raw_output.flush()
                os.fsync(raw_output.fileno())
        os.replace(temporary, destination_path)
    except BaseException:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source")
    parser.add_argument("destination")
    parser.add_argument("--epoch", type=int, required=True)
    args = parser.parse_args()
    normalize_sdist(args.source, args.destination, epoch=args.epoch)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
