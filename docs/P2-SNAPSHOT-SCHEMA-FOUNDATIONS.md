# P2 Snapshot Schema Foundations

The database schema now includes additive tables for production updater foundations:

- `schema_migrations`: migration identifier, applied timestamp, checksum;
- `source_snapshots`: per-source content digest, observation status and record count within a snapshot;
- `import_errors`: bounded per-record import failures with source/native ID and digest;
- `quality_metrics`: named numeric quality gates with structured details.

The schema retains the existing public schema version `4`; these tables are additive groundwork and do not change the existing schema-version contract. Existing databases receive them through the idempotent `CREATE TABLE IF NOT EXISTS` path. No activation, rollback, network fetch, or source import is performed by this change.

The existing `snapshot_health()` report includes read-count checks for all four tables. This is schema groundwork only; production updater streaming, atomic activation, rollback and retention remain separate P2 batches.

## Streaming artifact acquisition

`stream_json_artifact_to_file()` is an additive updater API for bounded HTTPS
responses. It reads chunks directly into a private temporary file, enforces the
response byte limit both from `Content-Length` and while reading, fsyncs the
temporary file, and atomically replaces the destination only after success.
It returns metadata and a SHA-256 digest rather than payload bytes. Existing
`fetch_json_artifact()` remains unchanged for callers that require the legacy
in-memory contract. Archive decompression and post-decompression limits remain
separate tasks.

## Safe archive extraction

`extract_archive_to_directory()` supports bounded ZIP, tar-family and single
gzip payload extraction. It rejects absolute/parent-traversing member paths,
ZIP symlinks, tar symlinks/hardlinks/special files, excessive member counts,
per-member decompressed bytes and total decompressed bytes. Extraction occurs
in a private temporary directory and the destination directory is atomically
published only after all members succeed. Existing destinations are refused;
the function never merges untrusted archive content into an existing tree.

## Incremental JSON records

`iter_json_records_from_file()` yields object records from a JSON array or
JSONL file using a bounded decoder buffer and line streaming. It enforces
maximum file bytes, record bytes and record count. It is intentionally a
separate parser contract; existing OSV ingestion APIs remain unchanged until
an explicit integration batch wires this iterator into source import and
per-record error accounting.
