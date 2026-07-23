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
