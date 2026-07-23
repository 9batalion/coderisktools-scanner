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

## Streaming OSV integration

`ingest_osv_streaming_file()` and the OSV source adapter's
`ingest_streaming_file()` connect the file iterator to a two-pass import:

1. validate all records in an in-memory validation database;
2. re-iterate the local file and import into the target database only when validation succeeds;
3. stage the snapshot and record `source_snapshots` plus three bounded `quality_metrics`;
4. record parser/import failures in `import_errors`.

The API is local-only and unsigned by design. Signed OSV envelopes continue to
use the existing full-envelope verification path. Activation remains explicit
through `activate=True` and is never implicit.

## Activation quality gate

`VulnerabilityDatabase.snapshot_quality_gate(snapshot_id)` is a read-only
pre-activation gate. It runs SQLite `PRAGMA integrity_check`,
`PRAGMA foreign_key_check`, verifies the staged snapshot state and compares the
stored manifest against the current deterministic manifest for content digest,
advisory count and affected-package count. `activate_snapshot()` now invokes
this gate and raises `SnapshotActivationError` on any failed check; no active
snapshot pointer or metadata is changed on failure.

## Signed snapshot manifests

`vulnerability.manifest_signing` defines the canonical Ed25519 envelope
`coderisktools.vulnerability.signed-manifest` version `1`. The signed payload
is deterministic JSON (`sort_keys`, compact separators, UTF-8). `sign_manifest`
uses the optional `cryptography` backend; installations without that optional
backend fail closed rather than silently falling back to HMAC or an unsigned
manifest. `verify_manifest` uses the repository's existing Ed25519 verifier,
and `stage_signed_snapshot()` verifies the envelope before staging. Tampering
with any manifest field is rejected.

## Air-gap bundles

`vulnerability.airgap` provides `export_air_gap_bundle()` and
`import_air_gap_bundle()`. A bundle contains `manifest.json` and
`snapshot.sqlite` in a bounded `tar.gz`. Import uses the safe archive extractor,
opens the staged SQLite database read-only, runs the database health gate and
compares the deterministic manifest before an fsync plus atomic replacement.
It never activates a snapshot; activation remains a separate explicit action.

## Explicit retention and prune

`VulnerabilityDatabase.prune_snapshots(keep_snapshot_ids, apply=False)` first
returns a deterministic dry-run plan. Only an explicit `apply=True` deletes
snapshot metadata outside the allowlist; active snapshots are never candidates.
Related `source_snapshots`, `import_errors` and `quality_metrics` rows are
removed together. This API does not infer retention from timestamps because
the current snapshot schema has no trusted acquisition timestamp.

## V12a Debian adapter boundary

`vulnerability.sources.debian.ingest_file()` is a bounded, local-only parser
for the versioned Debian feed fixture format. It preserves release,
source-package, binary-package, urgency, fixed-version and backport metadata.
It does not fetch Debian infrastructure, claim complete Security Tracker/OVAL
coverage, or activate/import records into the vulnerability database yet.

V12a now also provides `ingest_file_to_database()`: it maps Debian binary
packages and fixed versions into the existing OSV-shaped bounded importer,
stages a snapshot without implicit activation, preserves Debian backport data
in `database_specific`, and writes `source_snapshots` plus `quality_metrics`.
This remains fixture-format support, not a claim of complete Debian feed
coverage.

Debian fixed-only advisories are normalized as an explicit OSV range with
`introduced: "0"` followed by the Debian fixed revision. This makes the
backport boundary testable: a revision below `3.0.11-1~deb12u2` is affected,
while that revision and later revisions are not affected under the Debian
comparator. This is bounded matching behavior, not complete Debian archive
coverage.

The V12b Ubuntu adapter currently provides the same bounded fixture/provenance
boundary for Ubuntu releases. It is parser-only and does not claim complete
USN/Ubuntu archive coverage or database staging until its dedicated integration
batch is completed.

V12c adds the Ubuntu staging bridge using the same lifecycle contract as
Debian: normalized OSV-shaped records, staged snapshots without implicit
activation, source provenance, `source_snapshots`, and quality metrics. This
does not claim complete USN or Ubuntu archive coverage.

Ubuntu fixed-version boundaries are covered by an integration test through
`evaluate_component()`. A version below the normalized fixed revision is
classified as affected, while the fixed revision is classified as not affected.

V12e applies the same bounded staging contract to Red Hat fixtures, using the
RPM ecosystem and preserving RHSA severity, release, backport, and source
provenance metadata. This is not a claim of complete Red Hat advisory feed
coverage.

V12f applies the bounded staging contract to SUSE/SLES fixtures through the RPM
ecosystem, preserving release, severity, backport, and provenance metadata.
Full SUSE advisory-feed coverage is intentionally not claimed yet.

V12g extends the same bounded staging contract to Alpine APK fixtures and
verifies APK version revision ordering through `compare_alpine_version()`.

V12h adds a cross-distro bounded backport contract test covering Debian,
Ubuntu, Red Hat, SUSE, and Alpine. It verifies preservation of backport flags,
fixed versions, and provenance digests without claiming complete real-feed
backport coverage.

V13a adds a bounded Maven fixture/staging boundary with Maven coordinate
validation, fixed-version range matching, source provenance, and lifecycle
quality metadata. It does not claim complete Maven advisory coverage.

V13b adds the same bounded fixture/staging boundary for NuGet package IDs,
including fixed-version matching and lifecycle provenance. Complete NuGet
advisory coverage is not claimed.

V13c adds the same bounded fixture/staging boundary for RubyGems names,
including fixed-version matching and lifecycle provenance. Complete RubyGems
advisory coverage is not claimed.

V13d adds the same bounded fixture/staging boundary for Swift package
identities, including fixed-version matching and lifecycle provenance.
Complete Swift advisory coverage is not claimed.

V13e adds the same bounded fixture/staging boundary for Dart/pub package names,
including fixed-version matching and lifecycle provenance. Complete Dart
advisory coverage is not claimed.

V13f adds the same bounded fixture/staging boundary for Elixir/Hex package
names, including fixed-version matching and lifecycle provenance. Complete
Elixir advisory coverage is not claimed.

V13g adds the same bounded fixture/staging boundary for Haskell/Hackage package
names, including fixed-version matching and lifecycle provenance. Complete
Haskell advisory coverage is not claimed.

V13h adds the same bounded fixture/staging boundary for R/CRAN package names,
including fixed-version matching and lifecycle provenance. Complete R advisory
coverage is not claimed.

V13i adds the same bounded fixture/staging boundary for Conan package
references, including fixed-version matching and lifecycle provenance.
Complete Conan advisory coverage is not claimed.

V13j adds the same bounded fixture/staging boundary for vcpkg port names,
including fixed-version matching and lifecycle provenance. Complete vcpkg
advisory coverage is not claimed.

V14a adds a bounded generic CSAF 2.0 staging boundary with product-tree/PURL
mapping and `known_affected` preservation. Provider registry, remediations,
health and complete CSAF coverage are not claimed.

V14b adds a deterministic CSAF provider registry and health-state contract.
Registry operations are local and do not perform implicit network calls.
