# Global OSV SQLite snapshot

The global OSV builder imports the pinned OSV `all.zip` directly into a temporary SQLite database without extracting the archive to disk.

## Scope and naming

A successful artifact is labeled:

- `profile: global-osv`
- `completeness: full-osv-source`
- `production_full_database: false`

`full-osv-source` means that every accepted JSON member from the pinned global OSV archive was processed. It does **not** mean complete Core coverage, complete vulnerability coverage, or proof that an unmatched component is safe. GHSA, KEV, EPSS, NVD, distro feeds, and other enrichments have separate provenance and completeness requirements.

## Space-efficient evidence mode

The large snapshot uses `source_record_mode: digest-only`:

- normalized advisory, alias, package, range, version, reference, and matching data remain in SQLite;
- valid GIT/CVE records without an OSV `package` object remain as advisories and digest-backed source evidence; their affected entries are counted as `unmapped_affected_entries` and are not package-matchable;
- every source record keeps its source/native ID, SHA-256 content digest, record fingerprint, and advisory mapping;
- the duplicate full source JSON payload is omitted from SQLite;
- the exact pinned ZIP digest and source URL are retained in the manifest.

This avoids storing the same multi-gigabyte JSON payload twice while preserving verifiable provenance. The pinned ZIP remains the raw source artifact.

## Build

```bash
python scripts/build_global_osv_vulndb.py \
  --archive /path/to/all.zip \
  --source-manifest /path/to/manifest.json \
  --output /path/to/coderisktools-vulndb-global-osv.sqlite \
  --manifest-output /path/to/coderisktools-vulndb-global-osv.manifest.json \
  --sha256-output /path/to/coderisktools-vulndb-global-osv.sqlite.sha256 \
  --snapshot-id global-osv-YYYY-MM-DD
```

The builder:

1. rejects symlinks, unsafe paths, duplicate members, encrypted files, non-JSON payloads, oversized members, and oversized expanded archives;
2. verifies the pinned archive SHA-256 before import;
3. imports bounded batches with no archive extraction;
4. rejects the build if the configured import-error threshold is exceeded;
5. checks SQLite integrity and foreign keys;
6. generates a bounded-memory `compact-v1` content digest;
7. publishes manifest and checksum first and the SQLite readiness artifact last with no-overwrite hard links;
8. leaves the embedded snapshot **staged**, never active.

## GitHub Release ZIP and first-run installation

The repository never stores the multi-gigabyte database in Git history. Release `v3.1.0` publishes:

- `coderisktools-vulndb-global-osv-2026-07-23.sqlite.zip`;
- `coderisktools-vulndb-global-osv-2026-07-23.manifest.json`;
- `coderisktools-vulndb-global-osv-2026-07-23.manifest.sig.json`.

The ZIP contains exactly one SQLite member. On the first `vuln scan` invocation, when the default database path does not exist, the scanner:

1. downloads the pinned manifest and Ed25519 signature;
2. validates the embedded public key and profile contract;
3. streams the ZIP to disk with a 2 GiB compressed limit;
4. verifies the ZIP SHA-256;
5. validates the single-member ZIP contract and declared expanded size;
6. streams extraction with a 9 GiB database limit and SHA-256 verification;
7. runs SQLite integrity, foreign-key, compact-manifest, and snapshot quality gates;
8. atomically installs and locally activates the verified snapshot.

Default location:

```text
~/.local/share/coderisktools/vuln-db/global-osv.sqlite
```

Manual bootstrap:

```bash
secret-scanner vuln-db bootstrap-global
```

Automatic network bootstrap can be disabled with `vuln scan --no-bootstrap`.
