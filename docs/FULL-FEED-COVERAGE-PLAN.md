# Full feed coverage plan

## Objective

Build a reproducible local vulnerability database from declared sources without
claiming universal ecosystem coverage. A feed becomes `ready` only after its
adapter, fixture corpus, provenance, license/terms review, quality gate,
rebuild determinism and rollback path pass.

## Source waves

### Wave 1 — core advisory and exploitation sources

- OSV
- NVD
- CISA KEV
- EPSS
- GitHub Advisory Database

### Wave 2 — Linux distributions

- Debian Security
- Ubuntu Security
- Red Hat Security
- SUSE Security
- Alpine Security

### Wave 3 — CSAF providers

- Generic CSAF 2.0
- Provider-specific product trees
- Provider-specific status and remediation semantics

### Wave 4 — package ecosystems

- PyPI
- npm
- crates.io
- Maven Central
- NuGet
- remaining ecosystem adapters

## Per-feed implementation contract

1. Declare endpoint, source identity, terms/license status and update cadence.
2. Fetch only through the existing HTTPS allowlist, bounded streaming and
   conditional request policy.
3. Verify content type, size, digest and source provenance.
4. Parse into the existing OSV-shaped import boundary without changing
   `Finding`, `ScanResult` or fingerprint contracts.
5. Preserve source-native identifiers, aliases, references and raw status.
6. Run quality metrics and reject invalid snapshots before activation.
7. Test malformed, oversized, duplicate, stale and semantically ambiguous data.
8. Rebuild twice and compare artifact digests.
9. Verify rollback and air-gap export/import.
10. Mark the feed `ready` only when all evidence is stored.

## Current status

`src/vulnerability/feed_catalog.py` is metadata-only. It deliberately reports
all sources as `bounded` or `contract-only`; no source is `ready` yet. The
catalog never downloads or activates a feed.

## Non-goals

- No assertion that all advisories worldwide are covered.
- No package-manager execution.
- No execution of scanned repository code.
- No automatic activation after download.
- No redistribution of source data before terms/license verification.
