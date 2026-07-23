# CodeRiskTools Scanner 3.1.0 — release notes

CodeRiskTools Scanner 3.1.0 adds a controlled, local-first vulnerability database workflow, a small verified **partial seed**, and a pinned signed global OSV SQLite ZIP for first-use installation.

## What is included

- opt-in local dependency inventory and vulnerability matching;
- user-triggered staging, verification, reconciliation, rollback and retention commands;
- bounded source adapters and explicit provenance/quality evidence;
- a 5.9 MB SQLite seed with 187 advisories and 378 affected-package rows;
- represented OSV ecosystems: PyPI, npm, Go, crates.io, Maven, NuGet and Packagist;
- signed pinned bootstrap that installs seed as staged only;
- explicit `vuln-db activate --profile seed --apply` activation;
- real lodash `4.17.15` end-to-end matching evidence with stable fingerprints.
- streamed first-use global database bootstrap with ZIP/database SHA-256, Ed25519, SQLite integrity, foreign-key and compact-manifest verification;
- automatic installation to `~/.local/share/coderisktools/vuln-db/global-osv.sqlite` when the default database is missing;
- `vuln-db bootstrap-global` for an explicit installation and `vuln scan --no-bootstrap` to disable automatic network bootstrap.

## Release assets

- Python wheel and source distribution;
- `coderisktools-vulndb-seed-2026-07-23.sqlite`;
- detached seed manifest;
- SHA-256 sidecar;
- Ed25519 signed manifest envelope (`.sig` JSON);
- public release keyring.
- global OSV single-SQLite ZIP, detached manifest and Ed25519 signed manifest envelope.

## Verified seed facts

- `profile=seed`;
- `completeness=partial`;
- `production_full_database=false`;
- SQLite `PRAGMA integrity_check=ok`;
- SQLite `PRAGMA foreign_key_check=0`;
- database SHA-256 `2bf63ca969a56a12551c491a956746d504409f13ea1c006abcf19e52ff0e6b04`;
- CISA KEV: 1,653 processed, 2 exact enrichments, 1,651 unresolved retained;
- EPSS: 54 processed, 17 exact enrichments, 37 unresolved retained;
- GHSA: bounded 100 imported;
- OSV: 87 imported.

## Important limitations

The seed is not Core, Full, Production or Complete. The global snapshot is labeled `full-osv-source`, not complete Core coverage or proof that an unmatched component is safe. It retains exact-alias conflicts rather than heuristically merging advisories. A zero-finding scan is not proof that a project has no vulnerabilities. Secret/config scans remain offline; the first default vulnerability scan downloads only the pinned signed release asset, and subsequent matching is local.

A clean scanner result is not proof that code is secure. This release is not a security audit, certification, compliance guarantee or legal opinion.
