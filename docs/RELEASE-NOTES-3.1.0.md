# CodeRiskTools Scanner 3.1.0 — release notes

CodeRiskTools Scanner 3.1.0 adds a controlled, local-first vulnerability database workflow and publishes a real, verified **partial seed** snapshot for bootstrap and integration testing.

## What is included

- opt-in local dependency inventory and vulnerability matching;
- user-triggered staging, verification, reconciliation, rollback and retention commands;
- bounded source adapters and explicit provenance/quality evidence;
- a 5.9 MB SQLite seed with 187 advisories and 378 affected-package rows;
- represented OSV ecosystems: PyPI, npm, Go, crates.io, Maven, NuGet and Packagist;
- signed pinned bootstrap that installs seed as staged only;
- explicit `vuln-db activate --profile seed --apply` activation;
- real lodash `4.17.15` end-to-end matching evidence with stable fingerprints.

## Release assets

- Python wheel and source distribution;
- `coderisktools-vulndb-seed-2026-07-23.sqlite`;
- detached seed manifest;
- SHA-256 sidecar;
- Ed25519 signed manifest envelope (`.sig` JSON);
- public release keyring.

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

This seed is not Core, Full, Production or Complete. It retains 129 exact-alias conflicts rather than heuristically merging advisories. A zero-finding seed scan is not proof that a project has no vulnerabilities. Updates remain user-triggered; ordinary scanner runs do not download feeds.

A clean scanner result is not proof that code is secure. This release is not a security audit, certification, compliance guarantee or legal opinion.
