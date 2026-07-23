# Changelog

All notable changes to `coderisktools-scanner` are documented here.

## [Unreleased]

## [3.1.0] — 2026-07-23

### Added

- added the opt-in, read-only vulnerability inventory and matching pipeline with explicit local SQLite selection;
- added controlled, user-triggered staging/update, verification, reconciliation, rollback and retention operations;
- added bounded public feed adapters and explicit provenance/quality reports without claiming full-feed coverage;
- added a real partial `seed` snapshot with 187 advisories, 378 affected-package rows and seven represented OSV ecosystems;
- added signed, pinned seed bootstrap and a separate explicit `--profile seed --apply` activation command.

### Fixed

- directory self-scan now skips SQLite database artifacts, preventing the real seed from tripping the scanner byte cap in CI;
- bootstrap now verifies the detached Ed25519 manifest envelope, exact database SHA-256, SQLite integrity, foreign keys, snapshot identity and manifest counts before atomic installation.

### Seed boundary

- the seed is `completeness=partial` and `production_full_database=false`;
- 1,688 unresolved KEV/EPSS enrichments and 129 exact-alias conflicts are retained and disclosed rather than heuristically merged;
- an empty seed scan is not evidence that a project has no vulnerabilities;
- Core/Full activation remains separate and is never replaced automatically by seed bootstrap.

## [3.0.1] — 2026-07-20

### Changed

- refreshed the public package release metadata for the current Scanner flagship;
- updated the documented registry inventory to 299 native, 267 line and 32 contextual detectors;
- updated CI/CD coverage documentation to 73 policy detectors;
- synchronized install examples for pre-commit and GitHub Actions with `v3.0.1`.

### Security posture

- local-first and offline by default;
- no runtime telemetry;
- no runtime dependencies;
- bounded input handling;
- redacted output by default;
- no execution of target-project code;
- synthetic fixtures only in the public repository.

### Limitations

A clean result is not proof that code is secure. Findings can include false positives and false negatives. This release is not a security audit, certification, compliance guarantee or legal opinion.

## [3.0.0] — 2026-07-16

First public GitHub release of the MIT-licensed CodeRiskTools Secret Scanner Engine.

See the GitHub release notes and attached provenance files for the original 3.0.0 artifact record.
