# CodeRiskTools Scanner 3.0.1 — release notes

## Scope

This release documents the local-first vulnerability snapshot foundations and
production-readiness checks added after the scanner's existing secret/config
scanning features. The release does not claim complete coverage of every
package ecosystem or advisory feed.

## Included and verified

- bounded OSV-shaped local ingestion and SQLite vulnerability matching;
- PURL normalization and explicit affected/not-affected/indeterminate status;
- bounded snapshot staging, quality checks, signing and air-gap export/import;
- bounded Linux distribution and package-ecosystem adapters;
- CSAF import with provider metadata, remediation preservation and a quality gate;
- offline benchmark fixtures, database integration, repeated performance runs
  and final quality/performance reports;
- production snapshot readiness, database health, source coverage, rollback
  planning and disaster-recovery checks;
- existing secret/config scan contracts, SARIF/JSON output and offline policy
  boundaries remain unchanged.

## Operational guarantees

Ordinary scans remain local-first and do not require network access. The tool
does not execute code from the target repository. Vulnerability evidence and
secret findings remain separate result domains. Secret contents may be
redacted by secret-output formatters; vulnerability evidence is not silently
redacted.

## Validation

The release gate was run locally with the project's test suite, optimized
Python test execution, bytecode compilation, whitespace validation and the
secret self-scan. Exact results are recorded in the project session/CI output;
packagers should rerun the same gates for their target platform.

## Upgrade note

Existing CLI, `Finding`, `ScanResult`, baseline, suppression, VEX and SARIF
contracts are preserved. Vulnerability database features are opt-in and use
explicit local inputs or already-staged snapshots.
