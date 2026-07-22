# P0 Consolidation Audit — Vulnerability Module

Date: 2026-07-22

## Scope

This is a consolidation audit of the current `main` after Stage V0–V11. It does not claim that the repository is a complete multi-source vulnerability database. It records executable evidence, partial results and remaining gaps.

## Baseline

- Readback commit: `a8a9c0351f85b69f1225ed44598cb05d369aa66e`.
- Working tree: clean.
- Local interpreter exercised: Python 3.11.15.
- Test files: 167 total; 99 versioned vulnerability-oriented test files by the bounded inventory query.
- `pytest --collect-only -q`: 863 tests collected.
- Current Stage V11 checkboxes: all seven listed items checked, with OSV-Scanner, Trivy and Grype explicitly described as local external-evidence adapters rather than full evaluators.

## Executed evidence

### Tests and build gates

- `pytest -q`: 862 passed, 1 skipped, 909 subtests.
- `python3 -O -m pytest -q`: 862 passed, 1 skipped, 909 subtests; one expected pytest warning about assertions under `-O`.
- `python3 -m compileall -q src tests`: PASS.
- `git diff --check`: PASS.
- `secret-scanner scan --dir src --recursive --format json --profile balanced`: 0 findings.

The latest public CI run for the preceding provenance batch was also green on Python 3.10, 3.11, 3.12 and 3.13. Local execution in this audit was Python 3.11 only; this is not a substitute for a new CI run after later changes.

### Offline and no-subprocess boundary

A local process-level boundary test replaced socket constructors and subprocess entry points with failing sentinels. It then executed:

- local dependency inventory over a synthetic `requirements.txt`;
- ordinary recursive directory scan over synthetic files.

Observed result:

- inventory state: `ok`, one component;
- directory scan: zero secret findings, one config change;
- no forbidden socket or subprocess call occurred.

This proves the exercised inventory and ordinary directory-scan paths were offline and subprocess-free for this fixture. It does not prove every future code path or explicitly opted-in network/credential command is offline.

### SQLite health

A fresh database was opened and checked:

- `PRAGMA foreign_keys`: `1`;
- `PRAGMA integrity_check`: `ok`;
- `PRAGMA foreign_key_check`: `0` rows;
- metadata schema version: `4`;
- metadata schema status: `initialized`.

This is a verified health result for a fresh database, not yet a repository-wide health gate for every imported snapshot.

### Determinism and reproducibility

The same deterministic OSV fixture was imported into two fresh databases.

Equal:

- source digest;
- content digest;
- semantic snapshot manifest;
- advisory/component matching;
- vulnerability fingerprint: `sha256:22333d16122cd6befeeb1a4fe3c634b19e21d9ad4bed3ecd348386cd5575b973`.

The raw SQLite row dump differed only in `snapshots.manifest_json.source_path`, because the two fixtures were stored under different temporary directories. Therefore:

- semantic determinism: PASS;
- fingerprint determinism: PASS;
- raw byte-identical snapshot reproducibility: NOT YET PROVEN.

The source path should be canonicalized or excluded from reproducibility material before claiming byte-identical snapshot builds.

## Confirmed boundaries

- Secret/config output redaction remains isolated to the secret scanner contract.
- Vulnerability reports and OSV/Trivy/Grype evidence are not automatically redacted or truncated.
- External advisory payloads remain separate from local vulnerability finding fields.
- External evidence adapters do not execute OSV-Scanner, Trivy or Grype.
- Provenance sidecars verify source SHA-256 and tool identity, but do not turn external evidence into a local database match.

## Remaining P0/P1 gaps

The following are not marked complete by this audit:

- full multi-source database coverage, including distribution/vendor feeds;
- explicit `sources/osv.py` separation;
- isolated ecosystem/distribution version comparator package;
- full typed domain model for ranges, metrics, weaknesses, KEV/EPSS/SSVC, remediation and conflicts;
- normalized high-volume range/metric/source tables where JSON storage is currently used;
- a repository-wide imported-snapshot health gate using integrity/FK checks;
- byte-identical snapshot reproducibility independent of local source path;
- streaming/decompression/archive ingestion for large feeds;
- complete data license/attribution/redistribution matrix;
- public precision/recall/performance benchmark;
- complete production snapshot publication and air-gap bundle proof;
- a new CI run specifically attached to the post-audit `main` commit.

## Decision

Do not label the current module a full vulnerability database or production-ready full-feed aggregator. Keep the current bounded V0–V11 implementation, close the verified P0 evidence gaps, and then process comparator/source/model/health work as separate bounded batches. Each later batch must update the Master TODO only after RED/GREEN, full gates, CI and readback.
