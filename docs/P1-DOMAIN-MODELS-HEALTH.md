# P1 Domain Models and Snapshot Health

This document records the additive P1 domain-model and SQLite health contract.

## Domain models

`src/vulnerability/models.py` now exposes immutable dataclasses for:

- `AffectedRange`
- `SeverityMetric`
- `Weakness`
- `KevEntry`
- `EpssScore`
- `SsvcAssessment`
- `Remediation`
- `VulnerabilityFinding`
- `ConflictRecord`
- `LicenseRecord`
- `DatabaseHealth`

These models are additive. Existing scanner contracts (`Finding`, `ScanResult`, baseline and SARIF) are unchanged. Models expose deterministic field dictionaries through `to_dict()` and do not redact vulnerability evidence.

## Health gate

`VulnerabilityDatabase.snapshot_health()` is a read-only health report. It checks:

- SQLite `PRAGMA integrity_check`;
- required vulnerability tables and row-count readability;
- presence/absence of an active snapshot.

The result contains `healthy`, per-check statuses, counts, active `snapshot_id` when available, and machine-readable `issues`. Absence of an active snapshot is reported as `active_snapshot=absent` but is not itself a database-integrity failure; activation policy remains a separate updater gate.

This is a bounded health gate, not a claim that all source-quality, comparator, enrichment, or feed-freshness checks are complete.
