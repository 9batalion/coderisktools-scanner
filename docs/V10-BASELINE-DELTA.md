# V10 — vulnerability baseline/delta contract

```bash
python -m src vuln scan \
  --root REPOSITORY \
  --database vulnerability.sqlite \
  --baseline vulnerability-baseline.json \
  --format json
```

The delta schema is `coderisktools.vulnerability.delta`, version `1`, and contains:

- `new_findings`: exact current findings not present in the baseline;
- `existing_findings`: exact current findings present in the baseline;
- `resolved_fingerprints`: baseline fingerprints absent from the current scan;
- counts for baseline/current/new/existing/resolved;
- snapshot identity.

Baseline loading is strict and fail-closed. Invalid, duplicate, malformed, oversized, or symlink baselines are rejected. The delta report never hides current findings; it classifies them. `--baseline` currently requires JSON output because the delta schema is versioned JSON.
