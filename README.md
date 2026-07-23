# CodeRiskTools Secret Scanner Engine

**Local-first, offline-by-default scanner for secret-like values, risky configuration changes and opt-in local vulnerability analysis.**

CodeRiskTools Secret Scanner Engine is MIT licensed and has no runtime dependencies. It scans diffs, staged changes, local directories and bounded Git history without executing target-project code. Vulnerability analysis is a separate, explicitly selected local SQLite/SBOM path.

> Evidence, not guarantees. A clean result is not proof that code is secure. Findings can contain false positives and false negatives. This tool is not a security audit, certification, legal opinion or compliance guarantee.

## Features

- unified-diff, staged, directory and bounded Git-history scanning;
- strict JSON, Markdown, HTML, SARIF and GitHub output;
- 297 native detectors in the current public registry, including stable secret-format and CI/CD policy detectors;
- allowlists, strict baselines, severity profiles and signed offline rule packs;
- local Gitleaks JSON/SARIF import and explicitly supplied local Gitleaks binary mode;
- generic, Codex-labelled and Claude Code-labelled offline agent hooks;
- pre-commit integration and composite GitHub Action;
- local dependency inventory from a repository, CycloneDX JSON, SPDX JSON or Syft JSON;
- local OSV-Scanner JSON as explicitly separated external evidence;
- local Trivy JSON as explicitly separated external evidence;
- local Grype JSON as explicitly separated external evidence;
- local SQLite vulnerability snapshot scanning and reports;
- snapshot reconciliation, verification, status, update, rollback, retention pruning and provenance fetch commands;
- OpenVEX/CycloneDX VEX annotations, suppression and vulnerability baselines;
- no telemetry, no target-project execution and no network during ordinary scans.

The stable detector count excludes provisional candidates. See the detector backlog and source records in [`docs/STAGE6_SECRET_DETECTOR_BACKLOG.md`](docs/STAGE6_SECRET_DETECTOR_BACKLOG.md) and [`docs/STAGE8_CI_CD_BATCH1_SOURCES.md`](docs/STAGE8_CI_CD_BATCH1_SOURCES.md).

## Product boundary

This repository contains only the public Scanner flagship. It does not contain or license the proprietary MCPwatch Scanner or AI Change Firewall products. See [`docs/PRODUCT_BOUNDARY.md`](docs/PRODUCT_BOUNDARY.md).

## Requirements and installation

- Python 3.10–3.13;
- Git is required for `--staged` and `--git-history` modes;
- ordinary scanning does not require network access or third-party runtime packages.

From a checkout:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install --no-deps .
secret-scanner --version
```

When running without installation, use `python -m src` in place of `secret-scanner`.

## CLI overview

```text
secret-scanner
├── scan                 secrets/config scan
├── osv-import           import one explicitly supplied local OSV feed
├── vuln inventory       local dependency inventory or OSV-Scanner evidence
├── vuln scan            local vulnerability scan against SQLite snapshot
├── vuln-db              snapshot store, update and provenance operations
├── verify               optional explicit GitHub/Stripe credential check
├── rules                signed offline rule-pack install/rollback
└── hook                 bounded offline AI-agent hook envelope
```

Every command supports `--help`; `secret-scanner --version` prints the installed version.

## 1. Secret and configuration scanning

All `scan` modes require exactly one input source:

### Unified diff

```bash
secret-scanner scan \
  --diff changes.diff \
  --profile balanced \
  --format json
```

### Staged changes

```bash
secret-scanner scan \
  --staged \
  --profile balanced \
  --format github
```

This reads staged Git diff bytes and does not invoke external diff/text-conversion helpers.

### Local directory

```bash
secret-scanner scan \
  --dir . \
  --recursive \
  --profile strict \
  --format sarif \
  --output secret-results.sarif
```

Directory mode skips repository metadata, common dependency/build directories, binary formats and symlinks. Reads are bounded and descriptor-pinned.

### Bounded Git history

```bash
secret-scanner scan \
  --git-history \
  --since-ref origin/main \
  --max-commits 100 \
  --format json
```

`--max-commits` accepts 1–1000 and defaults to 100.

### Gitleaks report import

```bash
secret-scanner scan \
  --gitleaks-report gitleaks.json \
  --format json
```

The imported report must be a strict redacted Gitleaks JSON/SARIF document. This mode does not claim that the external tool was executed by CodeRiskTools.

### Explicit local Gitleaks binary

```bash
secret-scanner scan \
  --gitleaks-binary ./bin/gitleaks \
  --format json
```

The binary path is explicitly supplied by the operator. Do not use this mode with untrusted binaries.

### Scan options

- `--format {json,markdown,html,sarif,github}` — output format, default `json`;
- `--output FILE` — write report instead of stdout;
- `--profile {balanced,strict,secrets-only}` — policy profile;
- `--severity-threshold {low,medium,high,critical}` — minimum severity;
- `--config FILE` — severity/config policy file;
- `--config-check` / `--no-config-check` — override configuration detection;
- `--allowlist FILE` — `.secretsallowlist` file;
- `--baseline FILE` — strict secret/config finding baseline;
- `--write-baseline FILE` — atomically write the current unsuppressed baseline;
- `--force-baseline` — allow replacement of an existing regular baseline;
- `--rule-pack FILE` and `--rule-keyring FILE` — use a signed offline rule pack; both must be supplied together;
- `--recursive` — recurse in directory mode;
- `--quiet` — omit summary where supported.

### Optional vulnerability integration in directory scan

These options are valid with `--dir`:

```bash
secret-scanner scan \
  --dir . \
  --recursive \
  --vulnerability-db vulnerability.sqlite \
  --vulnerability-baseline vulnerability-baseline.json \
  --write-vulnerability-baseline next-baseline.json \
  --vulnerability-policy vulnerability-policy.json \
  --format json
```

- `--vulnerability-db FILE` — local SQLite database;
- `--vulnerability-baseline FILE` — suppress explicitly baselined vulnerability fingerprints;
- `--write-vulnerability-baseline FILE` — write vulnerability fingerprints;
- `--force-vulnerability-baseline` — allow overwrite;
- `--vulnerability-policy FILE` — local vulnerability severity policy.

These options require `--dir`. They do not change legacy secret/config scan contracts.

## 2. Output formats and exit codes

Secret/config scan formats:

- `json` — machine-readable full report;
- `markdown` — human-readable report;
- `html` — standalone local HTML report;
- `sarif` — SARIF-compatible findings;
- `github` — GitHub workflow annotations.

Vulnerability scan formats are `json`, `sarif`, `markdown`, `html` and `csv`.

Exit codes:

- `0` — clean or warning-only result;
- `1` — secret/vulnerability finding at the configured failure threshold;
- `2` — risky configuration/policy finding without a failing secret;
- `3` — malformed, unsafe, oversized or operationally rejected input.

Exact runtime evidence is preserved. Findings are not automatically redacted or truncated.

## 3. Offline dependency inventory

### Repository inventory

```bash
secret-scanner vuln inventory --root .
```

### CycloneDX, SPDX or Syft JSON

```bash
secret-scanner vuln inventory --sbom bom.json
```

The inventory path is read-only and local. It does not resolve packages from the network.

### Grype external evidence

```bash
secret-scanner vuln inventory --grype grype.json
```

The Grype adapter accepts bounded native Grype JSON, preserves descriptor version, artifact identity, locations, vulnerability ID and related aliases, and emits `coderisktools.vulnerability.external-evidence` with `evidence_type: external-tool`. It does not execute Grype or convert its matches into dependency inventory.
### Trivy external evidence

```bash
secret-scanner vuln inventory --trivy trivy.json
```

The Trivy adapter accepts bounded local Trivy JSON (`SchemaVersion` 1 or 2), preserves target/package/vulnerability data and emits the same `coderisktools.vulnerability.external-evidence` schema with `evidence_type: external-tool`. It does not execute Trivy or convert its findings into dependency inventory.
### OSV-Scanner external evidence

```bash
secret-scanner vuln inventory --osv-scanner osv-scanner.json
```

This is intentionally not dependency inventory. The output schema is:

```text
coderisktools.vulnerability.external-evidence
```

Each finding is marked `evidence_type: external-tool` and retains the OSV-Scanner source path, package identity, vulnerability ID and aliases. The provenance sidecar is optional and is verified against the actual input bytes:

```bash
secret-scanner vuln inventory \
  --osv-scanner osv-scanner.json \
  --provenance osv-scanner.provenance.json
```

The sidecar schema is `coderisktools.vulnerability.external-evidence-provenance` v1 and includes `source_id`, `source_format`, `source_sha256`, timezone-aware `collected_at`, `collector` and `tool_version`. The source digest and tool identity must match the evidence report. Tampered or mismatched sidecars fail closed. The adapter also validates tool version, bounded arrays, package identity, PURL and aliases. It does not run OSV-Scanner.


## 4. Local vulnerability scanning

The vulnerability path requires an explicitly supplied local SQLite database with an active snapshot:

```bash
secret-scanner vuln scan \
  --root . \
  --database vulnerability.sqlite \
  --format json
```

Optional annotations:

```bash
secret-scanner vuln scan \
  --root . \
  --database vulnerability.sqlite \
  --baseline vulnerability-baseline.json \
  --vex openvex-or-cyclonedx-vex.json \
  --suppressions suppressions.json \
  --format json \
  --output vulnerability-report.json
```

Options:

- `--root DIR` — local repository root;
- `--database FILE` — local regular SQLite database;
- `--format {json,sarif,markdown,html,csv}`;
- `--output FILE` — write the report atomically;
- `--baseline FILE` — JSON format emits new/existing/resolved delta;
- `--vex FILE` — local OpenVEX or CycloneDX VEX;
- `--suppressions FILE` — strict local suppression document.

Matching is offline, active-snapshot-only and read-only. The database path cannot be a symlink, URL or non-regular file.

## 5. OSV feed import

Import one explicitly supplied local OSV JSON feed:

```bash
secret-scanner osv-import \
  --input osv-all.json \
  --db vulnerability.sqlite \
  --snapshot-id osv-2026-07-22 \
  --source-id osv \
  --activate
```

Options:

- `--input FILE` — local OSV JSON; URLs are rejected;
- `--db FILE` — target local SQLite database;
- `--snapshot-id ID` — staged snapshot identifier;
- `--source-id ID` — source identifier;
- `--activate` — explicitly activate after successful import;
- `--keyring FILE` — trusted offline Ed25519 keyring for signed feed envelopes.

Activation is explicit. Ordinary scans do not update the database.

## 6. Vulnerability snapshot store (`vuln-db`)

### Reconcile metadata

```bash
secret-scanner vuln-db reconcile \
  --root snapshots \
  --active snapshots/active
```

Use `--output report.json` for an atomic local report file.

### Status and list snapshots

```bash
secret-scanner vuln-db status --root snapshots --active snapshots/active
secret-scanner vuln-db list-snapshots --root snapshots --active snapshots/active
```

### Verify one snapshot

```bash
secret-scanner vuln-db verify --snapshot snapshots/osv-2026-07-22
```

### Stage a local update

```bash
secret-scanner vuln-db update \
  --input osv-all.json \
  --root snapshots \
  --source-id osv \
  --snapshot-id osv-2026-07-22 \
  --active snapshots/active
```

Add `--apply` only when the operator explicitly wants to switch the active pointer.

### Source status and active database metadata

```bash
secret-scanner vuln-db source-status \
  --root snapshots \
  --active snapshots/active

secret-scanner vuln-db database-info \
  --active snapshots/active
```

### Explain one persisted match

```bash
secret-scanner vuln-db explain \
  --database vulnerability.sqlite \
  --fingerprint sha256:...
```

### Rollback

```bash
secret-scanner vuln-db rollback \
  --active snapshots/active \
  --target snapshots/previous \
  --apply
```

Rollback requires `--apply`; without it the command rejects the operation.

### Retention pruning

Dry-run is the default:

```bash
secret-scanner vuln-db prune \
  --root snapshots \
  --active snapshots/active \
  --keep-snapshot-id osv-2026-07-22
```

Deletion requires explicit `--apply`:

```bash
secret-scanner vuln-db prune \
  --root snapshots \
  --active snapshots/active \
  --keep-snapshot-id osv-2026-07-22 \
  --apply
```

### Explicit allowlisted HTTPS fetch

This is the only `vuln-db` operation that performs network I/O, and it requires an explicit allowlist:

```bash
secret-scanner vuln-db fetch \
  --url https://example.invalid/feed.json \
  --allowed-host example.invalid \
  --source-id example \
  --output staging/example.json \
  --provenance staging/example.provenance.json
```

Available fetch controls:

- `--conditions FILE` — verified provenance sidecar for conditional headers;
- `--etag VALUE` and `--last-modified VALUE` — conditional request values;
- `--max-bytes N` — response size limit;
- `--timeout SECONDS`;
- `--max-attempts N`;
- `--backoff-seconds SECONDS`.

The URL must be HTTPS, host-allowlisted and free of userinfo. Redirects are allowlist-checked. Fetching is separate from staging and activation.

## 7. VEX, suppressions and baselines

OpenVEX and CycloneDX VEX documents are local inputs. `not_affected` requires a justification. Suppression schema v1 remains supported; schema v2 can include:

```json
{
  "schema": "coderisktools.vulnerability.suppressions",
  "version": 2,
  "entries": [
    {
      "fingerprint": "sha256:<64 lowercase hex characters>",
      "reason": "accepted risk",
      "owner": "security",
      "ticket": "SEC-123",
      "scope": "service-a",
      "expires_at": "2026-12-31"
    }
  ]
}
```

Expiry and usage are reported by the Python API `suppression_lifecycle_report`; expired entries are not silently discarded. Vulnerability baselines are separate from secret/config baselines.

## 8. Optional credential verification

```bash
secret-scanner verify \
  --provider github \
  --credential-env GITHUB_TOKEN \
  --consent-network
```

Supported providers are `github` and `stripe`. The credential is read from the named environment variable. Network access is disabled unless `--consent-network` is present. Never put a real credential in command arguments, fixtures or documentation.

## 9. Signed offline rule packs

Install:

```bash
secret-scanner rules install \
  --source rule-pack.json \
  --destination .coderisktools/rules \
  --keyring trusted-keyring.json
```

Rollback:

```bash
secret-scanner rules rollback \
  --destination .coderisktools/rules \
  --keyring trusted-keyring.json
```

For scanning, supply the installed pack and its trusted keyring together:

```bash
secret-scanner scan \
  --dir . \
  --rule-pack .coderisktools/rules/active.json \
  --rule-keyring trusted-keyring.json
```

## 10. Agent-hook envelopes

The hook command accepts a bounded offline envelope from a generic, Codex-labelled or Claude Code-labelled adapter:

```bash
cat hook-payload.json | secret-scanner hook \
  --agent generic \
  --baseline hook-baseline.json \
  --config severity-config.json
```

Valid agents: `generic`, `codex`, `claude-code`. This is an explicit input contract, not a claim of undocumented vendor-native compatibility. See [`integrations/AI_AGENT_HOOKS.md`](integrations/AI_AGENT_HOOKS.md).

## 11. Pre-commit and GitHub Action

### Pre-commit

```yaml
repos:
  - repo: https://github.com/9batalion/coderisktools-scanner
    rev: v3.0.1
    hooks:
      - id: coderisktools-secret-scan
```

The hook scans staged Git diff bytes and does not run project builds or tests.

### GitHub Action

```yaml
name: CodeRiskTools Scanner
on:
  pull_request:
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0
        with:
          fetch-depth: 0
      - uses: 9batalion/coderisktools-scanner@v3.0.1
        with:
          profile: balanced
```

The Action analyzes bounded Git diff bytes, does not install target dependencies and does not execute target-project code.

## Security and operating boundaries

- offline by default; no telemetry;
- no runtime dependencies;
- no target-project execution;
- no ordinary-scan network access;
- explicit local paths only for databases, feeds, SBOMs, VEX and reports;
- symlinks, traversal paths, malformed documents and oversized inputs are rejected;
- external evidence is kept separate from local inventory and vulnerability findings;
- runtime vulnerability evidence is not auto-redacted or truncated;
- signed rule packs and feed envelopes require trusted local keyrings;
- networked credential verification and allowlisted fetch are explicit opt-in operations.

## Development and verification

```bash
python -m unittest discover -s tests -p 'test_*.py' -v
pytest -q
python -m compileall -q src tests
secret-scanner scan --dir src --recursive --format json
```

Contributions must use synthetic fixtures only. Never submit live credentials, private findings, customer repositories or proprietary MCPwatch/Firewall source. Changes to controlled fixtures must follow [`docs/SELF_SCAN_BASELINE.md`](docs/SELF_SCAN_BASELINE.md).

## Documentation map

- [`docs/P1-VERSION-COMPARATORS.md`](docs/P1-VERSION-COMPARATORS.md) — bounded comparator contract and explicit unsupported ecosystem semantics;
- [`docs/P0-CONSOLIDATION-AUDIT-V0-V11.md`](docs/P0-CONSOLIDATION-AUDIT-V0-V11.md) — executable P0 evidence, reproducibility result and remaining gaps;
- [`docs/VULNERABILITY-DATABASE-MASTER-TODO-HERMES.md`](docs/VULNERABILITY-DATABASE-MASTER-TODO-HERMES.md) — staged vulnerability roadmap;
- [`docs/MASTER-TODO-GAPS-AUDIT.md`](docs/MASTER-TODO-GAPS-AUDIT.md) — confirmed implementation gaps;
- [`docs/V4A-VULNERABILITY-PIPELINE.md`](docs/V4A-VULNERABILITY-PIPELINE.md) — local vulnerability pipeline;
- [`docs/V9F-OFFLINE-SCAN-CLI.md`](docs/V9F-OFFLINE-SCAN-CLI.md) — vulnerability scan CLI;
- [`docs/V10-BASELINE-DELTA.md`](docs/V10-BASELINE-DELTA.md) — baseline and delta;
- [`docs/V10-VEX-SUPPRESSION.md`](docs/V10-VEX-SUPPRESSION.md) — VEX and suppression;
- [`docs/V11A-CYCLONEDX-SBOM.md`](docs/V11A-CYCLONEDX-SBOM.md) — SBOM inventory;
- [`docs/V8A-SAFE-UPDATER-STAGING.md`](docs/V8A-SAFE-UPDATER-STAGING.md) through [`docs/V8P-FETCH-RETRY.md`](docs/V8P-FETCH-RETRY.md) — updater, provenance, staging, rollback and fetch boundaries;
- [`integrations/AI_AGENT_HOOKS.md`](integrations/AI_AGENT_HOOKS.md) — hook envelope contract.

## License

The files in this repository are available under the [MIT License](LICENSE). Product names, website content, MCPwatch Scanner, AI Change Firewall and separately distributed commercial materials are not automatically licensed by this repository.
