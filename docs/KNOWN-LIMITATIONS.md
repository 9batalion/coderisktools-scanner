# Known limitations

This document is part of the production snapshot boundary. It intentionally
lists limitations instead of implying complete vulnerability coverage.

## Vulnerability data

- Feed adapters are bounded contracts, not a claim of complete live-feed
  ingestion or complete historical coverage.
- OSV-shaped records are supported locally; source-specific fields outside the
  bounded adapter contract may be preserved only as metadata or omitted.
- Matching can be `indeterminate` when a package, version, range or ecosystem
  cannot be compared safely.
- Enrichment and correlation evidence is additive and provenance-aware; it is
  not a replacement for vendor advisory review.

## Ecosystem coverage

- Python, npm, Cargo/ crates.io and Go have the strongest local inventory path.
- Linux distribution, Maven, NuGet, RubyGems, Swift, Dart, Elixir, Haskell,
  R, Conan and vcpkg adapters are bounded and fixture-driven.
- CSAF support is bounded to the documented product/PURL, advisory, provider,
  remediation, vendor-status and quality-gate contract.
- The project must not be described as providing full support for all package
  managers, distributions, feeds or CSAF provider extensions.

## Benchmarking

- Public fixtures are deterministic but intentionally small; they are not a
  statistically complete vulnerability corpus.
- Precision/recall results are fixture results, not a security certification.
- Latency depends on hardware, Python version and database state. Absolute
  cross-platform baselines require separate measurement.
- Comparisons with OSV-Scanner, Trivy and Grype are external-evidence work and
  must not be represented as copied or authoritative results.

## Production and recovery

- Manifest signing verifies supplied keys and bytes; key custody and rotation
  remain deployment responsibilities.
- Air-gap import restores a verified database but does not activate it.
- Rollback planning is non-destructive until an explicit apply operation.
- Release readiness reports validate supplied metadata; they cannot prove the
  integrity of an upstream build system or hosting provider.

## Scanner boundary

- A clean result is not proof that code is secure.
- False positives and false negatives remain possible.
- The scanner is not a security audit, certification, legal opinion or
  compliance guarantee.
- The scanner does not execute target-project code and ordinary scans do not
  require network access.
