# P1 Version Comparator Contract

The vulnerability matcher now imports its current bounded version semantics from:

```text
src/vulnerability/versions/generic.py
src/vulnerability/versions/pep440.py
src/vulnerability/versions/semver.py
```

Public functions:

- `compare_bounded_version(left, right)`;
- `compare_pep440_version(left, right)`;
- `compare_semver_version(left, right)`;
- `osv_events_match(version, events)`.

PyPI (`pypi`) range matching now uses the stdlib-only bounded PEP 440 implementation. npm (`npm`) range matching now uses the stdlib-only SemVer 2.0 precedence implementation. Other ecosystems continue to use the bounded fallback until their own comparator batch is completed.

The implementation preserves the existing matcher behavior:

- strips a leading `v`;
- compares dot- and hyphen-separated numeric tokens numerically;
- compares non-numeric tokens case-insensitively;
- evaluates the bounded OSV `introduced`, `fixed` and `last_affected` event subset.

This is an explicit boundary, not a claim of complete ecosystem version support. The PEP 440 implementation covers the supported public/pre/post/dev/epoch/local forms needed by the current PyPI matcher, but it remains independently tested bounded code rather than an external standards library. It is not an implementation of:

- SemVer prerelease/build precedence;
- npm ranges;
- Maven comparison;
- NuGet comparison;
- RubyGems comparison;
- Composer comparison;
- Go module versions;
- Debian epochs/revisions;
- RPM EVR;
- Alpine package revisions.

Each ecosystem comparator must be added as a separate bounded RED/GREEN batch with fixtures, differential checks where an authoritative local implementation is available, and no silent fallback from a known ecosystem to incompatible semantics.
