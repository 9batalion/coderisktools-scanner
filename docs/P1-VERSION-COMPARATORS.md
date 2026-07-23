# P1 Version Comparator Contract

The vulnerability matcher now imports its current bounded version semantics from:

```text
src/vulnerability/versions/generic.py
```

Public functions:

- `compare_bounded_version(left, right)`;
- `osv_events_match(version, events)`.

The implementation preserves the existing matcher behavior:

- strips a leading `v`;
- compares dot- and hyphen-separated numeric tokens numerically;
- compares non-numeric tokens case-insensitively;
- evaluates the bounded OSV `introduced`, `fixed` and `last_affected` event subset.

This is an explicit boundary, not a claim of complete ecosystem version support. It is not yet a standards-complete implementation of:

- SemVer prerelease/build precedence;
- PEP 440;
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
