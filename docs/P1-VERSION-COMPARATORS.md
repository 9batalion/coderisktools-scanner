# P1 Version Comparator Contract

The vulnerability matcher now imports its current bounded version semantics from:

```text
src/vulnerability/versions/generic.py
src/vulnerability/versions/pep440.py
src/vulnerability/versions/semver.py
src/vulnerability/versions/npm_ranges.py
src/vulnerability/versions/maven.py
```

Public functions:

- `compare_bounded_version(left, right)`;
- `compare_pep440_version(left, right)`;
- `compare_semver_version(left, right)`;
- `matches_npm_range(version, expression)`;
- `compare_maven_version(left, right)`;
- `osv_events_match(version, events)`.

PyPI (`pypi`) range matching now uses the stdlib-only bounded PEP 440 implementation. npm (`npm`) version precedence uses SemVer 2.0, and `matches_npm_range` supports the bounded range subset: exact/partial/wildcard versions, `> >= < <=`, `~`, `^`, whitespace AND and `||` OR. Maven (`maven`) range matching uses the bounded ComparableVersion-style qualifier ordering for common alpha/beta/milestone/rc/snapshot/release/sp forms. Other ecosystems continue to use the bounded fallback until their own comparator batch is completed.

The implementation preserves the existing matcher behavior:

- strips a leading `v`;
- compares dot- and hyphen-separated numeric tokens numerically;
- compares non-numeric tokens case-insensitively;
- evaluates the bounded OSV `introduced`, `fixed` and `last_affected` event subset.

This is an explicit boundary, not a claim of complete ecosystem version support. The PEP 440 and bounded npm implementations cover the tested forms above, but they remain independently tested code rather than external standards libraries. They are not complete implementations of:

- full npm range grammar and npm-specific edge cases;
- full Maven ComparableVersion edge cases;
- NuGet comparison;
- RubyGems comparison;
- Composer comparison;
- Go module versions;
- Debian epochs/revisions;
- RPM EVR;
- Alpine package revisions.

Each ecosystem comparator must be added as a separate bounded RED/GREEN batch with fixtures, differential checks where an authoritative local implementation is available, and no silent fallback from a known ecosystem to incompatible semantics.
