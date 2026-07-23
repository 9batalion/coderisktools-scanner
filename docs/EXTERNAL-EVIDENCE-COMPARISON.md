# External evidence comparison

The benchmark comparison fixture is intentionally offline and synthetic. It
compares identifier sets representing an internal result and explicitly
supplied OSV-Scanner, Trivy and Grype evidence. It does not execute any of the
external tools and does not merge their findings into `Finding`, `ScanResult`
or the local vulnerability database.

## Difference meanings

- `aligned`: the identifier is present in both result sets;
- `external_only`: the supplied external evidence contains an identifier not
  present in the internal result;
- `internal_only`: the internal result contains an identifier absent from the
  supplied external evidence.

Differences are not proof that one tool is correct. They can result from
package identity normalization, version/range semantics, advisory database
freshness, severity policy, ignored paths, transitive dependency handling or
source-specific matching rules. Investigations must use the original evidence
and provenance rather than copying an external result.

The fixture is a contract test for comparison/reporting behavior, not an
accuracy ranking of OSV-Scanner, Trivy or Grype.
