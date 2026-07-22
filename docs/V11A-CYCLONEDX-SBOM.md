# V11a — local CycloneDX SBOM inventory

```bash
python -m src vuln inventory --sbom bom.json
```

The importer accepts local CycloneDX JSON documents with spec versions 1.4–1.7 and emits the existing versioned inventory schema.

- components require an exact `name` and `version`;
- PURLs are preserved and mapped to a best-effort ecosystem label;
- duplicate component identities are rejected;
- symlinks, malformed JSON, unsupported formats/spec versions, and oversized documents fail closed;
- component provenance records `source_type=cyclonedx` and the SBOM basename;
- no network, subprocess, package manager, or repository code execution is used;
- the existing `vuln inventory --root DIR` contract is unchanged.
