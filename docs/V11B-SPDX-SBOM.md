# V11b — local SPDX SBOM inventory

```bash
python -m src vuln inventory --sbom bom.spdx.json
```

The importer accepts SPDX JSON `SPDX-2.2` and `SPDX-2.3` documents and emits the existing versioned inventory schema.

- packages require asserted `name` and `versionInfo`;
- PURLs are read from `externalRefs` with `referenceCategory=PACKAGE-MANAGER` and `referenceType=purl`;
- package identity and provenance are deterministic;
- duplicate identities, duplicate PURL references, `NOASSERTION` versions, malformed documents, symlinks and oversized files fail closed;
- the importer is local-only and does not call Syft, OSV-Scanner, Trivy, package managers or repository code;
- CycloneDX autodetection through the same `--sbom` option remains supported.
