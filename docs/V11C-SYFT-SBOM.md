# V11c — local native Syft JSON inventory

```bash
python -m src vuln inventory --sbom syft.json
```

The importer accepts native Syft JSON documents identified by `descriptor.name=syft` and reads bounded `artifacts` entries.

- artifacts require asserted `name`, `version`, and `type`;
- PURLs are preserved when present;
- common Syft types map to ecosystems including PyPI, npm, Go, crates.io, Maven, Debian, RPM and Alpine;
- provenance records `source_type=syft`, descriptor version and the SBOM basename;
- duplicate identities, unknown versions, malformed documents, missing descriptor metadata, symlinks and oversized files fail closed;
- `--sbom` autodetects CycloneDX, SPDX and native Syft JSON;
- no Syft binary, network, package manager, subprocess, or repository code is executed.
