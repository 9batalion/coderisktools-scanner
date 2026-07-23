# Controlled vulnerability database update pipeline

The vulnerability scanner does not download advisory data. Scanning is read-only
against an already active local snapshot:

```text
python -m src vuln scan --root ./repo --database DATA/snapshots/.../snapshot.sqlite3
```

A database update is a separate operation:

```text
python -m src vuln-db update --full
```

At the start of this update operation the updater loads its source configuration
and fetches the declared feeds. The scanner itself never performs this startup
fetch. To create the starter configuration explicitly:

```text
python -m src vuln-db init-config
```

The default configuration path is:

```text
~/.config/coderisktools/vuln-db.json
```

The built-in starter configuration contains bounded entries for NVD, CISA KEV,
EPSS and GitHub Advisory. It also lists OSV, CVE v5, Debian, Ubuntu and RustSec
as `enabled: false` until their dedicated format/archive/pagination adapters are
connected to the multi-source importer. It is not a claim of complete global
coverage.

The default data root is:

```text
~/.local/share/coderisktools/vuln-db/
  staging/
  snapshots/
  active
```

## Configuration

The bounded full-update configuration declares one adapter-shaped source per
entry:

```json
{
  "sources": [
    {
      "source_id": "osv",
      "format": "osv",
      "url": "https://example.invalid/osv.json",
      "allowed_hosts": ["example.invalid"]
    }
  ]
}
```

Supported importer formats currently include `osv`, `nvd`, `cve-v5`, `kev`,
`epss`, and `github-advisories`. Each source is fetched with HTTPS, host
allowlisting, timeout and a byte limit. Its bytes are retained in the staging
run, hashed, parsed, and imported through the existing database importer.

## Activation boundary

Without `--apply`, the command only builds and verifies a staged snapshot:

```text
python -m src vuln-db update --full \
  --config ./vuln-db.json \
  --root ./coderisktools-data
```

Activation is explicit:

```text
python -m src vuln-db update --full \
  --config ./vuln-db.json \
  --root ./coderisktools-data \
  --active ./coderisktools-data/active \
  --apply
```

The database is built under a temporary staging directory, integrity-checked,
manifested, moved into `snapshots/<snapshot-id>`, verified again, and only then
can the active pointer be atomically replaced. A failed import preserves a
small `update-error.json` diagnostic in staging and cannot replace the active
snapshot.

This implementation is deliberately conservative: a source is not considered
full-coverage `ready` merely because its adapter can fetch and import a file.
Live acceptance, terms/license evidence, quality metrics, reproducibility and
rollback evidence remain separate gates.
