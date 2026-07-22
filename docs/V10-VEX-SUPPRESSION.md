# V10 — OpenVEX, CycloneDX VEX and suppression annotations

The offline scan accepts local documents:

```bash
python -m src vuln scan \
  --root REPOSITORY \
  --database vulnerability.sqlite \
  --vex openvex.json \
  --suppressions suppressions.json \
  --format json
```

Supported VEX inputs:

- OpenVEX statements with vulnerability, products, status and justification;
- CycloneDX VEX vulnerability analysis states and affected product references.

Suppression input schema:

```json
{
  "schema": "coderisktools.vulnerability.suppressions",
  "version": 1,
  "entries": [{"fingerprint": "sha256:<64 lowercase hex>", "reason": "..."}]
}
```

Annotations are additive. A finding is never removed, redacted, or truncated. Reports retain the original evidence and add `vex_status`, `vex_justification`, `vex_source_format`, `suppressed`, and `suppression_reason`. Invalid documents, duplicate statements, unsupported statuses, missing products, and unjustified `not_affected` claims fail closed.
