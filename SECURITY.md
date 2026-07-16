# Security policy

## Supported versions

Until the first stable release, only the latest tagged `3.x` release is supported.

## Reporting a vulnerability

Please do not open a public issue for a vulnerability that would expose a live credential, bypass detail, exploitable payload or private customer data.

Until GitHub Private Vulnerability Reporting is visibly enabled for this repository, report privately to `support@coderisktools.store` with subject `SECURITY: CodeRiskTools`. After that feature is enabled, the repository Security tab becomes the preferred channel.

Do not send live credentials. Use synthetic values and redact paths or customer identifiers.

## Response target

The public project will publish a real support address and response-time commitment before the first tagged release. Until then, no response SLA is claimed.

## Scope

Security reports may cover:

- unsafe path handling or symlink traversal;
- unbounded input or denial-of-service behavior;
- report redaction failures;
- command or environment injection;
- unexpected network access;
- incorrect fail-open behavior;
- release or GitHub Action supply-chain issues.

A scanner false negative or false positive can also be reported, but is not automatically a software vulnerability.
