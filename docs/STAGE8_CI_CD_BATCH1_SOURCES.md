# Stage 8 CI/CD — Batch 1 source ledger

This bounded batch adds five native CI policy detectors backed by GitHub's first-party security documentation.

## Sources

- Secure use reference: https://docs.github.com/en/actions/reference/security/secure-use
- Script injections: https://docs.github.com/en/actions/concepts/security/script-injections
- Securely using `pull_request_target`: https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target
- Self-hosted runner security: https://docs.github.com/en/actions/concepts/runners/self-hosted-runners
- actions/checkout README (`clean` input): https://github.com/actions/checkout#inputs

## Detector contracts

- `CRT-CI-010` `CI_SCRIPT_INJECTION_PR_TITLE`: direct `github.event.pull_request.title` or `github.event.pull_request.body` interpolation in a workflow `run` line. The source documentation identifies untrusted pull-request fields as script-injection inputs.
- `CRT-CI-011` `CI_SCRIPT_INJECTION_REF`: direct `github.head_ref` or `github.base_ref` interpolation in a workflow `run` line. These values are attacker-influenced branch names and must be passed through an environment variable or otherwise safely handled.
- `CRT-CI-012` `CI_SCRIPT_INJECTION_ISSUE_BODY`: direct `github.event.issue.title` or `github.event.issue.body` interpolation in a workflow `run` line.
- `CRT-CI-013` `CI_CHECKOUT_CLEAN_DISABLED`: `actions/checkout` workflow input `clean: false`. The checkout action documents that `clean` removes untracked files before checkout; disabling it is unsafe for persistent/self-hosted workspaces and requires explicit review.
- `CRT-CI-014` `CI_PR_SELF_HOSTED_RUNNER`: a `pull_request` workflow schedules on `self-hosted`. GitHub documents that self-hosted runners may be persistently compromised by untrusted workflow code; this is a bounded sequence finding, not a claim that every use is exploitable.

All rules are restricted to `.github/workflows/*.yml` and `.github/workflows/*.yaml`, are policy findings, use high confidence, and have negative controls for safe expressions, safe checkout cleanup and non-PR triggers. They do not execute YAML or workflow code.

## Scope boundary

These five rules are a bounded first batch of Stage 8. They do not change existing CI rule IDs, baseline v1, public formatter schemas or exit-code semantics. Further CI/CD batches require separate RED/GREEN evidence and source review.

## Batch 2 contracts

- `CRT-CI-015` `CI_REMOTE_SCRIPT_PIPE`: `curl` or `wget` output is piped directly to `sh`/`bash` in a workflow `run` line. Source: https://docs.github.com/en/actions/reference/security/secure-use
- `CRT-CI-016` `CI_DOCKER_SOCKET_MOUNT`: a workflow mounts `/var/run/docker.sock` to the same path, exposing the host Docker control socket. Source: https://docs.github.com/en/actions/concepts/runners/self-hosted-runners
- `CRT-CI-017` `CI_MUTABLE_CONTAINER_TAG`: a workflow job/container image uses the mutable `latest` tag. Source: https://docs.github.com/en/actions/how-tos/write-workflows/choose-where-workflows-run/run-jobs-in-a-container
- `CRT-CI-018` `GH_WORKFLOW_RUN_UNTRUSTED_CHECKOUT`: a `workflow_run` workflow checks out `github.event.workflow_run.head_sha`, combining a privileged trigger with code from the triggering run. Source: https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows
- `CRT-CI-019` `GH_WORKFLOW_RUN_SELF_HOSTED_RUNNER`: a `workflow_run` workflow runs on a self-hosted runner. GitHub documents that untrusted code/data on this trigger can lead to cache poisoning or unintended write/secrets access. Source: https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows
