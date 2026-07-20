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

## Batch 3 contracts

- `CRT-CI-020` `CI_SECRET_INTERPOLATION`: direct `secrets.NAME` interpolation in a workflow `run` command. GitHub warns that secrets printed or passed through command lines can be exposed in logs/process handling; environment passing is the safer boundary. Source: https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/use-secrets
- `CRT-CI-021` `GH_PR_TARGET_HEAD_REPOSITORY`: `pull_request_target` plus checkout of `github.event.pull_request.head.repo.full_name`. Source: https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target
- `CRT-CI-022` `GH_PR_TARGET_HEAD_REF_CHECKOUT`: `pull_request_target` plus checkout of `github.event.pull_request.head.ref`. Source: https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target
- `CRT-CI-023` `GH_WORKFLOW_RUN_ARTIFACT_EXECUTION`: `workflow_run` downloads an artifact and executes a local path or shell script. Source: https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows
- `CRT-CI-024` `GH_PR_WRITE_CONTENTS_PERMISSION`: `pull_request` plus `contents: write`. Source: https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/controlling-permissions-for-github_token

## Batch 4 contracts

- `CRT-CI-025` `CI_SCRIPT_INJECTION_COMMENT_BODY`: direct `github.event.comment.body` interpolation into `run`.
- `CRT-CI-026` `CI_SCRIPT_INJECTION_REVIEW_BODY`: direct `github.event.review.body` interpolation into `run`.
- `CRT-CI-027` `CI_SCRIPT_INJECTION_REVIEW_COMMENT`: direct `github.event.pull_request_review_comment.body` interpolation into `run`.
- `CRT-CI-028` `CI_SCRIPT_INJECTION_DISCUSSION_BODY`: direct `github.event.discussion.body` interpolation into `run`.
- `CRT-CI-029` `CI_SCRIPT_INJECTION_HEAD_LABEL`: direct `github.event.pull_request.head.label` interpolation into `run`.

All five use the GitHub Actions Script injections/Secure use guidance: untrusted event context must be passed through a controlled environment variable rather than interpolated into executable shell text. Sources: https://docs.github.com/en/actions/concepts/security/script-injections and https://docs.github.com/en/actions/reference/security/secure-use

## Batch 5 contracts

- `CRT-CI-030` `CI_SCRIPT_INJECTION_WORKFLOW_HEAD_BRANCH`: direct `github.event.workflow_run.head_branch` interpolation into `run`. Source: https://securitylab.github.com/advisories/GHSL-2024-274-GHSL-2024-275_Cilium/
- `CRT-CI-031` `CI_SCRIPT_INJECTION_WORKFLOW_TITLE`: direct `github.event.workflow_run.display_title` interpolation into `run`.
- `CRT-CI-032` `CI_SCRIPT_INJECTION_WORKFLOW_COMMIT_MESSAGE`: direct `github.event.workflow_run.head_commit.message` interpolation into `run`.
- `CRT-CI-033` `CI_SCRIPT_INJECTION_WORKFLOW_PR_HEAD_REF`: direct `github.event.workflow_run.pull_requests[N].head.ref` interpolation into `run`.
- `CRT-CI-034` `CI_SCRIPT_INJECTION_EVENT_PR_HEAD_REF`: direct `github.event.pull_request.head.ref` interpolation into `run`.

The last four use the GitHub Actions Script injections/Secure use guidance for attacker-controlled event context. Sources: https://docs.github.com/en/actions/concepts/security/script-injections and https://docs.github.com/en/actions/reference/security/secure-use

## Batch 6 contracts

- `CRT-CI-035` `CI_SCRIPT_INJECTION_CLIENT_PAYLOAD`: direct `github.event.client_payload.*` interpolation into `run`, covering caller-supplied `repository_dispatch` payload fields. Source: https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows
- `CRT-CI-036` `CI_SCRIPT_INJECTION_EVENT_INPUT`: direct `github.event.inputs.*` interpolation into `run` for workflow dispatch inputs. Source: https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax
- `CRT-CI-037` `CI_SCRIPT_INJECTION_WORKFLOW_INPUT`: direct `inputs.*` interpolation into `run` for reusable-workflow or dispatch inputs. Source: https://docs.github.com/en/actions/reference/workflows-and-actions/contexts

All three are restricted to workflow YAML and treat caller-controlled values as untrusted shell input.

## Batch 7 contracts

- `CRT-CI-038` `CI_SCRIPT_INJECTION_RELEASE_BODY`: direct `github.event.release.body` interpolation into `run`.
- `CRT-CI-039` `CI_SCRIPT_INJECTION_RELEASE_NAME`: direct `github.event.release.name` interpolation into `run`.
- `CRT-CI-040` `CI_SCRIPT_INJECTION_PAGE_NAME`: direct `github.event.pages[N].page_name` interpolation into `run`.
- `CRT-CI-041` `CI_SCRIPT_INJECTION_DEFAULT_BRANCH`: direct `github.event.repository.default_branch` interpolation into `run`.

These fields are documented by GitHub's Script injections guidance as context values that may be attacker-influenced. Source: https://docs.github.com/en/actions/concepts/security/script-injections

## Batch 8 contracts

- `CRT-CI-042` `CI_SCRIPT_INJECTION_RELEASE_TAG`: direct `github.event.release.tag_name` interpolation into `run`.
- `CRT-CI-043` `CI_SCRIPT_INJECTION_RELEASE_TARGET`: direct `github.event.release.target_commitish` interpolation into `run`.
- `CRT-CI-044` `CI_SCRIPT_INJECTION_WORKFLOW_REPO_BRANCH`: direct `github.event.workflow_run.head_repository.default_branch` interpolation into `run`.

Release and source-workflow context values are treated as untrusted shell input; immutable `head_sha` is intentionally not covered.

## Batch 9 contracts

- `CRT-CI-045` `CI_OIDC_TOKEN_PERMISSION`: `id-token: write`, a medium-severity policy signal requiring reviewed federated deployment trust conditions. Source: https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-google-cloud-platform
- `CRT-CI-046` `CI_DYNAMIC_ENVIRONMENT_INPUT`: deployment `environment` selected directly from `inputs.*`. Source: https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments
- `CRT-CI-047` `CI_DYNAMIC_ENVIRONMENT_REF`: deployment `environment` selected directly from `github.head_ref` or `github.ref`. Source: https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments

The environment rules require an explicit allowlist mapping before deployment; static environment names and `vars.*` are not flagged.

## Batch 10 contracts

- `CRT-CI-048` `CI_GITHUB_TOKEN_IN_RUN`: direct `${{ github.token }}` interpolation in a workflow `run` command. Source: https://docs.github.com/en/actions/concepts/security/github_token

The rule intentionally does not flag `env: GITHUB_TOKEN:`, `with: token:`, or `secrets.GITHUB_TOKEN`; those are separate reviewed handling patterns.

## Batch 11 contracts

- `CRT-CI-049` `CI_DOCKER_ACTION_MUTABLE_TAG`: `uses: docker://...:latest`, a mutable Docker container action reference. Source: https://docs.github.com/en/actions/reference/security/secure-use

Immutable Docker digests and explicit version tags are not flagged; existing `container:`/`image:` policy remains separate.
