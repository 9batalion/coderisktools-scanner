# Stage 6 — Stable Secret Detector Backlog

Source of truth for candidates after merged PR #4. Candidates are classified before implementation. `VERIFIED_READY` means the provider publishes a sufficiently distinctive format or prefix and the candidate still requires the normal RED→GREEN batch checks. `ALREADY_COVERED` means the current registry already covers the documented format. `RESEARCH_REQUIRED` means the provider documents the credential but the exact provider-specific format, length, or collision boundary still needs proof.

| Candidate | Provider | Credential type | Documented prefix | Exact format known | Collision risk | Official source | Status | Reason |
|---|---|---|---|---|---|---|---|---|
| GitHub App installation token | GitHub | installation token | `ghs_` | Partial; format variants are documented | Medium; current GitHub family overlaps | https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github | ALREADY_COVERED | Existing GitHub token family covers `ghs_` forms; do not add a duplicate yet. |
| GitLab personal/project/group access token | GitLab | access token | `glpat-` | Prefix documented; token body/version length varies | Medium; one provider family | https://docs.gitlab.com/api/admin/token/ | ALREADY_COVERED | Existing `GITLAB_TOKEN` covers `glpat-`; separate IDs require stronger type-specific evidence. |
| GitLab runner authentication token | GitLab | runner token | `glrt-` | Prefix and current formats documented | Low/medium | https://docs.gitlab.com/runner/register/ | ALREADY_COVERED | Existing `GITLAB_RUNNER_AUTH_TOKEN` covers current forms. |
| Buildkite user API token | Buildkite | user API token | `bkua_` | Prefix reported in current provider tooling; exact body rules require confirmation | Low/medium | https://buildkite.com/docs/apis/rest-api/api-tokens | RESEARCH_REQUIRED | Confirm current prefix, alphabet, and length from Buildkite-owned documentation before RED. |
| SendGrid API key | Twilio SendGrid | API key | `SG.` | Structured prefix and segmented body documented in provider examples | Low/medium | https://docs.sendgrid.com/ui/account-and-settings/api-keys | VERIFIED_READY | Candidate has a provider-specific marker and bounded segmented structure; needs collision tests against generic JWT-like text. |
| Mailgun private API key | Mailgun | private API key | `key-` | Provider prefix documented; body length/version needs confirmation | Medium/high | https://documentation.mailgun.com/docs/mailgun/api-reference/ | RESEARCH_REQUIRED | `key-` is not sufficiently unique without exact body proof and assignment/context controls. |
| Anthropic API key | Anthropic | API key | `sk-ant-api03-` | Prefix documented; body length/version should be pinned from current docs | Low | https://docs.anthropic.com/en/api/getting-started | ALREADY_COVERED | Existing Anthropic provider rule covers the documented family; verify before considering variants. |
| OpenAI project API key | OpenAI | project API key | `sk-proj-` | Prefix documented; exact current body format varies | Medium | https://platform.openai.com/docs/api-reference/authentication | ALREADY_COVERED | Existing OpenAI family covers current project-key forms. |
| Hugging Face access token | Hugging Face | user/access token | `hf_` | Prefix documented; token classes and lengths vary | Medium | https://huggingface.co/docs/hub/security-tokens | ALREADY_COVERED | Existing Hugging Face family covers the provider prefix. |
| Datadog API key | Datadog | API key | none | Hex-like fixed-length value | High | https://docs.datadoghq.com/account_management/api-app-keys/ | REJECTED_TOO_GENERIC | No unique provider marker; collides with hashes and generic hexadecimal values. |
| Datadog application key | Datadog | application key | none | Hex-like fixed-length value | High | https://docs.datadoghq.com/account_management/api-app-keys/ | REJECTED_TOO_GENERIC | No provider-specific prefix or safe standalone boundary. |
| PagerDuty REST API token | PagerDuty | API token | none | Opaque token format | High | https://developer.pagerduty.com/docs/ZG9jOjM0MDI5NTc-rest-api-authentication | REJECTED_NO_OFFICIAL_FORMAT | Credential exists but official format is not sufficiently distinctive. |
| Linear personal API key | Linear | API key | `lin_api_` | Prefix documented in provider tooling; exact body needs confirmation | Low/medium | https://linear.app/developers/graphql | RESEARCH_REQUIRED | Verify current official token prefix/length and distinguish from public IDs. |
| LaunchDarkly access token | LaunchDarkly | API token | `api-` | Prefix is too broad; token body varies | High | https://launchdarkly.com/docs/api | REJECTED_TOO_GENERIC | `api-` is not a safe provider-specific detector without a stronger structure. |
| Netlify personal access token | Netlify | personal access token | `nfp_` | Prefix documented in CLI/API material; exact body requires confirmation | Low/medium | https://docs.netlify.com/api/get-started/ | RESEARCH_REQUIRED | Candidate is promising but needs current length/alphabet proof and fixture controls. |
| Vercel access token | Vercel | access token | `vercel_` | Prefix documented; body/version should be confirmed | Low/medium | https://vercel.com/docs/rest-api | RESEARCH_REQUIRED | Provider-specific prefix appears suitable; verify exact current format before implementation. |
| Snyk API token | Snyk | API token | `snyk_` | Prefix documented in current integrations; exact body requires confirmation | Low/medium | https://docs.snyk.io/snyk-api/authentication-for-api | RESEARCH_REQUIRED | Confirm token classes and body constraints from Snyk-owned sources. |
| Atlassian API token | Atlassian | API token | none | Opaque account token | High | https://developer.atlassian.com/cloud/confluence/basic-auth-for-rest-apis/ | REJECTED_NO_OFFICIAL_FORMAT | No stable provider-specific standalone format. |
| Azure DevOps PAT | Microsoft Azure DevOps | personal access token | none | Base64-like opaque value | High | https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate | REJECTED_TOO_GENERIC | No safe standalone prefix; would require broad contextual matching. |
| CircleCI personal API token | CircleCI | personal token | `CCIPAT_` | Fixed provider prefix and bounded body | Low | https://circleci.com/docs/managing-api-tokens/ | ALREADY_COVERED | Existing `CIRCLECI_PERSONAL_TOKEN` covers the documented form. |

## First implementation ranking

The first new batch is intentionally limited to candidates with the strongest specificity:

1. SendGrid API key (`SG.`) — `VERIFIED_READY`;
2. Buildkite user API token (`bkua_`) — after official format confirmation;
3. Linear personal API key (`lin_api_`) — after official format confirmation;
4. Netlify personal access token (`nfp_`) — after official format confirmation;
5. Vercel access token (`vercel_`) — after official format confirmation.

No candidate is implemented from this document alone. Each selected candidate must pass inventory check, source research, format proof, focused RED, negative corpus, golden regeneration, full regression, and the batch report protocol.
