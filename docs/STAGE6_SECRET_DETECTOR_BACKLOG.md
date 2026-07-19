# Stage 6 — Stable Secret Detector Backlog

Source of truth for candidates after merged PR #4. Candidates are classified before implementation. `VERIFIED_READY` means the provider publishes a sufficiently distinctive format or prefix and the candidate still requires the normal RED→GREEN batch checks. `ALREADY_COVERED` means the current registry already covers the documented format. `RESEARCH_REQUIRED` means the provider documents the credential but the exact provider-specific format, length, or collision boundary still needs proof.

| Candidate | Provider | Credential type | Documented prefix | Exact format known | Collision risk | Official source | Status | Reason |
|---|---|---|---|---|---|---|---|---|
| GitHub App installation token | GitHub | installation token | `ghs_` | Partial; format variants are documented | Medium; current GitHub family overlaps | https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github | ALREADY_COVERED | Existing GitHub token family covers `ghs_` forms; do not add a duplicate yet. |
| GitLab personal/project/group access token | GitLab | access token | `glpat-` | Prefix documented; token body/version length varies | Medium; one provider family | https://docs.gitlab.com/api/admin/token/ | ALREADY_COVERED | Existing `GITLAB_TOKEN` covers `glpat-`; separate IDs require stronger type-specific evidence. |
| GitLab runner authentication token | GitLab | runner token | `glrt-` | Prefix and current formats documented | Low/medium | https://docs.gitlab.com/runner/register/ | ALREADY_COVERED | Existing `GITLAB_RUNNER_AUTH_TOKEN` covers current forms. |
| Buildkite user API token | Buildkite | user API token | `bkua_` | Official docs confirm prefix but not exact body rules | Low/medium | https://buildkite.com/docs/platform/security/tokens; https://buildkite.com/docs/apis/mcp-server/local/installing | RESEARCH_REQUIRED | The provider says the token usually begins with `bkua_`; exact alphabet/length still needs a provider-owned format proof. |
| SendGrid API key | Twilio SendGrid | API key | `SG.` | Existing rule has bounded segmented format | Low/medium | https://docs.sendgrid.com/ui/account-and-settings/api-keys | ALREADY_COVERED | Existing `CRT-SEC-033 SENDGRID_API_KEY` covers the segmented `SG.` format; do not duplicate it. |
| Mailgun private API key | Mailgun | private API key | `key-` | Provider prefix documented; body length/version needs confirmation | Medium/high | https://documentation.mailgun.com/docs/mailgun/api-reference/ | RESEARCH_REQUIRED | `key-` is not sufficiently unique without exact body proof and assignment/context controls. |
| Anthropic API key | Anthropic | API key | `sk-ant-api03-` | Prefix documented; body length/version should be pinned from current docs | Low | https://docs.anthropic.com/en/api/getting-started | ALREADY_COVERED | Existing Anthropic provider rule covers the documented family; verify before considering variants. |
| OpenAI project API key | OpenAI | project API key | `sk-proj-` | Prefix documented; exact current body format varies | Medium | https://platform.openai.com/docs/api-reference/authentication | ALREADY_COVERED | Existing OpenAI family covers current project-key forms. |
| Hugging Face access token | Hugging Face | user/access token | `hf_` | Prefix documented; token classes and lengths vary | Medium | https://huggingface.co/docs/hub/security-tokens | ALREADY_COVERED | Existing Hugging Face family covers the provider prefix. |
| Datadog API key | Datadog | API key | none | Hex-like fixed-length value | High | https://docs.datadoghq.com/account_management/api-app-keys/ | REJECTED_TOO_GENERIC | No unique provider marker; collides with hashes and generic hexadecimal values. |
| Datadog application key | Datadog | application key | none | Hex-like fixed-length value | High | https://docs.datadoghq.com/account_management/api-app-keys/ | REJECTED_TOO_GENERIC | No provider-specific prefix or safe standalone boundary. |
| PagerDuty REST API token | PagerDuty | API token | none | Opaque token format | High | https://developer.pagerduty.com/docs/ZG9jOjM0MDI5NTc-rest-api-authentication | REJECTED_NO_OFFICIAL_FORMAT | Credential exists but official format is not sufficiently distinctive. |
| Linear personal API key | Linear | API key | `lin_api_` | Existing rule has a bounded 40-character body | Low | https://linear.app/developers/graphql; https://github.com/linear/linear-solutions/blob/main/scripts/migrate-label-based-releases-to-release-pipelines/README.md | ALREADY_COVERED | Existing `CRT-SEC-041 LINEAR_API_KEY` covers the documented prefix and length. |
| LaunchDarkly access token | LaunchDarkly | API token | `api-` | Prefix is too broad; token body varies | High | https://launchdarkly.com/docs/api | REJECTED_TOO_GENERIC | `api-` is not a safe provider-specific detector without a stronger structure. |
| Netlify personal access token | Netlify | personal access token | `nfp_` | Prefix documented in CLI/API material; exact body requires confirmation | Low/medium | https://docs.netlify.com/api/get-started/ | RESEARCH_REQUIRED | Candidate is promising but needs current length/alphabet proof and fixture controls. |
| Vercel access token | Vercel | access token | `vercel_` | Prefix documented; body/version should be confirmed | Low/medium | https://vercel.com/docs/rest-api | RESEARCH_REQUIRED | Provider-specific prefix appears suitable; verify exact current format before implementation. |
| Snyk API token | Snyk | API token | `snyk_` | Prefix documented in current integrations; exact body requires confirmation | Low/medium | https://docs.snyk.io/snyk-api/authentication-for-api | RESEARCH_REQUIRED | Confirm token classes and body constraints from Snyk-owned sources. |
| Atlassian API token | Atlassian | API token | none | Opaque account token | High | https://developer.atlassian.com/cloud/confluence/basic-auth-for-rest-apis/ | REJECTED_NO_OFFICIAL_FORMAT | No stable provider-specific standalone format. |
| Azure DevOps PAT | Microsoft Azure DevOps | personal access token | none | Base64-like opaque value | High | https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate | REJECTED_TOO_GENERIC | No safe standalone prefix; would require broad contextual matching. |
| CircleCI personal API token | CircleCI | personal token | `CCIPAT_` | Fixed provider prefix and bounded body | Low | https://circleci.com/docs/managing-api-tokens/ | ALREADY_COVERED | Existing `CIRCLECI_PERSONAL_TOKEN` covers the documented form. |
| Paddle API key | Paddle | API key | `pdl_live_apikey_`, `pdl_sdbx_apikey_` | Exact provider regex published; 26 + 22 + 3 payload segments | Low | https://developer.paddle.com/api-reference/about/authentication/ | IMPLEMENTED | Implemented as `CRT-SEC-180`; live and sandbox are environment variants of the same credential family. |
| Paddle webhook endpoint secret | Paddle | webhook signing secret | `pdl_ntfset_` | Exact provider regex published; 26 + 32 payload segments | Low | https://developer.paddle.com/api-reference/notification-settings/create-notification-setting/ | IMPLEMENTED | Implemented as `CRT-SEC-181`; notification endpoint secret used for webhook signature verification. |

## First implementation ranking

The initial ranking was revalidated against the live registry. SendGrid is already covered by `CRT-SEC-033`, so it is not a new batch. The remaining candidates are research-gated:

1. Buildkite user API token (`bkua_`) — confirm exact body alphabet and length;
2. Linear personal API key (`lin_api_`) — confirm exact body constraints;
3. Netlify personal access token (`nfp_`) — require official format proof, not repository examples;
4. Vercel access token (`vercel_`) — require official prefix/body proof;
5. Snyk API token (`snyk_`) — require official token-format proof.

No candidate is implemented from this document alone. Each selected candidate must pass inventory check, source research, format proof, focused RED, negative corpus, golden regeneration, full regression, and the batch report protocol.

## Current research decision

The first five ranked candidates were checked against the live registry and current provider documentation. SendGrid and Linear are already covered. Buildkite, Netlify, Vercel and Snyk remain `RESEARCH_REQUIRED`; no new stable detector is justified until their exact provider-owned body constraints are documented.
