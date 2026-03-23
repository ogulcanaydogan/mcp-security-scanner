# ROADMAP — mcp-security-scanner (Post Sprint 8AD)

## Current State

- Release line is stable through `v0.1.25`.
- Sprint `8A..8AC` scope is complete.
- Sprint `8AD` is a v1.0 release-candidate stabilization freeze:
  - no new runtime/provider features
  - OAuth cache backend contract is locked during RC
  - release guards support prerelease tag normalization (`vX.Y.Z-rcN` -> `X.Y.ZrcN`)

## Current Target

- Publish `v1.0.0-rc1` / package version `1.0.0rc1`.
- Validate RC quality gate and release flow end to end:
  - local lint/type/test/coverage gates
  - CI tag guard + OIDC publish + Sigstore + GitHub release
  - PyPI visibility check with retry/backoff

## v1.0 GA Criteria

- RC release is green and reproducible.
- No contract regressions in:
  - compare findings (`tool_added` / `tool_removed` / `tool_changed`, `LLM05`)
  - OAuth cache invariants (`persistent=false` bypass, non-fatal provider bypass, local-only `cache rotate`)
- No blocking regressions in CLI/runtime behavior.

## Post-1.0 Backlog

- Additional persistent secret-store providers beyond:
  - `local`, `aws_secrets_manager`, `aws_ssm_parameter_store`, `gcp_secret_manager`, `azure_key_vault`, `hashicorp_vault`, `kubernetes_secrets`, `oci_vault`, `doppler_secrets`, `onepassword_connect`, `bitwarden_secrets`, `infisical_secrets`, `akeyless_secrets`, `gitlab_variables`, `gitlab_group_variables`, `github_actions_variables`, `github_environment_variables`, `github_organization_variables`, `consul_kv`, `redis_kv`, `cloudflare_kv`
- Optional report/visual schema improvements that do not break contracts.
