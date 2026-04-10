# ROADMAP — mcp-security-scanner (Post v1.0.0 GA)

## Current State

- Release line is stable at `v1.0.26` after Sprint 10B stabilization hardening.
- Sprint `8A..8AC` scope is complete and GA promoted from the `1.0.0rc2` snapshot.
- Sprint `8AD` feature freeze and contract lock remain the baseline for post-1.0 work.
- Sprint `9Z` discovery gate completed and Sprint `10A` target is implemented.
- Sprint `10B` stabilization-only hardening is implemented with full release closure.

## Current Target

Sprint 10C Planning Target (post-10B, decision gate):
  - lock next sprint direction (provider onboarding vs stabilization) with decision-complete scope
  - keep runtime contracts unchanged (`in-memory -> persistent -> refresh -> primary`, non-fatal bypass, local-only `cache rotate`)
  - keep release model patch-only and OIDC publish-safe

### Sprint 9Z Discovery Matrix (Decision Gate)

| Candidate | Auth Model | Pre-Provisioned-Only Fit | Contract Risk | Dependency Impact | Test/CI Cost | Release Risk | Decision |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `openbao_kv` | env token (`VAULT_TOKEN`-style) + optional namespace | Strong | Low | None | Low | Low | **Winner** |
| `gitea_actions_variables` | env PAT token | Medium | Medium | None | Medium | Medium | Shortlist |
| `nats_kv` | creds/token chain | Weak (v1 constraints) | High | New SDK + async surface | High | High | Deferred |

### Sprint 10A Completed Scope (`openbao_kv`)

- Config/API shape:
  - `auth.cache.backend += openbao_kv`
  - reuse existing vault cache fields (`vault_url`, `vault_secret_path`, `vault_token_env?`, `vault_namespace?`)
  - no new CLI flag/command
- Validation:
  - `vault_url` + `vault_secret_path` required for `openbao_kv`
  - `vault_*` fields accepted for `hashicorp_vault` and `openbao_kv`; invalid on unrelated backends
- Provider behavior:
  - pre-provisioned-only KV v2 read/update; no secret create path
  - read/write/provider/auth/parse/network errors remain non-fatal (persistent skip, scan continues)
  - secret/token plaintext never written to findings/logs
- Acceptance (completed):
  - dispatch completeness includes `openbao_kv`
  - `persistent=false` remote bypass preserved
  - `compare` contract unchanged (`tool_added/tool_removed/tool_changed`, `LLM05`)
  - released as `v1.0.25` with existing deterministic release-consistency guards

### Sprint 10B Completed Scope (Stabilization-Only)

- Runtime behavior unchanged:
  - lookup order and persistent-cache contracts preserved
  - pre-provisioned-only write model preserved
  - provider failure paths remain non-fatal bypass
  - `cache rotate` remains local-only
- OAuth cache contract hardening:
  - remote dispatch resolver now fails closed when backend contract drift is detected
  - deterministic backend-contract drift diagnostics retained (`set/source/callable` deltas)
- Release-consistency hardening:
  - deterministic retry-wait visibility diagnostics now include `next_attempt`
  - terminal visibility failure diagnostics include deterministic `last_status` + `last_output`
  - official-index + no-cache visibility semantics unchanged
- Acceptance (completed):
  - released as `v1.0.26` with full CI/tag publish closure

## v1.0 GA Status

- `v1.0.0` GA published successfully.
- Contract invariants preserved:
  - compare findings (`tool_added` / `tool_removed` / `tool_changed`, `LLM05`)
  - OAuth cache invariants (`persistent=false` bypass, non-fatal provider bypass, local-only `cache rotate`)

## Post-1.0 Backlog

- Sprint 10A onboarding is complete (`openbao_kv`); non-selected candidates remain deferred.
- Additional persistent secret-store providers beyond:
  - `local`, `aws_secrets_manager`, `aws_ssm_parameter_store`, `gcp_secret_manager`, `azure_key_vault`, `hashicorp_vault`, `openbao_kv`, `kubernetes_secrets`, `oci_vault`, `doppler_secrets`, `onepassword_connect`, `bitwarden_secrets`, `infisical_secrets`, `akeyless_secrets`, `gitlab_variables`, `gitlab_group_variables`, `gitlab_instance_variables`, `github_actions_variables`, `github_environment_variables`, `github_organization_variables`, `consul_kv`, `redis_kv`, `cloudflare_kv`, `etcd_kv`, `postgres_kv`, `mysql_kv`, `mongo_kv`, `dynamodb_kv`, `s3_object_kv`, `sqlite_kv`
- Optional report/visual schema improvements that do not break contracts.
