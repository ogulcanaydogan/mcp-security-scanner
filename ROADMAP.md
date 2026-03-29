# ROADMAP — mcp-security-scanner (Post v1.0.0 GA)

## Current State

- Release line is stable at `v1.0.19` and advancing under stabilization-first post-1.0 policy.
- Sprint `8A..8AC` scope is complete and GA promoted from the `1.0.0rc2` snapshot.
- Sprint `8AD` feature freeze and contract lock remain the baseline for post-1.0 work.

## Current Target

- `v1.0.20` stabilization hardening (no new backend) while keeping GA contracts stable:
  - no breaking changes to CLI/exit-code/report/auth-cache contracts
  - keep OAuth cache lookup order and non-fatal bypass behavior unchanged
  - keep GitLab v2 scope contract lock unchanged (project/group only, instance forbidden)
  - normalize volatile retry diagnostics in release-visibility checks for deterministic logs
  - preserve deterministic backend-contract drift checks and release visibility verification

## v1.0 GA Status

- `v1.0.0` GA published successfully.
- Contract invariants preserved:
  - compare findings (`tool_added` / `tool_removed` / `tool_changed`, `LLM05`)
  - OAuth cache invariants (`persistent=false` bypass, non-fatal provider bypass, local-only `cache rotate`)

## Post-1.0 Backlog

- Additional persistent secret-store providers beyond:
  - `local`, `aws_secrets_manager`, `aws_ssm_parameter_store`, `gcp_secret_manager`, `azure_key_vault`, `hashicorp_vault`, `kubernetes_secrets`, `oci_vault`, `doppler_secrets`, `onepassword_connect`, `bitwarden_secrets`, `infisical_secrets`, `akeyless_secrets`, `gitlab_variables`, `gitlab_group_variables`, `gitlab_instance_variables`, `github_actions_variables`, `github_environment_variables`, `github_organization_variables`, `consul_kv`, `redis_kv`, `cloudflare_kv`, `etcd_kv`, `postgres_kv`, `mysql_kv`, `mongo_kv`, `dynamodb_kv`, `s3_object_kv`
- Optional report/visual schema improvements that do not break contracts.
