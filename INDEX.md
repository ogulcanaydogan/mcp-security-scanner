# MCP Security Scanner — Repository Index

Current index for the implemented Sprint 1-9H scope plus `v1.0.8` provider-expansion target.

## Status Snapshot

- Sprint 1: done (`server` MVP, severity ranking fix, stdio connector)
- Sprint 2: done (`config`, `baseline`, `compare`, baseline-v1, mutation compare)
- Sprint 3: done (`sse` transport support + CLI target unification)
- Sprint 4C: done (`streamable-http` transport + URL auto-detect fallback)
- Sprint 5A: done (`EscalationAnalyzer` default-on in scan pipeline)
- Sprint 5B: done (`ToolPoisoningAnalyzer` default-on in scan pipeline)
- Sprint 5C: done (`CrossToolAnalyzer` default-on in scan pipeline)
- Sprint 6A: done (`config` auth/session flow v1 with env-backed auth resolution)
- Sprint 6B: done (`oauth_client_credentials` for config auth with single-run token cache)
- Sprint 6C: done (`oauth_device_code` + refresh-token flow for config auth)
- Sprint 6D: done (`oauth_auth_code_pkce` + local callback + refresh-token reuse)
- Sprint 6E: done (`oauth` provider edge-case hardening, `client_secret_basic`, refresh fallback)
- Sprint 6F: done (optional secure persistent OAuth cache with keyring+encrypted file fallback)
- Sprint 6G: done (persistent cache hardening with strict lock, corrupt recovery, v2 metadata envelope, key rotation command)
- Sprint 6H: done (OAuth hardening+ with multi-key historical decrypt recovery and shared transient retry policy)
- Sprint 7A: done (OAuth provider integrations v1: `private_key_jwt` + token endpoint mTLS for config auth)
- Sprint 7B: done (OAuth provider integrations v2: `private_key_jwt` supports AWS KMS signer source)
- Sprint 7C: done (transport-level mTLS propagation for `sse` and `streamable-http` config entries)
- Sprint 8A: done (Dynamic Analyzer v1 added as opt-in via `--dynamic`)
- Sprint 8B: done (Dynamic analyzer hardening: bounded runtime policy, deterministic outputs, false-positive suppression)
- Sprint 8C: done (URL positional auth/mTLS UX for `server`, `baseline`, `compare`)
- Sprint 8D: done (release stabilization and PyPI package identity conflict fix)
- Sprint 8E: done (dynamic analyzer expansion with semantic probe variants and stronger benign-context suppression)
- Sprint 8F: done (publish unblock follow-up + advanced OAuth cache backend v1 with AWS Secrets Manager)
- Sprint 8G: done (advanced OAuth cache backend v2 with GCP Secret Manager, ADC-first, pre-provisioned secret model)
- Sprint 8H: done (advanced OAuth cache backend v3 with Azure Key Vault, default-credential auth, pre-provisioned secret model)
- Sprint 8I: done (advanced OAuth cache backend v4 with HashiCorp Vault, token-env/default-chain auth, pre-provisioned secret path model)
- Sprint 8J: done (release hardening: idempotent GitHub release creation/upload, publish timeout/concurrency guard, single-owner PyPI operations checklist)
- Sprint 8K: done (advanced OAuth cache backend v5 with AWS SSM Parameter Store, pre-provisioned SecureString parameter model)
- Sprint 8L: done (advanced OAuth cache backend v6 with Kubernetes Secrets, in-cluster auth + kubeconfig fallback, pre-provisioned Secret model)
- Sprint 8M: done (advanced OAuth cache backend v7 with OCI Vault, resource-principal-first auth chain + OCI config fallback, pre-provisioned secret model)
- Sprint 8N: done (release + contract hardening: tag/version guard, post-publish PyPI visibility retry check, shared OAuth cache backend invariants)
- Sprint 8O: done (advanced OAuth cache backend v8 with Doppler Secrets, env-token auth only, pre-provisioned secret model)
- Sprint 8P: done (advanced OAuth cache backend v9 with 1Password Connect, env-token auth only, pre-provisioned item/field model)
- Sprint 8Q: done (advanced OAuth cache backend v10 with Bitwarden Secrets Manager API, env-token auth only, pre-provisioned secret model)
- Sprint 8R: done (advanced OAuth cache backend v11 with Infisical Secrets API, env-token auth only, pre-provisioned secret model)
- Sprint 8S: done (advanced OAuth cache backend v12 with Akeyless Secrets API, env-token auth only, pre-provisioned secret model)
- Sprint 8T: done (advanced OAuth cache backend v13 with GitLab project variables API, env-token auth only, pre-provisioned variable model)
- Sprint 8U: done (advanced OAuth cache backend v14 with GitHub Actions variables API, env-token auth only, pre-provisioned repository variable model)
- Sprint 8V: done (advanced OAuth cache backend v15 with GitHub environment variables API, env-token auth only, pre-provisioned repository environment variable model)
- Sprint 8W: done (advanced OAuth cache backend v16 with GitHub organization variables API, env-token auth only, pre-provisioned organization variable model)
- Sprint 8X: done (stabilization hardening with build-wheel CLI smoke verification, publish-time wheel/tag version guard, and expanded `persistent=false` OAuth cache invariants)
- Sprint 8Y: done (advanced OAuth cache backend v17 with Consul KV API, env-token auth only, pre-provisioned KV key model)
- Sprint 8Z: done (advanced OAuth cache backend v18 with Redis KV, env-password auth only, pre-provisioned key model)
- Sprint 8AA: done (OAuth cache stabilization: centralized backend dispatch contract + publish-time version consistency guard across `pyproject`/`__version__`/wheel/CLI)
- Sprint 8AB: done (advanced OAuth cache backend v19 with Cloudflare KV API, env-token auth only, pre-provisioned KV key model)
- Sprint 8AC: done (advanced OAuth cache backend v20 with GitLab group variables API, env-token auth only, pre-provisioned group variable model)
- Sprint 8AD: done (v1.0 RC stabilization freeze with explicit backend contract lock and release-guard normalization for `v1.0.0-rcN` tags)
- v1.0.0 GA: done (RC2 snapshot promoted to stable with feature freeze preserved and no runtime/CLI/auth/report contract changes)
- Sprint 9A: done (GitLab project/group variable v2 with optional `gitlab_environment_scope`, default `*`)
- Sprint 9B: done (GitHub organization variable v2 with visibility-preserving updates for `all`/`private`/`selected`)
- Sprint 9C: done (post-1.0 stabilization hardening for OAuth cache dispatch fail-closed behavior and deterministic PyPI visibility verification flags)
- Sprint 9D: done (advanced OAuth cache backend v21 with etcd v3 KV JSON API, env-token auth, pre-provisioned key model)
- Sprint 9E: done (post-1.0 stabilization hardening with canonical remote-backend spec-derived dispatch maps and stricter dispatch matrix contract checks)
- Sprint 9F: done (advanced OAuth cache backend v22 with GitLab instance variables API, env-token auth, pre-provisioned instance variable model without environment scope)
- Sprint 9G: done (post-1.0 stabilization hardening with canonical GitLab capability matrix reuse and single-script release version guard reuse across build/publish jobs)
- Sprint 9H: done (advanced OAuth cache backend v23 with Postgres KV using psycopg3, env-DSN auth, fixed-schema pre-provisioned row model)

## Top-Level Docs

- [README.md](README.md): user-facing usage, transports, commands, exit codes
- [ROADMAP.md](ROADMAP.md): broader project direction/backlog
- [CONTRIBUTING.md](CONTRIBUTING.md): development and contribution flow
- [SETUP_COMPLETE.md](SETUP_COMPLETE.md): setup and completion checklist

## Release Notes Snapshot

- PyPI distribution name: `ogulcanaydogan-mcp-security-scanner`
- Python package/module path unchanged: `mcp_security_scanner`
- CLI entrypoint unchanged: `mcp-scan`
- GitHub release publishing path: idempotent `gh release` create/upload in CI publish job
- Publish safety checks: build-wheel CLI smoke check + tag/version guard + publish-time consistency guard (`pyproject`, `__version__`, wheel metadata, CLI) + post-publish PyPI visibility verification (retry/backoff)

## Source Map

### CLI and Core

- `src/mcp_security_scanner/cli.py`
  - Implemented commands: `server`, `config`, `baseline`, `compare`, `cache rotate`
  - Severity filtering, output formatting, exit code contract
  - URL target auto-routing with fallback (`streamable-http` -> `sse`)
  - URL positional auth/mTLS options (`--headers-json`, `--auth-json`, `--mtls-*`) for `server`/`baseline`/`compare`
  - Config auth normalization (`bearer` / `api_key` / `session_cookie` / `oauth_client_credentials` / `oauth_device_code` / `oauth_auth_code_pkce`)
  - Auth finding flow: `auth_config_error` (schema/env) and `auth_token_error` (token endpoint)
  - OAuth client-credentials + device-code + auth-code PKCE/refresh with in-memory cache
  - Optional encrypted persistent OAuth cache via `auth.cache` (`persistent`, `namespace`, `backend`, `aws_secret_id`, `aws_ssm_parameter_name`, `aws_region`, `aws_endpoint_url`, `gcp_secret_name`, `gcp_endpoint_url`, `azure_vault_url`, `azure_secret_name`, `azure_secret_version`, `vault_url`, `vault_secret_path`, `vault_token_env`, `vault_namespace`, `k8s_secret_namespace`, `k8s_secret_name`, `k8s_secret_key`, `oci_secret_ocid`, `oci_region`, `oci_endpoint_url`, `doppler_project`, `doppler_config`, `doppler_secret_name`, `doppler_token_env`, `doppler_api_url`, `op_connect_host`, `op_vault_id`, `op_item_id`, `op_field_label`, `op_connect_token_env`, `bw_secret_id`, `bw_access_token_env`, `bw_api_url`, `infisical_project_id`, `infisical_environment`, `infisical_secret_name`, `infisical_token_env`, `infisical_api_url`, `akeyless_secret_name`, `akeyless_token_env`, `akeyless_api_url`, `gitlab_project_id`, `gitlab_group_id`, `gitlab_variable_key`, `gitlab_environment_scope`, `gitlab_token_env`, `gitlab_api_url`, `github_repository`, `github_organization`, `github_environment_name`, `github_variable_name`, `github_token_env`, `github_api_url`, `consul_key_path`, `consul_token_env`, `consul_api_url`, `redis_key`, `redis_url`, `redis_password_env`, `cf_account_id`, `cf_namespace_id`, `cf_kv_key`, `cf_api_token_env`, `cf_api_url`, `etcd_key`, `etcd_api_url`, `etcd_token_env`, `postgres_cache_key`, `postgres_dsn_env`)
  - Persistent cache hardening:
    - strict lock file with retry/timeout and non-fatal bypass
    - corrupt cache quarantine (`*.corrupt.<timestamp>`)
    - v2 cache envelope (`schema_version`, `key_id`, `updated_at`, `entries`) with v1 backward compatibility
    - key metadata handling (`active` + `historical` key sets with `key_id` + `fernet_key`) and `mcp-scan cache rotate`
    - historical key retention (max 3) and deterministic decrypt recovery (`key_id` match -> active -> historical)
  - Advanced persistent cache backend v1:
    - `backend=local` (existing encrypted file + keyring/fallback key model)
    - `backend=aws_secrets_manager` (single secret JSON envelope for OAuth cache entries)
    - `backend=aws_ssm_parameter_store` (single SecureString parameter JSON envelope for OAuth cache entries)
    - `backend=gcp_secret_manager` (single secret JSON envelope for OAuth cache entries via Secret Manager versions)
    - `backend=azure_key_vault` (single secret JSON envelope for OAuth cache entries via Azure Key Vault secret versions)
    - `backend=hashicorp_vault` (single secret JSON envelope for OAuth cache entries via Vault KV v2 secret path)
    - `backend=kubernetes_secrets` (single secret-data-key JSON envelope for OAuth cache entries via Kubernetes Secrets API)
    - `backend=oci_vault` (single secret bundle JSON envelope for OAuth cache entries via OCI Vault data/management planes)
    - `backend=doppler_secrets` (single secret JSON envelope for OAuth cache entries via Doppler config secret key)
    - `backend=onepassword_connect` (single item-field JSON envelope for OAuth cache entries via 1Password Connect API)
    - `backend=bitwarden_secrets` (single secret-value JSON envelope for OAuth cache entries via Bitwarden Secrets Manager API)
    - `backend=infisical_secrets` (single secret-value JSON envelope for OAuth cache entries via Infisical Secrets API)
    - `backend=akeyless_secrets` (single secret-value JSON envelope for OAuth cache entries via Akeyless API)
    - `backend=gitlab_variables` (single project-variable JSON envelope via GitLab API, v2 supports optional `environment_scope`)
    - `backend=gitlab_group_variables` (single group-variable JSON envelope via GitLab API, v2 supports optional `environment_scope`)
    - `backend=gitlab_instance_variables` (single instance-variable JSON envelope via GitLab admin API, v1 has no `environment_scope`)
    - `backend=github_actions_variables` (single repository-variable JSON envelope for OAuth cache entries via GitHub Actions Variables API)
    - `backend=github_environment_variables` (single repository-environment-variable JSON envelope for OAuth cache entries via GitHub Environments Variables API)
    - `backend=github_organization_variables` (single organization-variable JSON envelope via GitHub Organization Variables API, v2 preserves existing `visibility`)
    - `backend=consul_kv` (single KV-value JSON envelope for OAuth cache entries via Consul KV API)
    - `backend=redis_kv` (single key-value JSON envelope for OAuth cache entries via Redis KV)
    - `backend=cloudflare_kv` (single KV-value JSON envelope for OAuth cache entries via Cloudflare KV API)
    - `backend=etcd_kv` (single KV-value JSON envelope for OAuth cache entries via etcd v3 JSON API)
    - `backend=postgres_kv` (single fixed-schema row JSON envelope for OAuth cache entries via psycopg3)
    - backend read/write failures are non-fatal and fall back to live token flow
  - `token_endpoint_auth_method` support (`client_secret_post` / `client_secret_basic` / `private_key_jwt`) for config OAuth entries
  - `private_key_jwt` signer inputs with exclusivity (`client_assertion_key_env` or `client_assertion_key_file` or `client_assertion_kms_key_id`), optional `client_assertion_kid`
  - optional AWS KMS signer tuning (`client_assertion_kms_region`, `client_assertion_kms_endpoint_url`)
  - OAuth token endpoint mTLS inputs (`mtls_cert_file`, `mtls_key_file`, optional `mtls_ca_bundle_file`)
  - transport-level mTLS normalization for config network entries (`mtls_cert_file`, `mtls_key_file`, `mtls_ca_bundle_file`)
  - OAuth Authorization header precedence (`auth.scheme` > `token_type` > `Bearer`)
  - Shared transient retry policy for OAuth token/device/refresh/auth-code endpoint calls (`429/5xx` + timeout/connection errors)
  - Refresh fallback on `invalid_grant`/`invalid_token` with headless-safe behavior
  - dynamic scan path enabled by `--dynamic` for `server`/`config` with connector-backed tool probes
  - dynamic hardening policy for bounded probes (tool/payload limits + per-probe timeout) and deterministic finding ordering

- `src/mcp_security_scanner/discovery.py`
  - `MCPServerConnector` with `stdio`, `sse`, and `streamable-http` transports
  - Capability enumeration (`tools`, `resources`, `prompts`)
  - Resource read, tool call, and transport-specific cleanup

- `src/mcp_security_scanner/mutation.py`
  - Canonical JSON + deterministic hashing
  - Baseline-v1 generation and validation
  - Mutation diff engine (`added`, `removed`, `changed`)

- `src/mcp_security_scanner/reporter.py`
  - JSON / HTML / SARIF report generation

### Analyzers

- `src/mcp_security_scanner/analyzers/base.py`
  - `Finding`, `Severity` ordering/comparison, `BaseAnalyzer`
- `src/mcp_security_scanner/analyzers/static.py`
  - metadata pattern checks (code exec, shell, fs, network, secrets, SQL)
- `src/mcp_security_scanner/analyzers/injection.py`
  - prompt injection/jailbreak pattern checks on tool/resource metadata
- `src/mcp_security_scanner/analyzers/escalation.py`
  - capability risk profiling (`admin`/`privileged`/`sensitive`) with conservative severity mapping
- `src/mcp_security_scanner/analyzers/poisoning.py`
  - tool metadata poisoning checks (`instruction`, `schema_payload`, `behavior_drift`)
- `src/mcp_security_scanner/analyzers/cross_tool.py`
  - cross-tool attack-chain checks (`secret_exfiltration`, `file_to_exec`, `sql_to_write`, `prompt_to_exec`)
- `src/mcp_security_scanner/analyzers/dynamic.py`
  - opt-in runtime probe checks (`dynamic_tool_execution_error`, `dynamic_sensitive_output`, `dynamic_command_execution_signal`)
  - hardened signal filtering to suppress benign placeholder/blocked-execution contexts

## Tests

- `tests/test_cli.py`: command flows, output/exit codes, baseline/compare, URL fallback routing
- `tests/test_discovery.py`: stdio + SSE + streamable-http connector behavior, validation, disconnect paths
- `tests/test_mutation.py`: baseline-v1, deterministic hash, mutation diff logic
- `tests/test_reporter.py`: JSON/HTML/SARIF formatting
- `tests/analyzers/`: analyzer unit tests
- `tests/analyzers/test_dynamic.py`: dynamic analyzer bounded-policy, noise-suppression, timeout, and determinism behavior

## Quality Commands

```bash
pytest -q
mypy src
```

Coverage threshold is enforced at `>=80%`.

## Current Deferred Backlog (Post-1.0)

- additional persistent secret-store providers beyond `local`, `aws_secrets_manager`, `aws_ssm_parameter_store`, `gcp_secret_manager`, `azure_key_vault`, `hashicorp_vault`, `kubernetes_secrets`, `oci_vault`, `doppler_secrets`, `onepassword_connect`, `bitwarden_secrets`, `infisical_secrets`, `akeyless_secrets`, `gitlab_variables`, `gitlab_group_variables`, `gitlab_instance_variables`, `github_actions_variables`, `github_environment_variables`, `github_organization_variables`, `consul_kv`, `redis_kv`, `cloudflare_kv`, `etcd_kv`, and `postgres_kv`; Sprint 8AA established the shared backend dispatch/contract baseline used for post-1.0 provider onboarding
