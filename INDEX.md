# MCP Security Scanner — Repository Index

Current index for the implemented Sprint 1-8O scope.

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
- Publish safety checks: tag/version guard before publish + post-publish PyPI visibility verification (retry/backoff)

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
  - Optional encrypted persistent OAuth cache via `auth.cache` (`persistent`, `namespace`, `backend`, `aws_secret_id`, `aws_ssm_parameter_name`, `aws_region`, `aws_endpoint_url`, `gcp_secret_name`, `gcp_endpoint_url`, `azure_vault_url`, `azure_secret_name`, `azure_secret_version`, `vault_url`, `vault_secret_path`, `vault_token_env`, `vault_namespace`, `k8s_secret_namespace`, `k8s_secret_name`, `k8s_secret_key`, `oci_secret_ocid`, `oci_region`, `oci_endpoint_url`, `doppler_project`, `doppler_config`, `doppler_secret_name`, `doppler_token_env`, `doppler_api_url`)
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

## Current Deferred Backlog

- additional persistent secret-store providers beyond `local`, `aws_secrets_manager`, `aws_ssm_parameter_store`, `gcp_secret_manager`, `azure_key_vault`, `hashicorp_vault`, `kubernetes_secrets`, `oci_vault`, and `doppler_secrets`
