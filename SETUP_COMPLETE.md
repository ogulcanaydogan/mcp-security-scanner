# Setup Complete — Sprint 1-8AA Implementation State

This file records the actual implementation status after Sprint 8AA.

## Completed Work

### Sprint 1 (MVP `server`, stdio)

- `pyproject.toml` cleanup/fix completed for editable install and `src` package discovery
- severity ordering/comparisons fixed in `analyzers/base.py`
- `MCPServerConnector` stdio flow implemented:
  - connect/initialize
  - enumerate tools/resources/prompts
  - resource read + tool call
  - disconnect/cleanup
- `mcp-scan server` implemented end-to-end:
  - capability collection
  - MVP analyzers
  - severity filter
  - JSON/HTML/SARIF output
  - exit code contract

### Sprint 2 (CLI completion)

- `mcp-scan config` implemented:
  - parses Claude `mcpServers`
  - scans entries sequentially
  - continues on per-server failures
  - emits findings for invalid/unsupported/failed entries
  - `--timeout` supported
- `mcp-scan baseline` implemented with official `baseline-v1` JSON
- `mcp-scan compare` implemented with mutation findings:
  - `added` => medium
  - `removed` / `changed` => high
  - OWASP mapping => `LLM05`
- deterministic canonical hashing centralized in `mutation.py`
- connector config extended with stdio `env`

### Sprint 3 (`sse` transport)

- discovery connector now supports `stdio` + `sse`
- SSE connect path implemented using MCP client session
- transport validation rules added for `sse` (`url`, optional `headers`)
- CLI target unification implemented:
  - positional target in `server`/`baseline`/`compare`
  - URL target (`http/https`) auto-routes to `sse`
  - non-URL target routes to `stdio` command
- `config` command supports `transport: "sse"`
- `scan_failure` findings include transport context (`stdio`/`sse`)

### Sprint 4C (`streamable-http` + URL auto-detect)

- discovery connector now supports `stdio` + `sse` + `streamable-http`
- `streamable_http` alias is accepted and normalized to `streamable-http`
- URL targets in `server`/`baseline`/`compare` now auto-try:
  - `streamable-http` first
  - `sse` fallback if first attempt fails
- `config` command supports `transport: "streamable-http"` and alias
- `scan_failure` findings include transport context (`stdio`/`sse`/`streamable-http`)

### Sprint 5A (Capability Escalation Analyzer)

- new `EscalationAnalyzer` added and wired as default-on in scan pipeline
- capability profiles implemented:
  - `ADMIN` => `high` (`LLM08`)
  - `PRIVILEGED` => `medium` (`LLM06`)
  - `SENSITIVE` => `low` (`LLM06`)
  - `STANDARD` / `BENIGN` => no finding
- one highest-risk finding emitted per tool to reduce noise
- finding metadata includes `risk_profile`, `risk_score`, `matched_signals`

### Sprint 5B (Tool Poisoning Analyzer)

- new `ToolPoisoningAnalyzer` added and wired as default-on in scan pipeline
- deterministic poisoning signal checks implemented for:
  - instruction overrides in tool metadata (`tool_poisoning_instruction`, `high`, `LLM03`)
  - schema payload poisoning in `default/example/enum/description` (`tool_poisoning_schema_payload`, `high`, `LLM03`)
  - benign framing + risky behavior drift (`tool_poisoning_behavior_drift`, `medium`, `LLM05`)
- poisoning finding metadata includes `matched_signals`, `matched_locations`, `risk_score`
- `server` and `config` outputs now include poisoning findings by default
- `compare` mutation contract remains unchanged (`tool_added`/`tool_removed`/`tool_changed`, `LLM05`)

### Sprint 5C (Cross-Tool Attack Analyzer)

- new `CrossToolAnalyzer` added and wired as default-on in scan pipeline
- deterministic capability extraction added for:
  - `file_read`, `env_read`, `credential_read`, `prompt_injection_like`
  - `network_egress`, `command_exec`, `file_write`, `sql_mutation`
- cross-tool chain rules implemented:
  - `cross_tool_secret_exfiltration` (`high`, `LLM07`)
  - `cross_tool_file_to_exec` (`medium`, `LLM07`)
  - `cross_tool_sql_to_write` (`medium`, `LLM07`)
  - `cross_tool_prompt_to_exec` (`medium`, `LLM07`)
- chain finding metadata includes `source_tool`, `sink_tool`, `source_capabilities`, `sink_capabilities`, `chain_id`, `risk_score`
- duplicate/symmetric chain suppression and deterministic ordering are enforced
- `server` and `config` outputs now include cross-tool findings by default
- `compare` mutation contract remains unchanged (`tool_added`/`tool_removed`/`tool_changed`, `LLM05`)

### Sprint 6A (Auth/Session Flow v1, Config-Only)

- `config` entry schema now supports optional `auth` for network transports:
  - `bearer` (`token_env`, optional `header`, optional `scheme`)
  - `api_key` (`key_env`, optional `header`)
  - `session_cookie` (`cookie_env`, optional `cookie_name`)
- auth resolution is env-backed and merged deterministically with explicit `headers`:
  - explicit `headers` applied first
  - auth-derived headers applied second (auth overrides on collisions)
  - session cookies merge into `Cookie` as `existing; name=value`
- auth validation/resolution failures return `auth_config_error` finding (`high`, `LLM10`)
- `auth_config_error` metadata includes `server_name`, `transport`, `auth_type`, `env_var`
- token/cookie secret values are not written to findings evidence
- `config` continues scanning other servers when auth resolution fails
- URL positional commands (`server`/`baseline`/`compare`) remain unchanged and do not add auth flags

### Sprint 6B (OAuth Client Credentials, Config-Only)

- `config` auth schema now also supports:
  - `oauth_client_credentials` (`token_url`, `client_id_env`, `client_secret_env`, optional `scope`, optional `audience`, optional `header`, optional `scheme`)
- OAuth token acquisition flow implemented with `application/x-www-form-urlencoded` POST:
  - `grant_type=client_credentials`
  - `client_id` + `client_secret`
  - optional `scope` and `audience`
  - timeout uses existing `--timeout` value
- in-memory OAuth token cache implemented for single `config` command lifetime:
  - cache key: `token_url + client_id + scope + audience`
  - `expires_in` aware TTL with safety skew
- token endpoint/network/response failures now emit `auth_token_error` finding (`high`, `LLM10`)
- `auth_token_error` metadata includes `server_name`, `transport`, `auth_type`, `env_var`, `token_url`, `http_status` (if available)
- auth errors remain non-fatal per server: scan continues with remaining entries
- discovery connector behavior is unchanged; only resolved headers are passed downstream

### Sprint 6C (OAuth Device Code + Refresh, Config-Only)

- `config` auth schema now also supports:
  - `oauth_device_code` (`device_authorization_url`, `token_url`, `client_id_env`, optional `client_secret_env`, optional `scope`, optional `audience`, optional `header`, optional `scheme`)
- device authorization flow implemented with copy/paste UX:
  - prints `verification_uri` / `verification_uri_complete` and `user_code`
  - token polling handles `authorization_pending`, `slow_down`, `access_denied`, `expired_token`
- refresh-token flow added:
  - when cached access token expires and refresh token exists, `refresh_token` grant is attempted first
  - refresh failure emits `auth_token_error` and server entry is skipped
- headless/CI behavior:
  - non-interactive TTY environments do not start device flow
- `auth_token_error` is emitted and scanning continues with other servers
- in-memory OAuth cache now stores `access_token`, `expires_at`, optional `refresh_token` for one command run

### Sprint 6D (OAuth Auth Code PKCE + Local Callback, Config-Only)

- `config` auth schema now also supports:
  - `oauth_auth_code_pkce` (`authorization_url`, `token_url`, `client_id_env`, optional `scope`, optional `audience`, optional `header`, optional `scheme`, optional `redirect_host`, optional `redirect_port`, optional `callback_path`)
- auth-code flow implemented with PKCE (`S256`):
  - `code_verifier`, `code_challenge`, `state` generated per run
  - local callback listener receives `code` + `state` and enforces state validation
- local callback behavior:
  - tries configured/default callback port first
  - falls back to random local port when preferred port bind fails
  - prints authorization URL for copy/paste flow (no auto browser open)
- refresh-token behavior aligned with other OAuth flows:
  - when cached access token is expired and refresh token exists, `refresh_token` grant is attempted first
  - refresh failure emits `auth_token_error` and skips that server entry
- headless/CI behavior:
  - non-interactive TTY environments do not start auth-code flow
  - `auth_token_error` is emitted and scanning continues

### Sprint 6E (OAuth Provider Edge-Case Hardening, Config-Only)

- `config` OAuth auth schema hardening:
  - `oauth_client_credentials` and `oauth_device_code` now support optional `token_endpoint_auth_method`
  - supported values: `client_secret_post` (default), `client_secret_basic`
  - `oauth_device_code` requires `client_secret_env` when `client_secret_basic` is selected
- OAuth token endpoint request flow unified:
  - common form POST helper handles both auth methods
  - `client_secret_basic` sends `Authorization: Basic ...` and omits `client_secret` from body
  - OAuth error parsing now handles both JSON and form-encoded payloads
- Authorization scheme precedence enforced for OAuth headers:
  - `auth.scheme` (if provided)
  - token response `token_type` (if present)
  - fallback `Bearer`
- refresh fallback behavior improved:
  - if refresh fails with `invalid_grant` or `invalid_token`, cached refresh token is dropped
  - scanner retries primary grant once
  - in headless mode, when fallback requires interaction, `auth_token_error` is emitted and scanning continues

### Sprint 6F (Secure Persistent OAuth Cache v1, Config-Only)

- OAuth auth types now support optional `auth.cache`:
  - `persistent` (bool, default `false`)
  - `namespace` (string, default `"default"`)
  - `backend` (string, default `"local"`)
  - for AWS backend: `aws_secret_id` (required), optional `aws_region`, `aws_endpoint_url`
- `auth.cache` is OAuth-only (`oauth_client_credentials`, `oauth_device_code`, `oauth_auth_code_pkce`)
  - invalid shape/field usage returns `auth_config_error`
- optional persistent cache implementation (`backend=local`):
  - encrypted cache file: `~/.cache/mcp-security-scanner/oauth-cache-v1.json.enc`
  - key resolution order:
    - keyring (`service="mcp-security-scanner"`, `username="oauth-cache-key-v1"`)
    - fallback key file: `~/.config/mcp-security-scanner/cache.key` (created with `0600`)
  - cache writes use temp file + atomic replace (`os.replace`)
- OAuth lookup order with cache enabled:
  - in-memory cache
  - persistent cache
  - refresh grant
  - primary grant
- refresh fallback behavior is preserved:
  - `invalid_grant` / `invalid_token` drops cached refresh token and retries primary once
- cache read/write/decrypt failures are non-fatal:
  - scanner bypasses persistent cache and continues live token flow

### Sprint 6G (Persistent OAuth Cache Hardening + Key Rotation, Config-Only)

- persistent cache I/O now uses strict lock discipline:
  - lock file: `oauth-cache-v1.lock`
  - exclusive lock with retry (`50ms`) and timeout (`2s`)
  - lock failures are non-fatal; scanner bypasses persistent layer and continues
- cache corruption recovery hardened:
  - corrupt/undecryptable payloads are quarantined as `oauth-cache-v1.json.enc.corrupt.<timestamp>`
  - scan continues with persistent bypass or live token flow
- cache/key file permission hardening added (best-effort `0600`)
- cache payload schema upgraded to metadata envelope v2:
  - `schema_version`, `key_id`, `updated_at`, `entries`
  - v1 payload read compatibility preserved
- key storage metadata upgraded:
  - keyring/fallback key file use `key_id` + `fernet_key`
  - legacy raw-key format remains readable
- new CLI command implemented:
  - `mcp-scan cache rotate`
  - rotates active key and re-encrypts cache entries
  - exit `0` on success, exit `2` on operational failure

### Sprint 6H (OAuth Hardening+, Config-Only)

- persistent cache key management extended to active + historical key-set model:
  - encrypt path always uses active key
  - decrypt recovery supports deterministic key fallback across active/historical keys
  - historical key retention is bounded (`max 3`, oldest pruned)
- `cache rotate` behavior extended:
  - generates new active key
  - previous active key is retained in historical set (bounded/pruned)
  - cache payload schema remains `v2`
- OAuth provider compatibility hardened:
  - token parse normalization improved for heterogeneous providers (JSON + form-encoded variants)
  - token scheme resolution remains deterministic: `auth.scheme` > normalized `token_type` > `Bearer`
  - shared transient retry policy added for OAuth endpoint requests:
    - retryable HTTP statuses: `429`, `500`, `502`, `503`, `504`
    - retryable transport errors: timeout/connection/network errors
    - max `2` retries (total `3` attempts) with short bounded backoff
- error contract is unchanged:
  - `auth_config_error` for config/env/schema issues
  - `auth_token_error` for token/device/refresh/auth-code endpoint failures
  - per-server failures remain non-fatal in `config` scans

### Sprint 7A (OAuth Provider Integrations v1, Config-Only)

- OAuth token endpoint auth method support expanded:
  - `client_secret_post` (existing default)
  - `client_secret_basic` (existing)
  - `private_key_jwt` (new)
- `private_key_jwt` is supported for:
  - `oauth_client_credentials`
  - `oauth_device_code`
- `private_key_jwt` config fields implemented:
  - `client_assertion_key_env` (optional)
  - `client_assertion_key_file` (optional)
  - exactly one of the two is required when method is `private_key_jwt`
  - optional `client_assertion_kid`
  - signing algorithm: `RS256` (v1 scope)
- OAuth token endpoint mTLS fields implemented for OAuth auth types:
  - `mtls_cert_file` (optional)
  - `mtls_key_file` (optional)
  - `mtls_ca_bundle_file` (optional)
  - validation rule: `mtls_cert_file` + `mtls_key_file` must be provided together
- token request semantics:
  - `private_key_jwt` adds `client_assertion_type` + `client_assertion`
  - `client_secret` is omitted when `private_key_jwt` is used
  - mTLS settings are applied only to OAuth token endpoint HTTP calls
- contracts preserved:
  - no new CLI flags/commands
  - finding categories unchanged (`auth_config_error`, `auth_token_error`)
  - `config` continues scanning after per-server auth failures

### Sprint 7B (OAuth Provider Integrations v2, AWS KMS First)

- `private_key_jwt` signer source support expanded with AWS KMS:
  - `client_assertion_kms_key_id` (new signer source)
  - optional `client_assertion_kms_region`
  - optional `client_assertion_kms_endpoint_url`
- signer source exclusivity hardened for `private_key_jwt`:
  - exactly one source is required: `client_assertion_key_env` or `client_assertion_key_file` or `client_assertion_kms_key_id`
- JWT assertion signing supports:
  - PEM key signing (existing)
  - AWS KMS `Sign` API (`RSASSA_PKCS1_V1_5_SHA_256`) when KMS source is selected
- token request semantics are unchanged:
  - `client_assertion_type` + `client_assertion` sent
  - `client_secret` omitted for `private_key_jwt`

### Sprint 7C (Transport-Level mTLS Propagation, Config-Only)

- network transport entries now support top-level mTLS fields:
  - `mtls_cert_file` (optional)
  - `mtls_key_file` (optional)
  - `mtls_ca_bundle_file` (optional)
- validation rules implemented for top-level transport mTLS:
  - `mtls_cert_file` + `mtls_key_file` must be provided together
  - configured file paths must exist
  - invalid config produces finding and `config` scan continues
- discovery connector now applies top-level mTLS to transport HTTP clients:
  - `sse`: via custom `httpx_client_factory`
  - `streamable-http`: via configured `httpx.AsyncClient`
- OAuth token-endpoint mTLS under `auth.mtls_*` is preserved and independent from transport-level mTLS

### Sprint 8A (Dynamic Analyzer v1, Opt-In)

- new `DynamicAnalyzer` added to analyzer package
- rollout model:
  - opt-in flag `--dynamic` added to `server` and `config`
  - default analyzer pipeline is unchanged when flag is not provided
- dynamic path behavior:
  - keeps connector session open during analysis
  - executes bounded safe probes against tool call surfaces
  - emits dynamic findings through the existing finding/report model
- dynamic finding categories:
  - `dynamic_tool_execution_error` (`medium`, `LLM07`)
  - `dynamic_sensitive_output` (`high`, `LLM06`)
  - `dynamic_command_execution_signal` (`high`, `LLM07`)
- report formats and exit-code contract are unchanged

### Sprint 8B (Dynamic Analyzer Hardening, Opt-In)

- dynamic runtime probing policy centralized in a single control point:
  - max tools per scan
  - max payload fields per probe
  - max probe payloads per tool
  - per-probe timeout budget
  - evidence trim length
- probe payload generation hardened:
  - deterministic key ordering with required-field prioritization
  - bounded field count
  - conservative low-risk defaults for schema types
- signal quality hardening:
  - sensitive output detection tuned toward high-confidence credential signals
  - command-execution detection tuned with benign blocked/simulated context suppression
  - placeholder credential outputs are suppressed to reduce false positives
- runtime safety and resilience:
  - per-probe timeout is non-fatal and emits `dynamic_tool_execution_error`
  - scan continues to next tools after timeout/exception paths
- determinism improvements:
  - tools are probed in deterministic order
  - dynamic findings are returned in stable sorted order with deterministic metadata keys

### Sprint 8C (URL Positional Auth/mTLS UX)

- URL positional commands now support auth/mTLS options:
  - `server`, `baseline`, `compare` accept `--headers-json`, `--auth-json`, `--mtls-cert-file`, `--mtls-key-file`, `--mtls-ca-bundle-file`
- URL target connector generation now reuses existing config normalization/validation pipeline:
  - auth resolution, OAuth flows, and mTLS validation semantics remain consistent with `config` command behavior
  - URL auto-detect order is preserved (`streamable-http` -> `sse`)
- validation/error behavior for URL positional options:
  - malformed `headers-json` / `auth-json` values return command-level operational error (`exit 2`)
  - stdio targets with URL-only auth/mTLS flags return command-level operational error (`exit 2`)
  - transport mTLS pair/path validation and auth env/shape failures return command-level operational error (`exit 2`)
- existing contracts are preserved:
  - `config` command flow unchanged
  - `compare` mutation categories/OWASP mapping unchanged (`tool_added`/`tool_removed`/`tool_changed`, `LLM05`)

### Sprint 8D (Release Stabilization + PyPI Package Identity Fix)

- release/package identity conflict resolved:
  - `project.name` switched from `mcp-security-scanner` to `ogulcanaydogan-mcp-security-scanner`
  - Python module path remains `mcp_security_scanner`
  - CLI executable remains `mcp-scan`
- CI publish workflow made package-name-agnostic for Sigstore signing input:
  - `./dist/*.tar.gz`
- docs synchronized for installation/release messaging:
  - README install guidance now includes `pip install ogulcanaydogan-mcp-security-scanner`

### Sprint 8E (Dynamic Analyzer Expansion, Opt-In)

- dynamic probe generation extended with semantic field-name variants while preserving bounded policy limits:
  - URL/endpoint-like fields -> deterministic safe URL probe
  - path/file-like fields -> deterministic safe file/path probe
  - query/message-like fields -> deterministic safe text probe
  - command/shell and SQL-like fields -> deterministic low-risk command/query probes
- dynamic findings contract preserved (no new categories):
  - `dynamic_tool_execution_error`
  - `dynamic_sensitive_output`
  - `dynamic_command_execution_signal`
- benign-context suppression expanded to reduce false positives in runtime outputs:
  - placeholder/example/mock/redacted sensitive text contexts
  - documentation/sample/dry-run/blocked command-output contexts
- dynamic rollout unchanged:
  - analyzer remains opt-in through `--dynamic`
  - default scan behavior unchanged when `--dynamic` is not provided

### Sprint 8F (Publish Unblock Follow-up + Advanced Secret-Store Backend v1)

- publish unblock follow-up executed from repository side:
  - tag publish workflow rerun attempted and validated against current workflow claims
  - remaining Trusted Publisher mismatch is external (PyPI project-side mapping) and requires owner-side update
- OAuth persistent cache backend abstraction expanded:
  - `auth.cache.backend` supports:
    - `local` (existing encrypted file + keyring/fallback key flow)
    - `aws_secrets_manager` (new v1 backend)
  - AWS backend reads/writes cache envelope as a single secret document (`schema_version`, `updated_at`, `entries`)
  - `aws_secret_id` is required when backend is AWS; optional `aws_region` and `aws_endpoint_url` are supported
  - non-fatal provider behavior preserved: AWS read/write/parse failures bypass persistent layer and continue live token flow
- lookup/write order preserved for OAuth cache-enabled flows:
  - in-memory -> persistent backend -> refresh grant -> primary grant
- `cache rotate` behavior remains local-backend scoped and unchanged

### Sprint 8G (Advanced Secret-Store Backend v2: GCP Secret Manager)

- OAuth persistent cache backend abstraction expanded again:
  - `auth.cache.backend` now supports:
    - `local`
    - `aws_secrets_manager`
    - `gcp_secret_manager`
- GCP backend contract:
  - required: `gcp_secret_name` (`projects/<project>/secrets/<secret>`)
  - optional: `gcp_endpoint_url` (http/https)
  - ADC-first auth model (no new CLI credential flags)
  - pre-provisioned secret model (no auto-create flow in scanner)
- GCP backend behavior:
  - read from `projects/.../secrets/.../versions/latest`
  - persist via `add_secret_version` with JSON cache envelope payload (`schema_version`, `updated_at`, `entries`)
  - provider/read/write/parse errors are non-fatal and bypass persistent layer
- lookup/write order remains unchanged:
  - in-memory -> persistent backend -> refresh grant -> primary grant
- `cache rotate` remains local-backend only

### Sprint 8H (Advanced Secret-Store Backend v3: Azure Key Vault)

- OAuth persistent cache backend abstraction expanded again:
  - `auth.cache.backend` now supports:
    - `local`
    - `aws_secrets_manager`
    - `gcp_secret_manager`
    - `azure_key_vault`
- Azure backend contract:
  - required: `azure_vault_url` (`https://<name>.vault.azure.net`)
  - required: `azure_secret_name`
  - optional: `azure_secret_version` (default `latest`)
  - auth model: Azure SDK default credential chain (`DefaultAzureCredential`)
  - pre-provisioned secret model (scanner does not create missing secret names)
- Azure backend behavior:
  - read from configured secret name/version via Key Vault `get_secret`
  - persist via `set_secret` as JSON cache envelope payload (`schema_version`, `updated_at`, `entries`)
  - provider/read/write/parse errors are non-fatal and bypass persistent layer
- lookup/write order remains unchanged:
  - in-memory -> persistent backend -> refresh grant -> primary grant
- `cache rotate` remains local-backend only

### Sprint 8I (Advanced Secret-Store Backend v4: HashiCorp Vault)

- OAuth persistent cache backend abstraction expanded again:
  - `auth.cache.backend` now supports:
    - `local`
    - `aws_secrets_manager`
    - `gcp_secret_manager`
    - `azure_key_vault`
    - `hashicorp_vault`
- HashiCorp Vault backend contract:
  - required: `vault_url` (`http://` or `https://`)
  - required: `vault_secret_path` (KV path)
  - optional: `vault_token_env` (uses env var name for Vault token; defaults to `VAULT_TOKEN`)
  - optional: `vault_namespace`
  - pre-provisioned secret path model (scanner does not create missing paths)
- HashiCorp Vault backend behavior:
  - read from configured KV v2 path (`read_secret_version`)
  - persist via `create_or_update_secret` with single JSON envelope payload (`schema_version`, `updated_at`, `entries`)
  - provider/read/write/parse errors are non-fatal and bypass persistent layer
- lookup/write order remains unchanged:
  - in-memory -> persistent backend -> refresh grant -> primary grant
- `cache rotate` remains local-backend only

### Sprint 8J (Release Hardening + v0.1.5)

- CI publish workflow hardened:
  - replaced `softprops/action-gh-release@v2` with idempotent `gh release` create/upload flow
  - added `publish` job timeout guard (`timeout-minutes`)
  - added tag-scoped publish concurrency guard (`cancel-in-progress: false`)
- OIDC publish and Sigstore signing flow are preserved.
- release/docs hardening:
  - single-owner PyPI operations checklist documented (2FA/recovery/publisher hygiene)
  - release scope expanded from Sprint 1-8I to Sprint 1-8J state tracking
- scanner runtime and CLI behavior are unchanged.

### Sprint 8K (Advanced Secret-Store Backend v5: AWS SSM Parameter Store)

- OAuth persistent cache backend abstraction expanded again:
  - `auth.cache.backend` now supports:
    - `local`
    - `aws_secrets_manager`
    - `aws_ssm_parameter_store`
    - `gcp_secret_manager`
    - `azure_key_vault`
    - `hashicorp_vault`
- AWS SSM backend contract:
  - required: `aws_ssm_parameter_name` (SSM parameter path/name)
  - optional: `aws_region`, `aws_endpoint_url`
  - pre-provisioned SecureString model (scanner does not create missing parameters)
- AWS SSM backend behavior:
  - read from configured SSM parameter (`get_parameter`, decrypt enabled)
  - persist via `put_parameter` with single JSON envelope payload (`schema_version`, `updated_at`, `entries`)
  - provider/read/write/parse errors are non-fatal and bypass persistent layer
- lookup/write order remains unchanged:
  - in-memory -> persistent backend -> refresh grant -> primary grant
- `cache rotate` remains local-backend only

### Sprint 8L (Advanced Secret-Store Backend v6: Kubernetes Secrets)

- OAuth persistent cache backend abstraction expanded again:
  - `auth.cache.backend` now supports:
    - `local`
    - `aws_secrets_manager`
    - `aws_ssm_parameter_store`
    - `gcp_secret_manager`
    - `azure_key_vault`
    - `hashicorp_vault`
    - `kubernetes_secrets`
- Kubernetes backend contract:
  - required: `k8s_secret_namespace`, `k8s_secret_name`
  - optional: `k8s_secret_key` (default `oauth_cache`)
  - pre-provisioned Secret model (scanner does not auto-create missing Secrets)
- Kubernetes backend behavior:
  - auth chain: `load_incluster_config()` first, then `load_kube_config()` fallback
  - reads/writes JSON envelope in Secret data key (`schema_version`, `updated_at`, `entries`)
  - writes patch existing Secret data key; missing/provider/read/write/parse errors are non-fatal
- lookup/write order remains unchanged:
  - in-memory -> persistent backend -> refresh grant -> primary grant
- `cache rotate` remains local-backend only

### Sprint 8M (Advanced Secret-Store Backend v7: OCI Vault)

- OAuth persistent cache backend abstraction expanded again:
  - `auth.cache.backend` now supports:
    - `local`
    - `aws_secrets_manager`
    - `aws_ssm_parameter_store`
    - `gcp_secret_manager`
    - `azure_key_vault`
    - `hashicorp_vault`
    - `kubernetes_secrets`
    - `oci_vault`
- OCI backend contract:
  - required: `oci_secret_ocid`
  - optional: `oci_region`, `oci_endpoint_url`
  - pre-provisioned secret model (scanner does not auto-create missing secrets)
- OCI backend behavior:
  - auth chain: Resource Principal signer first; config/profile fallback via OCI config file
  - reads secret bundle content via OCI data-plane and parses JSON envelope payload
  - writes new secret content version via OCI management-plane
  - provider/read/write/parse/auth errors are non-fatal and bypass persistent layer
- lookup/write order remains unchanged:
  - in-memory -> persistent backend -> refresh grant -> primary grant
- `cache rotate` remains local-backend only

### Sprint 8N (Release + Contract Hardening)

- Release pipeline hardening:
  - pre-publish version guard validates `refs/tags/vX.Y.Z` against `pyproject` package version
  - publish job now verifies PyPI index visibility for just-published version with retry/backoff
  - existing OIDC publish + Sigstore + idempotent GitHub release flow remains intact
- OAuth cache contract hardening:
  - shared backend dispatch contract tests for load/persist paths across all supported backends
  - invariant test for `persistent=false` path confirms persistent layer is bypassed
  - remote backend read/write helpers validated for fail-closed behavior when client builders are unavailable
  - explicit regression coverage for `cache rotate` local-only behavior
- no runtime/CLI contract changes:
  - no new commands/flags
  - no report schema or exit-code contract changes

### Sprint 8O (Advanced Secret-Store Backend v8: Doppler Secrets)

- OAuth persistent cache backend abstraction expanded again:
  - `auth.cache.backend` now supports:
    - `local`
    - `aws_secrets_manager`
    - `aws_ssm_parameter_store`
    - `gcp_secret_manager`
    - `azure_key_vault`
    - `hashicorp_vault`
    - `kubernetes_secrets`
    - `oci_vault`
    - `doppler_secrets`
- Doppler backend contract:
  - required: `doppler_project`, `doppler_config`, `doppler_secret_name`
  - optional: `doppler_token_env` (default `DOPPLER_TOKEN`), `doppler_api_url` (`https`)
  - pre-provisioned secret model (scanner does not auto-create missing secret keys)
- Doppler backend behavior:
  - auth uses env token only (`doppler_token_env` / `DOPPLER_TOKEN`)
  - reads/writes JSON envelope in configured Doppler config secret key
  - provider/read/write/parse errors are non-fatal and bypass persistent layer
- lookup/write order remains unchanged:
  - in-memory -> persistent backend -> refresh grant -> primary grant
- `cache rotate` remains local-backend only

### Sprint 8P (Advanced Secret-Store Backend v9: 1Password Connect)

- OAuth persistent cache backend abstraction expanded again:
  - `auth.cache.backend` now supports:
    - `local`
    - `aws_secrets_manager`
    - `aws_ssm_parameter_store`
    - `gcp_secret_manager`
    - `azure_key_vault`
    - `hashicorp_vault`
    - `kubernetes_secrets`
    - `oci_vault`
    - `doppler_secrets`
    - `onepassword_connect`
- 1Password Connect backend contract:
  - required: `op_connect_host` (`https`), `op_vault_id`, `op_item_id`
  - optional: `op_field_label` (default `oauth_cache`), `op_connect_token_env` (default `OP_CONNECT_TOKEN`)
  - pre-provisioned item/field model (scanner does not auto-create missing item/field)
- 1Password Connect backend behavior:
  - auth uses env token only (`op_connect_token_env` / `OP_CONNECT_TOKEN`)
  - reads/writes JSON envelope in configured Connect item field
  - provider/read/write/parse/auth errors are non-fatal and bypass persistent layer
- lookup/write order remains unchanged:
  - in-memory -> persistent backend -> refresh grant -> primary grant
- `cache rotate` remains local-backend only

### Sprint 8Q (Advanced Secret-Store Backend v10: Bitwarden Secrets Manager API)

- OAuth persistent cache backend abstraction expanded again:
  - `auth.cache.backend` now supports:
    - `local`
    - `aws_secrets_manager`
    - `aws_ssm_parameter_store`
    - `gcp_secret_manager`
    - `azure_key_vault`
    - `hashicorp_vault`
    - `kubernetes_secrets`
    - `oci_vault`
    - `doppler_secrets`
    - `onepassword_connect`
    - `bitwarden_secrets`
- Bitwarden backend contract:
  - required: `bw_secret_id`
  - optional: `bw_access_token_env` (default `BWS_ACCESS_TOKEN`), `bw_api_url` (`https`)
  - pre-provisioned secret model (scanner does not auto-create missing secrets)
- Bitwarden backend behavior:
  - auth uses env token only (`bw_access_token_env` / `BWS_ACCESS_TOKEN`)
  - reads/writes JSON envelope in configured Bitwarden secret value
  - provider/read/write/parse/auth errors are non-fatal and bypass persistent layer
- lookup/write order remains unchanged:
  - in-memory -> persistent backend -> refresh grant -> primary grant
- `cache rotate` remains local-backend only

### Sprint 8R (Advanced Secret-Store Backend v11: Infisical Secrets API)

- OAuth persistent cache backend abstraction expanded again:
  - `auth.cache.backend` now supports:
    - `local`
    - `aws_secrets_manager`
    - `aws_ssm_parameter_store`
    - `gcp_secret_manager`
    - `azure_key_vault`
    - `hashicorp_vault`
    - `kubernetes_secrets`
    - `oci_vault`
    - `doppler_secrets`
    - `onepassword_connect`
    - `bitwarden_secrets`
    - `infisical_secrets`
- Infisical backend contract:
  - required: `infisical_project_id`, `infisical_environment`, `infisical_secret_name`
  - optional: `infisical_token_env` (default `INFISICAL_TOKEN`), `infisical_api_url` (`https`)
  - pre-provisioned secret model (scanner does not auto-create missing secrets)
- Infisical backend behavior:
  - auth uses env token only (`infisical_token_env` / `INFISICAL_TOKEN`)
  - reads/writes JSON envelope in configured Infisical secret value
  - provider/read/write/parse/auth errors are non-fatal and bypass persistent layer
- lookup/write order remains unchanged:
  - in-memory -> persistent backend -> refresh grant -> primary grant
- `cache rotate` remains local-backend only

### Sprint 8S (Advanced Secret-Store Backend v12: Akeyless Secrets API)

- OAuth persistent cache backend abstraction expanded again:
  - `auth.cache.backend` now supports:
    - `local`
    - `aws_secrets_manager`
    - `aws_ssm_parameter_store`
    - `gcp_secret_manager`
    - `azure_key_vault`
    - `hashicorp_vault`
    - `kubernetes_secrets`
    - `oci_vault`
    - `doppler_secrets`
    - `onepassword_connect`
    - `bitwarden_secrets`
    - `infisical_secrets`
    - `akeyless_secrets`
- Akeyless backend contract:
  - required: `akeyless_secret_name`
  - optional: `akeyless_token_env` (default `AKEYLESS_TOKEN`), `akeyless_api_url` (`https`)
  - pre-provisioned secret model (scanner does not auto-create missing secrets)
- Akeyless backend behavior:
  - auth uses env token only (`akeyless_token_env` / `AKEYLESS_TOKEN`)
  - reads/writes JSON envelope in configured Akeyless secret value
  - provider/read/write/parse/auth errors are non-fatal and bypass persistent layer
- lookup/write order remains unchanged:
  - in-memory -> persistent backend -> refresh grant -> primary grant
- `cache rotate` remains local-backend only

### Sprint 8T (Advanced Secret-Store Backend v13: GitLab Project Variables API)

- OAuth persistent cache backend abstraction expanded again:
  - `auth.cache.backend` now supports:
    - `local`
    - `aws_secrets_manager`
    - `aws_ssm_parameter_store`
    - `gcp_secret_manager`
    - `azure_key_vault`
    - `hashicorp_vault`
    - `kubernetes_secrets`
    - `oci_vault`
    - `doppler_secrets`
    - `onepassword_connect`
    - `bitwarden_secrets`
    - `infisical_secrets`
    - `akeyless_secrets`
    - `gitlab_variables`
- GitLab backend contract:
  - required: `gitlab_project_id`, `gitlab_variable_key`
  - optional: `gitlab_token_env` (default `GITLAB_TOKEN`), `gitlab_api_url` (`https`)
  - pre-provisioned variable model (scanner does not auto-create missing variables)
- GitLab backend behavior:
  - auth uses env token only (`gitlab_token_env` / `GITLAB_TOKEN`)
  - reads/writes JSON envelope in configured GitLab project variable value
  - provider/read/write/parse/auth errors are non-fatal and bypass persistent layer
- lookup/write order remains unchanged:
  - in-memory -> persistent backend -> refresh grant -> primary grant
- `cache rotate` remains local-backend only

### Sprint 8U (Advanced Secret-Store Backend v14: GitHub Actions Variables API)

- OAuth persistent cache backend abstraction expanded again:
  - `auth.cache.backend` now supports:
    - `local`
    - `aws_secrets_manager`
    - `aws_ssm_parameter_store`
    - `gcp_secret_manager`
    - `azure_key_vault`
    - `hashicorp_vault`
    - `kubernetes_secrets`
    - `oci_vault`
    - `doppler_secrets`
    - `onepassword_connect`
    - `bitwarden_secrets`
    - `infisical_secrets`
    - `akeyless_secrets`
    - `gitlab_variables`
    - `github_actions_variables`
- GitHub backend contract:
  - required: `github_repository`, `github_variable_name`
  - optional: `github_token_env` (default `GITHUB_TOKEN`), `github_api_url` (`https`)
  - pre-provisioned variable model (scanner does not auto-create missing variables)
- GitHub backend behavior:
  - auth uses env token only (`github_token_env` / `GITHUB_TOKEN`)
  - reads/writes JSON envelope in configured GitHub Actions repository variable value
  - provider/read/write/parse/auth errors are non-fatal and bypass persistent layer
- lookup/write order remains unchanged:
  - in-memory -> persistent backend -> refresh grant -> primary grant
- `cache rotate` remains local-backend only

### Sprint 8V (Advanced Secret-Store Backend v15: GitHub Environment Variables API)

- OAuth persistent cache backend abstraction expanded again:
  - `auth.cache.backend` now supports:
    - `local`
    - `aws_secrets_manager`
    - `aws_ssm_parameter_store`
    - `gcp_secret_manager`
    - `azure_key_vault`
    - `hashicorp_vault`
    - `kubernetes_secrets`
    - `oci_vault`
    - `doppler_secrets`
    - `onepassword_connect`
    - `bitwarden_secrets`
    - `infisical_secrets`
    - `akeyless_secrets`
    - `gitlab_variables`
    - `github_actions_variables`
    - `github_environment_variables`
- GitHub environment backend contract:
  - required: `github_repository`, `github_environment_name`, `github_variable_name`
  - optional: `github_token_env` (default `GITHUB_TOKEN`), `github_api_url` (`https`)
  - pre-provisioned model (scanner does not auto-create missing environments/variables)
- GitHub environment backend behavior:
  - auth uses env token only (`github_token_env` / `GITHUB_TOKEN`)
  - reads/writes JSON envelope in configured GitHub repository environment variable value
  - environment/variable path segments are URL-encoded in API calls
  - provider/read/write/parse/auth errors are non-fatal and bypass persistent layer
- lookup/write order remains unchanged:
  - in-memory -> persistent backend -> refresh grant -> primary grant
- `cache rotate` remains local-backend only

### Sprint 8W (Advanced Secret-Store Backend v16: GitHub Organization Variables API)

- OAuth persistent cache backend abstraction expanded again:
  - `auth.cache.backend` now supports:
    - `local`
    - `aws_secrets_manager`
    - `aws_ssm_parameter_store`
    - `gcp_secret_manager`
    - `azure_key_vault`
    - `hashicorp_vault`
    - `kubernetes_secrets`
    - `oci_vault`
    - `doppler_secrets`
    - `onepassword_connect`
    - `bitwarden_secrets`
    - `infisical_secrets`
    - `akeyless_secrets`
    - `gitlab_variables`
    - `github_actions_variables`
    - `github_environment_variables`
    - `github_organization_variables`
- GitHub organization backend contract:
  - required: `github_organization`, `github_variable_name`
  - optional: `github_token_env` (default `GITHUB_TOKEN`), `github_api_url` (`https`)
  - pre-provisioned model (scanner does not auto-create missing organization variables)
- GitHub organization backend behavior:
  - auth uses env token only (`github_token_env` / `GITHUB_TOKEN`)
  - reads/writes JSON envelope in configured GitHub organization variable value
  - organization/variable path segments are URL-encoded in API calls
  - provider/read/write/parse/auth errors are non-fatal and bypass persistent layer
- lookup/write order remains unchanged:
  - in-memory -> persistent backend -> refresh grant -> primary grant
- `cache rotate` remains local-backend only

### Sprint 8X (Release + Contract Stabilization Hardening)

- release pipeline hardening extended without runtime behavior changes:
  - build job now smoke-installs the produced wheel and validates `mcp-scan --version` against `pyproject` version
  - publish job keeps tag/version guard and adds installed wheel CLI/tag version guard before OIDC upload
  - OIDC publish, Sigstore signing, idempotent GitHub release, and PyPI visibility verification remain unchanged
- OAuth cache contract test matrix strengthened:
  - `persistent=false` now explicitly verified across all supported backends for hydration/persist bypass behavior
  - non-fatal backend error model, dispatch contract, compare contract, and local-only `cache rotate` invariants remain enforced

### Sprint 8Y (Consul KV Backend v1)

- OAuth persistent cache backend abstraction expanded again:
  - `auth.cache.backend` now supports:
    - `local`
    - `aws_secrets_manager`
    - `aws_ssm_parameter_store`
    - `gcp_secret_manager`
    - `azure_key_vault`
    - `hashicorp_vault`
    - `kubernetes_secrets`
    - `oci_vault`
    - `doppler_secrets`
    - `onepassword_connect`
    - `bitwarden_secrets`
    - `infisical_secrets`
    - `akeyless_secrets`
    - `gitlab_variables`
    - `github_actions_variables`
    - `github_environment_variables`
    - `github_organization_variables`
    - `consul_kv`
- Consul backend contract:
  - required: `consul_key_path`
  - optional: `consul_token_env` (default `CONSUL_HTTP_TOKEN`), `consul_api_url` (`http/https`, default `http://127.0.0.1:8500`)
  - pre-provisioned model (scanner does not auto-create missing Consul KV keys)
- Consul backend behavior:
  - auth uses env token only (`consul_token_env` / `CONSUL_HTTP_TOKEN`)
  - reads/writes JSON envelope in configured Consul KV key
  - key path is URL-encoded (with `/` preserved) for API calls
  - provider/read/write/parse/auth/network errors are non-fatal and bypass persistent layer
- lookup/write order remains unchanged:
  - in-memory -> persistent backend -> refresh grant -> primary grant
- `cache rotate` remains local-backend only

### Sprint 8Z (Redis KV Backend v1)

- OAuth persistent cache backend abstraction expanded again:
  - `auth.cache.backend` now supports:
    - `local`
    - `aws_secrets_manager`
    - `aws_ssm_parameter_store`
    - `gcp_secret_manager`
    - `azure_key_vault`
    - `hashicorp_vault`
    - `kubernetes_secrets`
    - `oci_vault`
    - `doppler_secrets`
    - `onepassword_connect`
    - `bitwarden_secrets`
    - `infisical_secrets`
    - `akeyless_secrets`
    - `gitlab_variables`
    - `github_actions_variables`
    - `github_environment_variables`
    - `github_organization_variables`
    - `consul_kv`
    - `redis_kv`
- Redis backend contract:
  - required: `redis_key`
  - optional: `redis_url` (default `redis://127.0.0.1:6379/0`), `redis_password_env` (default `REDIS_PASSWORD`)
  - pre-provisioned model (scanner does not auto-create missing Redis keys)
- Redis backend behavior:
  - auth uses env password only (`redis_password_env` / `REDIS_PASSWORD`)
  - reads/writes JSON envelope in configured Redis key
  - supports both `redis://` and `rediss://` connection URLs
  - provider/read/write/parse/auth/network errors are non-fatal and bypass persistent layer
- lookup/write order remains unchanged:
  - in-memory -> persistent backend -> refresh grant -> primary grant
- `cache rotate` remains local-backend only

### Sprint 8AA (OAuth Cache Stabilization + Release Hardening)

- OAuth cache backend dispatch was normalized to a centralized backend->handler contract:
  - remote load handlers are now resolved from one backend map
  - remote persist handlers are now resolved from one backend map
  - behavior remains unchanged (`local` fallback, non-fatal bypass, pre-provisioned semantics)
- CI release hardening was strengthened without CLI/runtime changes:
  - build smoke validates `pyproject` version == `__version__` == wheel metadata version == installed `mcp-scan --version`
  - publish guard now validates tag version against `pyproject`, `__version__`, and wheel metadata before OIDC publish
  - existing OIDC publish + Sigstore + idempotent GitHub release + PyPI visibility verification remains intact
- OAuth cache contract tests were tightened:
  - dispatch map completeness is validated against all non-local supported backends
  - existing persistent bypass, non-fatal provider error, compare contract, and local-only `cache rotate` invariants remain enforced

### Sprint 8AB (Cloudflare KV Backend v1)

- OAuth persistent cache backend abstraction expanded again:
  - `auth.cache.backend` now supports:
    - `local`
    - `aws_secrets_manager`
    - `aws_ssm_parameter_store`
    - `gcp_secret_manager`
    - `azure_key_vault`
    - `hashicorp_vault`
    - `kubernetes_secrets`
    - `oci_vault`
    - `doppler_secrets`
    - `onepassword_connect`
    - `bitwarden_secrets`
    - `infisical_secrets`
    - `akeyless_secrets`
    - `gitlab_variables`
    - `github_actions_variables`
    - `github_environment_variables`
    - `github_organization_variables`
    - `consul_kv`
    - `redis_kv`
    - `cloudflare_kv`
- Cloudflare backend contract:
  - required: `cf_account_id`, `cf_namespace_id`, `cf_kv_key`
  - optional: `cf_api_token_env` (default `CLOUDFLARE_API_TOKEN`), `cf_api_url` (`https`, default `https://api.cloudflare.com/client/v4`)
  - pre-provisioned model (scanner does not auto-create missing Cloudflare KV keys)
- Cloudflare backend behavior:
  - auth uses env token only (`cf_api_token_env` / `CLOUDFLARE_API_TOKEN`)
  - reads/writes JSON envelope in configured Cloudflare KV key
  - account/namespace/key path segments are URL-encoded before API calls
  - provider/read/write/parse/auth/network errors are non-fatal and bypass persistent layer
- lookup/write order remains unchanged:
  - in-memory -> persistent backend -> refresh grant -> primary grant
- `cache rotate` remains local-backend only

## Exit Code Contract (Current)

- `server` / `config` / `compare`:
  - `0`: no findings after severity filter
  - `1`: findings exist after severity filter
  - `2`: operational error
- `baseline`:
  - `0`: baseline written
  - `2`: operational error

## Current Non-Goals / Deferred

- additional persistent secret-store providers beyond `local`, `aws_secrets_manager`, `aws_ssm_parameter_store`, `gcp_secret_manager`, `azure_key_vault`, `hashicorp_vault`, `kubernetes_secrets`, `oci_vault`, `doppler_secrets`, `onepassword_connect`, `bitwarden_secrets`, `infisical_secrets`, `akeyless_secrets`, `gitlab_variables`, `github_actions_variables`, `github_environment_variables`, `github_organization_variables`, `consul_kv`, `redis_kv`, and `cloudflare_kv`; Sprint 8AA provides the shared dispatch/contract baseline for future provider onboarding
- visual/report schema refactors beyond current formatter behavior

## Validation Targets

Run from repo root:

```bash
pytest -q
mypy src
mcp-scan --version
```

Expected:

- tests green
- coverage `>=80%`
- mypy clean
