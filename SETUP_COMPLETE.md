# Setup Complete — Sprint 1-6G Implementation State

This file records the actual implementation status after Sprint 6G.

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
- `auth.cache` is OAuth-only (`oauth_client_credentials`, `oauth_device_code`, `oauth_auth_code_pkce`)
  - invalid shape/field usage returns `auth_config_error`
- optional persistent cache implementation:
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

## Exit Code Contract (Current)

- `server` / `config` / `compare`:
  - `0`: no findings after severity filter
  - `1`: findings exist after severity filter
  - `2`: operational error
- `baseline`:
  - `0`: baseline written
  - `2`: operational error

## Current Non-Goals / Deferred

- OAuth advanced provider-specific flows beyond current config-only auth v1
- multi-key historical decrypt and advanced persistent secret-store options
- further analyzer expansion beyond current core (`StaticAnalyzer`, `PromptInjectionAnalyzer`, `EscalationAnalyzer`, `ToolPoisoningAnalyzer`, `CrossToolAnalyzer`)
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
