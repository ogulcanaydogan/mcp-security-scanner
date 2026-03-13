# MCP Security Scanner

[![CI](https://github.com/ogulcanaydogan/mcp-security-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/ogulcanaydogan/mcp-security-scanner/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Coverage](https://img.shields.io/badge/coverage-%3E%3D80%25-green.svg)](.)

Security scanner for Model Context Protocol (MCP) servers.  
Scans MCP capabilities, runs analyzer checks, and exports findings in `json`, `html`, or `sarif`.

## Current Scope (Sprint 1-8G)

- `stdio`, `sse`, and `streamable-http` transport support in discovery/connector layer
- CLI commands implemented: `server`, `config`, `baseline`, `compare`, `cache rotate`
- `config` supports auth/session flow v1 for network transports (`bearer`, `api_key`, `session_cookie`, `oauth_client_credentials`, `oauth_device_code`, `oauth_auth_code_pkce`)
- Optional persistent OAuth cache hardening (strict lock, corruption recovery, metadata key management, multi-key recovery)
- Advanced persistent OAuth cache backends (`auth.cache.backend=aws_secrets_manager|gcp_secret_manager`) for config-based OAuth flows
- OAuth provider hardening+ (tolerant token parsing and transient retry policy for token endpoints)
- OAuth provider integrations v2 in `config` auth: `token_endpoint_auth_method=private_key_jwt` supports env/file/AWS KMS signing sources
- OAuth token-endpoint mTLS (`auth.mtls_*`) and transport-level discovery mTLS (`mtls_*` on network entries)
- Dynamic analyzer hardening (opt-in `--dynamic`) with bounded probe policy, deterministic ordering, and noise suppression
- Dynamic analyzer expansion (opt-in `--dynamic`) with semantic probe variants and stronger false-positive suppression
- Release stabilization (Sprint 8D): PyPI distribution name switched to `ogulcanaydogan-mcp-security-scanner` to avoid name collision
- Default analyzers enabled in scan flows:
  - `StaticAnalyzer`
  - `PromptInjectionAnalyzer`
  - `EscalationAnalyzer`
  - `ToolPoisoningAnalyzer`
  - `CrossToolAnalyzer`
- Baseline mutation detection (`added` / `removed` / `changed`) with deterministic hashes
- Severity threshold filtering and documented exit-code contract

## Installation

From PyPI (after trusted publisher mapping is enabled and first publish succeeds):

```bash
pip install ogulcanaydogan-mcp-security-scanner
```

From source:

```bash
git clone https://github.com/ogulcanaydogan/mcp-security-scanner.git
cd mcp-security-scanner
pip install -e .[dev]
```

## Quick Start

```bash
# Version check
mcp-scan --version

# Scan a stdio server command
mcp-scan server "python -m my_mcp_server" --format json

# Scan a URL target (auto-detected: streamable-http, fallback to sse)
mcp-scan server "https://example.com/sse" --format html --output report.html

# Scan a URL target with auth/header/mTLS JSON options
mcp-scan server "https://example.com/mcp" \
  --headers-json '{"X-Trace":"run-42"}' \
  --auth-json '{"type":"api_key","key_env":"MCP_API_KEY"}' \
  --mtls-cert-file /etc/mcp/client.crt \
  --mtls-key-file /etc/mcp/client.key \
  --format json

# Run dynamic probes in addition to default analyzers (opt-in)
mcp-scan server "python -m my_mcp_server" --dynamic --format json

# Build baseline from live server snapshot
mcp-scan baseline "python -m my_mcp_server" --save baseline.json

# Compare live snapshot with baseline
mcp-scan compare baseline.json "python -m my_mcp_server" --format sarif --output mutations.sarif

# Rotate persistent OAuth cache encryption key
mcp-scan cache rotate
```

## `config` Command (Claude Desktop Config)

`mcp-scan config` reads `mcpServers` entries and scans each server sequentially.

```bash
mcp-scan config ~/.claude/claude_desktop_config.json --timeout 30 --format json
```

Supported entry styles:

```json
{
  "mcpServers": {
    "local-stdio": {
      "transport": "stdio",
      "command": "python",
      "args": ["-m", "my_mcp_server"],
      "env": {"APP_ENV": "prod"}
    },
    "remote-sse": {
      "transport": "sse",
      "url": "https://example.com/sse",
      "headers": {"X-Trace": "req-42"},
      "mtls_cert_file": "/etc/mcp/transport-client.crt",
      "mtls_key_file": "/etc/mcp/transport-client.key",
      "mtls_ca_bundle_file": "/etc/mcp/transport-ca.pem",
      "auth": {"type": "bearer", "token_env": "MCP_BEARER_TOKEN"}
    },
    "remote-streamable": {
      "transport": "streamable-http",
      "url": "https://example.com/mcp",
      "auth": {"type": "api_key", "key_env": "MCP_API_KEY", "header": "X-API-Key"}
    },
    "remote-session": {
      "transport": "sse",
      "url": "https://example.com/session",
      "headers": {"Cookie": "existing=1"},
      "auth": {"type": "session_cookie", "cookie_env": "MCP_SESSION_ID", "cookie_name": "session"}
    },
    "remote-oauth": {
      "transport": "streamable-http",
      "url": "https://example.com/mcp",
      "auth": {
        "type": "oauth_client_credentials",
        "token_url": "https://auth.example.com/oauth/token",
        "client_id_env": "MCP_OAUTH_CLIENT_ID",
        "token_endpoint_auth_method": "private_key_jwt",
        "client_assertion_kms_key_id": "arn:aws:kms:eu-west-1:111122223333:key/abcd",
        "client_assertion_kms_region": "eu-west-1",
        "client_assertion_kms_endpoint_url": "https://kms.eu-west-1.amazonaws.com",
        "client_assertion_kid": "key-2026-03",
        "mtls_cert_file": "/etc/mcp/oauth-client.crt",
        "mtls_key_file": "/etc/mcp/oauth-client.key",
        "mtls_ca_bundle_file": "/etc/mcp/oauth-ca.pem",
        "scope": "mcp.read",
        "audience": "mcp-security-scanner",
        "cache": {"persistent": true, "namespace": "prod-security", "backend": "local"},
        "header": "Authorization",
        "scheme": "Bearer"
      }
    },
    "remote-oauth-aws-cache": {
      "transport": "sse",
      "url": "https://example.com/sse",
      "auth": {
        "type": "oauth_client_credentials",
        "token_url": "https://auth.example.com/oauth/token",
        "client_id_env": "MCP_OAUTH_CLIENT_ID",
        "client_secret_env": "MCP_OAUTH_CLIENT_SECRET",
        "cache": {
          "persistent": true,
          "namespace": "prod-security",
          "backend": "aws_secrets_manager",
          "aws_secret_id": "mcp-security-scanner/oauth-cache-prod",
          "aws_region": "eu-west-1",
          "aws_endpoint_url": "https://secretsmanager.eu-west-1.amazonaws.com"
        }
      }
    },
    "remote-oauth-gcp-cache": {
      "transport": "streamable-http",
      "url": "https://example.com/mcp",
      "auth": {
        "type": "oauth_client_credentials",
        "token_url": "https://auth.example.com/oauth/token",
        "client_id_env": "MCP_OAUTH_CLIENT_ID",
        "client_secret_env": "MCP_OAUTH_CLIENT_SECRET",
        "cache": {
          "persistent": true,
          "namespace": "prod-security",
          "backend": "gcp_secret_manager",
          "gcp_secret_name": "projects/my-project/secrets/mcp-security-scanner-oauth-cache",
          "gcp_endpoint_url": "https://secretmanager.googleapis.com"
        }
      }
    },
    "remote-device-oauth": {
      "transport": "sse",
      "url": "https://example.com/sse",
      "auth": {
        "type": "oauth_device_code",
        "device_authorization_url": "https://auth.example.com/oauth/device/code",
        "token_url": "https://auth.example.com/oauth/token",
        "client_id_env": "MCP_OAUTH_DEVICE_CLIENT_ID",
        "client_secret_env": "MCP_OAUTH_DEVICE_CLIENT_SECRET",
        "token_endpoint_auth_method": "client_secret_post",
        "scope": "mcp.read",
        "audience": "mcp-security-scanner",
        "header": "Authorization",
        "scheme": "Bearer"
      }
    },
    "remote-auth-code": {
      "transport": "streamable-http",
      "url": "https://example.com/mcp",
      "auth": {
        "type": "oauth_auth_code_pkce",
        "authorization_url": "https://auth.example.com/oauth/authorize",
        "token_url": "https://auth.example.com/oauth/token",
        "client_id_env": "MCP_OAUTH_AUTH_CODE_CLIENT_ID",
        "scope": "mcp.read",
        "audience": "mcp-security-scanner",
        "redirect_host": "127.0.0.1",
        "redirect_port": 8765,
        "callback_path": "/callback"
      }
    }
  }
}
```

Notes:
- `stdio` validation: `command` required, `args` optional list, `env` optional object
- `sse` validation: `url` required (`http/https`), `headers` optional object
- `streamable-http` validation: `url` required (`http/https`), `headers` optional object
- `transport: "streamable_http"` alias is accepted and normalized to `streamable-http`
- `auth` is optional and only valid for `sse`/`streamable-http` entries
- `auth` validation/env resolution errors produce `auth_config_error` findings and scan continues with remaining servers
- OAuth token endpoint/network/response failures produce `auth_token_error` findings and scan continues with remaining servers
- `oauth_client_credentials` and `oauth_device_code` support optional `token_endpoint_auth_method`:
  - `client_secret_post` (default)
  - `client_secret_basic` (`oauth_device_code` requires `client_secret_env` when used)
  - `private_key_jwt` (`oauth_client_credentials` + `oauth_device_code`; `oauth_auth_code_pkce` remains unchanged)
- `private_key_jwt` validation rules:
  - exactly one signing source is required:
    - `client_assertion_key_env`
    - `client_assertion_key_file`
    - `client_assertion_kms_key_id` (AWS KMS signing)
  - optional KMS tuning: `client_assertion_kms_region`, `client_assertion_kms_endpoint_url`
  - optional `client_assertion_kid` is propagated into JWT header
  - v1 signing algorithm is `RS256`
- token endpoint mTLS options for OAuth auth entries:
  - `mtls_cert_file` + `mtls_key_file` must be provided together
  - optional `mtls_ca_bundle_file` is used as request verify bundle
  - mTLS is applied only to OAuth token endpoint calls
- transport-level mTLS options for network entries (`sse`, `streamable-http`):
  - top-level `mtls_cert_file` + `mtls_key_file` must be provided together
  - optional top-level `mtls_ca_bundle_file` is used as connection verify bundle
  - applies to discovery transport HTTP client setup (independent from `auth.mtls_*`)
- OAuth token cache key is deterministic: `namespace + token_url + client_id + scope + audience`
- `auth.cache` is optional and only valid for OAuth auth types:
  - `persistent` (bool, default `false`)
  - `namespace` (string, default `"default"`)
  - `backend` (string, default `"local"`): `local`, `aws_secrets_manager`, or `gcp_secret_manager`
  - `aws_secret_id` (required when `backend=aws_secrets_manager`)
  - optional `aws_region`, `aws_endpoint_url` for AWS client routing
  - `gcp_secret_name` (required when `backend=gcp_secret_manager`, format `projects/<project>/secrets/<secret>`)
  - optional `gcp_endpoint_url` for GCP client endpoint routing (ADC auth)
- cache lookup order for OAuth:
  - in-memory
  - persistent disk cache (`auth.cache.persistent=true`)
  - refresh grant
  - primary grant
- persistent cache details (opt-in):
  - `backend=local`:
    - encrypted file: `~/.cache/mcp-security-scanner/oauth-cache-v1.json.enc`
    - lock file: `~/.cache/mcp-security-scanner/oauth-cache-v1.lock` (exclusive lock with retry; timeout falls back to in-memory/live token flow)
    - encrypted payload envelope: `schema_version`, `key_id`, `updated_at`, `entries` (v2)
    - encryption key lookup: OS keyring (`service="mcp-security-scanner"`, `username="oauth-cache-key-v1"`) then fallback key file `~/.config/mcp-security-scanner/cache.key`
    - key metadata stores `active` + `historical` key entries (`key_id` + `fernet_key`); legacy raw key format remains readable
    - decrypt recovery order: payload `key_id` match when possible, then active key, then historical keys (deterministic order)
    - historical key retention is bounded (max 3); `cache rotate` promotes current active key into historical set
    - fallback key file is created with `0600` permissions
    - cache/key file mode hardening uses best-effort `0600`
    - corrupt or undecryptable cache payloads are quarantined as `oauth-cache-v1.json.enc.corrupt.<timestamp>`
  - `backend=aws_secrets_manager`:
    - cache payload is stored as a single JSON envelope in the configured AWS secret (`auth.cache.aws_secret_id`)
    - optional `aws_region` and `aws_endpoint_url` tune client resolution
  - `backend=gcp_secret_manager`:
    - cache payload is stored as a single JSON envelope in the configured GCP secret (`auth.cache.gcp_secret_name`)
    - writes use new secret versions via `projects/.../secrets/.../versions/latest` read + `add_secret_version` write
    - secret must be pre-provisioned; missing/provider errors are non-fatal and scanner falls back to live token flow
    - optional `gcp_endpoint_url` is supported for custom endpoint routing; auth uses ADC
  - backend read/write/decrypt/parse failures are non-fatal; scanner falls back to live token flow
- `oauth_device_code` uses copy/paste UX (`verification_uri` + `user_code`) and supports refresh-token reuse on expiry
- in headless/CI environments (no interactive TTY), `oauth_device_code` entries produce `auth_token_error` and scan continues
- `oauth_auth_code_pkce` uses local callback + PKCE (`S256`), prints authorization URL, and supports refresh-token reuse on expiry
- `oauth_auth_code_pkce` callback listener tries configured/default port first and falls back to random local port when needed
- in headless/CI environments (no interactive TTY), `oauth_auth_code_pkce` entries produce `auth_token_error` and scan continues
- Authorization header scheme precedence for OAuth is:
  - `auth.scheme` (if provided)
  - token response `token_type` (if present)
  - fallback `Bearer`
- OAuth token/device/refresh/auth-code endpoint calls use shared transient retry policy:
  - retryable statuses: `429`, `500`, `502`, `503`, `504`
  - retryable transport errors: timeout/connection/network
  - max `2` retries (total `3` attempts), short bounded backoff
- dynamic analyzer v1 is opt-in:
  - enable with `--dynamic` on `server` and `config`
  - default pipeline remains unchanged when flag is omitted
  - bounded runtime policy is enforced from a single control point:
    - max tool count, max probe payload count, max payload fields, per-probe timeout
  - dynamic findings are returned in deterministic order with stable metadata keys
  - benign placeholder/blocked-execution contexts are suppressed to reduce false positives
- Refresh fallback behavior:
  - if refresh fails with `invalid_grant` / `invalid_token`, scanner drops cached refresh token and retries primary grant once
  - if retry requires interaction in headless mode, `auth_token_error` is emitted and scan continues
- auth finding evidence never includes secret/token/cookie plaintext
- Unsupported transport entries do not stop the run; they are reported as findings
- Per-server scan failures do not stop the run; they are reported as `scan_failure` findings
- URL positional commands (`server`, `baseline`, `compare`) support:
  - `--headers-json` (JSON object)
  - `--auth-json` (JSON object with same shape as `config.auth`)
  - `--mtls-cert-file` + `--mtls-key-file` (optional `--mtls-ca-bundle-file`)
- URL auth/mTLS options are URL-only; when used with stdio targets the command fails with operational error (`exit 2`)

`cache` command:
- `mcp-scan cache rotate` rotates persistent OAuth cache encryption key and re-encrypts cached entries
- exit `0` on success, exit `2` on operational failure

## Outputs and Severity Filter

- `--format`: `json` (default), `html`, `sarif`
- `--output`: write report to file; if omitted, prints to stdout
- `--severity`: `critical | high | medium | low | info | all`

Severity threshold is inclusive (`high` shows `high` + `critical`).

## Exit Codes

| Command | Exit `0` | Exit `1` | Exit `2` |
|---|---|---|---|
| `server` | No findings after severity filter | Findings exist after filter | Operational error |
| `config` | No findings after severity filter | Findings exist after filter | Operational error |
| `compare` | No findings after severity filter | Findings exist after filter | Operational error |
| `baseline` | Baseline created successfully | N/A | Operational error |

## Baseline v1 Format

`baseline` writes a `baseline-v1` JSON document:

- `schema_version`
- `scanner_version`
- `created_at`
- `server` (`name`, `command`)
- `tools[]` (`overall_hash`, field hashes, metadata)

`compare` maps mutation severity as:

- `removed` / `changed`: `high`
- `added`: `medium`

All mutation findings map to `OWASP: LLM05`.

## Development

```bash
pytest -q
mypy src
```

Current quality gate:
- tests passing
- coverage `>=80%`
- `mypy src` clean

## Roadmap (Post Sprint 8E)

Deferred items:
- additional persistent secret-store providers beyond `local`, `aws_secrets_manager`, and `gcp_secret_manager`
