# MCP Security Scanner — Repository Index

Current index for the implemented Sprint 1-6H scope.

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

## Top-Level Docs

- [README.md](README.md): user-facing usage, transports, commands, exit codes
- [ROADMAP.md](ROADMAP.md): broader project direction/backlog
- [CONTRIBUTING.md](CONTRIBUTING.md): development and contribution flow
- [SETUP_COMPLETE.md](SETUP_COMPLETE.md): setup and completion checklist

## Source Map

### CLI and Core

- `src/mcp_security_scanner/cli.py`
  - Implemented commands: `server`, `config`, `baseline`, `compare`, `cache rotate`
  - Severity filtering, output formatting, exit code contract
  - URL target auto-routing with fallback (`streamable-http` -> `sse`)
  - Config auth normalization (`bearer` / `api_key` / `session_cookie` / `oauth_client_credentials` / `oauth_device_code` / `oauth_auth_code_pkce`)
  - Auth finding flow: `auth_config_error` (schema/env) and `auth_token_error` (token endpoint)
  - OAuth client-credentials + device-code + auth-code PKCE/refresh with in-memory cache
  - Optional encrypted persistent OAuth cache via `auth.cache` (`persistent`, `namespace`)
  - Persistent cache hardening:
    - strict lock file with retry/timeout and non-fatal bypass
    - corrupt cache quarantine (`*.corrupt.<timestamp>`)
    - v2 cache envelope (`schema_version`, `key_id`, `updated_at`, `entries`) with v1 backward compatibility
    - key metadata handling (`active` + `historical` key sets with `key_id` + `fernet_key`) and `mcp-scan cache rotate`
    - historical key retention (max 3) and deterministic decrypt recovery (`key_id` match -> active -> historical)
  - `token_endpoint_auth_method` support (`client_secret_post` / `client_secret_basic`) for config OAuth entries
  - OAuth Authorization header precedence (`auth.scheme` > `token_type` > `Bearer`)
  - Shared transient retry policy for OAuth token/device/refresh/auth-code endpoint calls (`429/5xx` + timeout/connection errors)
  - Refresh fallback on `invalid_grant`/`invalid_token` with headless-safe behavior

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

## Tests

- `tests/test_cli.py`: command flows, output/exit codes, baseline/compare, URL fallback routing
- `tests/test_discovery.py`: stdio + SSE + streamable-http connector behavior, validation, disconnect paths
- `tests/test_mutation.py`: baseline-v1, deterministic hash, mutation diff logic
- `tests/test_reporter.py`: JSON/HTML/SARIF formatting
- `tests/analyzers/`: analyzer unit tests

## Quality Commands

```bash
pytest -q
mypy src
```

Coverage threshold is enforced at `>=80%`.

## Current Deferred Backlog

- OAuth advanced provider integrations beyond current config-only auth scope (`private_key_jwt`, mTLS, external KMS flows)
- advanced persistent secret-store options beyond keyring/fallback file model
- further analyzer expansion beyond current core (Static + PromptInjection + Escalation + ToolPoisoning + CrossTool)
