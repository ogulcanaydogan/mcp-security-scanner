# Setup Complete — Sprint 1-3 Implementation State

This file records the actual implementation status after Sprint 3.

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

## Exit Code Contract (Current)

- `server` / `config` / `compare`:
  - `0`: no findings after severity filter
  - `1`: findings exist after severity filter
  - `2`: operational error
- `baseline`:
  - `0`: baseline written
  - `2`: operational error

## Current Non-Goals / Deferred

- `streamable-http` transport
- OAuth/session auth flows
- analyzer expansion beyond MVP set (`StaticAnalyzer`, `PromptInjectionAnalyzer`)
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
