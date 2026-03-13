# MCP Security Scanner

[![CI](https://github.com/ogulcanaydogan/mcp-security-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/ogulcanaydogan/mcp-security-scanner/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Coverage](https://img.shields.io/badge/coverage-%3E%3D80%25-green.svg)](.)

Security scanner for Model Context Protocol (MCP) servers.  
Scans MCP capabilities, runs analyzer checks, and exports findings in `json`, `html`, or `sarif`.

## Current Scope (Sprint 1-3)

- `stdio` and `sse` transport support in discovery/connector layer
- CLI commands implemented: `server`, `config`, `baseline`, `compare`
- MVP analyzers enabled in scan flows:
  - `StaticAnalyzer`
  - `PromptInjectionAnalyzer`
- Baseline mutation detection (`added` / `removed` / `changed`) with deterministic hashes
- Severity threshold filtering and documented exit-code contract

## Installation

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

# Scan an SSE target (URL target is auto-detected as sse)
mcp-scan server "https://example.com/sse" --format html --output report.html

# Build baseline from live server snapshot
mcp-scan baseline "python -m my_mcp_server" --save baseline.json

# Compare live snapshot with baseline
mcp-scan compare baseline.json "python -m my_mcp_server" --format sarif --output mutations.sarif
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
      "headers": {"Authorization": "Bearer <token>"}
    }
  }
}
```

Notes:
- `stdio` validation: `command` required, `args` optional list, `env` optional object
- `sse` validation: `url` required (`http/https`), `headers` optional object
- Unsupported transport entries do not stop the run; they are reported as findings
- Per-server scan failures do not stop the run; they are reported as `scan_failure` findings

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

## Roadmap (Post Sprint 3)

Deferred items:
- `streamable-http` transport
- OAuth/session-based auth flows
- broader analyzer set beyond MVP
