# MCP Security Scanner — Repository Index

Current index for the implemented Sprint 1-3 scope.

## Status Snapshot

- Sprint 1: done (`server` MVP, severity ranking fix, stdio connector)
- Sprint 2: done (`config`, `baseline`, `compare`, baseline-v1, mutation compare)
- Sprint 3: done (`sse` transport support + CLI target unification)

## Top-Level Docs

- [README.md](README.md): user-facing usage, transports, commands, exit codes
- [ROADMAP.md](ROADMAP.md): broader project direction/backlog
- [CONTRIBUTING.md](CONTRIBUTING.md): development and contribution flow
- [SETUP_COMPLETE.md](SETUP_COMPLETE.md): setup and completion checklist

## Source Map

### CLI and Core

- `src/mcp_security_scanner/cli.py`
  - Implemented commands: `server`, `config`, `baseline`, `compare`
  - Severity filtering, output formatting, exit code contract
  - URL target auto-routing to SSE (`http://` / `https://`)

- `src/mcp_security_scanner/discovery.py`
  - `MCPServerConnector` with `stdio` and `sse` transports
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

## Tests

- `tests/test_cli.py`: command flows, output/exit codes, baseline/compare, SSE target routing
- `tests/test_discovery.py`: stdio + SSE connector behavior, validation, disconnect paths
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

- `streamable-http` transport
- auth/session flows beyond static SSE headers
- analyzer set expansion beyond MVP (Static + PromptInjection)
