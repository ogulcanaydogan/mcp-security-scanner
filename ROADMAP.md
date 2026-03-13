# ROADMAP — mcp-security-scanner

**Vision**: The first open-source security scanner for Model Context Protocol (MCP) servers.
Detects prompt injection, tool poisoning, capability escalation, and rug-pull attacks.
Maps findings to OWASP LLM Top 10 for governance and risk management.

---

## Phase 1: Core Scanner Engine (Week 1)

### 1.1 Project Setup
- [ ] Initialize Python project structure with `pyproject.toml`
  - **File**: `/src/pyproject.toml`
  - **Details**: Python >=3.11, dependencies (mcp, click, rich, pydantic, jinja2, httpx, mcp-server-std), dev deps (pytest, pytest-cov, pytest-asyncio, ruff, mypy)
  - **Entry point**: `mcp-scan = mcp_security_scanner.cli:main`
  - **AC**: `pip install -e .` installs package and `mcp-scan --version` works

### 1.2 MCP Server Discovery & Connection
- [ ] Implement MCP server discovery module
  - **File**: `src/mcp_security_scanner/discovery.py`
  - **Classes**:
    - `MCPServerConnector`: Manage stdio/SSE transport connections
    - `ServerCapabilities`: Data model for discovered tools, resources, prompts
  - **Methods**:
    - `connect(transport_config: dict) -> AsyncGenerator[ServerCapabilities]`
    - `enumerate_tools() -> list[ToolDefinition]`
    - `enumerate_resources() -> list[ResourceDefinition]`
    - `enumerate_prompts() -> list[PromptDefinition]`
  - **AC**: Can connect to a real or mock MCP server via stdio, enumerate 3+ tools, and retrieve full schemas

### 1.3 Static Analysis Engine
- [ ] Build static analysis module for tool descriptions
  - **File**: `src/mcp_security_scanner/analyzers/static.py`
  - **Classes**:
    - `StaticAnalyzer(BaseAnalyzer)`
  - **Detections** (min 10 patterns):
    - Dangerous functions: `eval`, `exec`, `__import__`, `os.system`, `subprocess.call`
    - File system access: `open()`, `pathlib.Path`, `/etc/`, `/root/`, absolute paths in descriptions
    - Network operations: `requests`, `socket`, `http`, external URLs
    - Environment variable access: `os.getenv`, `os.environ`
    - Shell injection risk: backticks, `$()` in command descriptions
    - SQL patterns: `SELECT`, `DELETE`, `DROP` in tool descriptions
    - Crypto patterns: `private_key`, `secret_key`, `api_key` without encryption context
    - Regex bombs: ReDoS patterns in input validation descriptions
    - XXE patterns: XML entity references
    - LDAP injection: LDAP filter characters in descriptions
  - **AC**: Detects all 10+ patterns when given test tool definitions; produces Finding objects with evidence

### 1.4 Dynamic Analysis Engine
- [ ] Build dynamic analysis module for runtime behavior
  - **File**: `src/mcp_security_scanner/analyzers/dynamic.py`
  - **Classes**:
    - `DynamicAnalyzer(BaseAnalyzer)`
    - `TestVector`: Data model for attack payload (name, description, payload, expected_behavior)
  - **Methods**:
    - `test_tool(tool: ToolDefinition, vectors: list[TestVector]) -> list[Finding]`
    - `monitor_execution(tool_name: str, args: dict) -> ExecutionReport` (side effects tracking)
  - **Test vectors** (min 5):
    - Basic prompt injection: `"; DROP TABLE users; --"`
    - Command injection: `"; cat /etc/passwd #`
    - Template injection: `{{ 7 * 7 }}`
    - Unicode/encoding bypass: `\x2e\x2e/\x2e\x2e/etc/passwd`
    - Header injection: `\r\nX-Custom: injected`
  - **Side effect detection**:
    - Unexpected file creation (temp directories)
    - Unexpected network requests (DNS resolution, HTTP calls outside whitelist)
    - Process spawning (subprocess, shell execution)
    - Memory exhaustion patterns
  - **AC**: Executes test suite against mock MCP server, captures 3+ side effects, reports findings

### 1.5 Prompt Injection Detector
- [ ] Implement prompt injection detection module
  - **File**: `src/mcp_security_scanner/analyzers/injection.py`
  - **Classes**:
    - `PromptInjectionAnalyzer(BaseAnalyzer)`
  - **Detections**:
    - Embedded instructions: "System:", "Administrator:", "Ignore previous", "You are now"
    - Tool description mutations: "Do X instead of Y"
    - Resource poisoning: Embedded JSON/YAML with malicious instructions
    - Jailbreak patterns: "forget your instructions", "bypass security", "disable safety"
    - Context confusion: Quotes/backticks suggesting prompt context breaks
    - Token smuggling: High Unicode/special char density in descriptions
  - **AC**: Detects OWASP LLM01 patterns in tool descriptions and resources; finds 3+ injection signatures in test data

---

## Phase 2: Attack Detection Rules (Week 1-2)

### 2.1 Tool Poisoning & Rug-Pull Detector
- [ ] Implement tool poisoning detector
  - **File**: `src/mcp_security_scanner/analyzers/poisoning.py`
  - **Classes**:
    - `ToolPoisoningAnalyzer(BaseAnalyzer)`
  - **Methods**:
    - `detect_description_mutation(baseline: ToolDefinition, current: ToolDefinition) -> Finding`
    - `detect_hidden_instructions(tool: ToolDefinition) -> list[Finding]`
    - `hash_tool_schema(tool: ToolDefinition) -> str` (for baseline comparisons)
  - **Detections**:
    - Tool description changed post-approval (rug-pull)
    - Input/output schema modified (parameter types, return types)
    - Hidden instructions in defaultValue or example fields
    - Tool removed from server (disappearance attack)
    - Tool name or namespace collision (shadowing)
  - **AC**: Compares two tool snapshots, detects mutations, produces audit trail

### 2.2 Capability Escalation Detector
- [ ] Implement capability escalation detector
  - **File**: `src/mcp_security_scanner/analyzers/escalation.py`
  - **Classes**:
    - `EscalationAnalyzer(BaseAnalyzer)`
    - `CapabilityRiskProfile`: Enum for risk levels (ADMIN, PRIVILEGED, SENSITIVE, STANDARD, BENIGN)
  - **Risk taxonomy**:
    - ADMIN: System shutdown, config changes, process termination, user management
    - PRIVILEGED: File system write, network outbound, credential access, database mutations
    - SENSITIVE: File system read (non-public), environment variable read, resource enumeration
    - STANDARD: Compute, inference, read-only API calls
    - BENIGN: Status checks, heartbeat, version info
  - **Methods**:
    - `assess_tool_risk(tool: ToolDefinition) -> CapabilityRiskProfile`
    - `score_tool_permissions(tool: ToolDefinition) -> float` (0.0-1.0, where 1.0 = max risk)
    - `flag_excessive_permissions(tools: list[ToolDefinition]) -> list[Finding]`
  - **AC**: Produces risk score per tool; flags tools requesting admin access without justification

### 2.3 Cross-Tool Attack Detector
- [ ] Implement cross-tool attack detector
  - **File**: `src/mcp_security_scanner/analyzers/cross_tool.py`
  - **Classes**:
    - `CrossToolAnalyzer(BaseAnalyzer)`
    - `AttackChain`: Model for tool combinations leading to escalation
  - **Attack patterns**:
    - Chain 1: `file_read` → `code_execution` (read config, execute commands)
    - Chain 2: `env_read` → `network_call` (exfiltrate secrets via HTTP)
    - Chain 3: `sql_query` → `file_write` (persist malicious data)
    - Chain 4: `prompt_inject_tool_1` → `exec_tool_2` (chain injections)
  - **Methods**:
    - `find_dangerous_chains(tools: list[ToolDefinition]) -> list[AttackChain]`
    - `score_chain_risk(chain: AttackChain) -> float`
  - **AC**: Identifies 3+ cross-tool attack patterns in test data; produces chain diagrams

### 2.4 OWASP LLM Top 10 Mapping
- [ ] Create OWASP LLM Top 10 mapping
  - **File**: `src/mcp_security_scanner/owasp_mapping.py`
  - **Classes**:
    - `OWASPCategory`: Enum with all 10 categories
    - `OWASPMapping`: Data model linking findings to OWASP IDs
  - **Mapping**:
    - LLM01 - Prompt Injection → PromptInjectionAnalyzer findings
    - LLM02 - Insecure Output Handling → StaticAnalyzer (unsafe deserialization)
    - LLM03 - Training Data Poisoning → ToolPoisoningAnalyzer
    - LLM04 - Model Denial of Service → DynamicAnalyzer (resource exhaustion)
    - LLM05 - Supply Chain Vulnerability → ToolPoisoningAnalyzer (rug-pull)
    - LLM06 - Sensitive Information Disclosure → EscalationAnalyzer (env vars, secrets)
    - LLM07 - Insecure Plugin Integration → CrossToolAnalyzer, EscalationAnalyzer
    - LLM08 - Excessive Agency → EscalationAnalyzer (admin capabilities)
    - LLM09 - Overreliance on LLM-generated Content → PromptInjectionAnalyzer
    - LLM10 - Insecure Model Retrieval → (covered by discovery + static analysis)
  - **Methods**:
    - `map_finding_to_owasp(finding: Finding) -> list[OWASPCategory]`
    - `get_owasp_remediation(category: OWASPCategory) -> str`
  - **AC**: All 10 OWASP categories have ≥1 detection rule; findings include OWASP ID

---

## Phase 3: Reporting & CLI (Week 2)

### 3.1 Report Generator
- [ ] Build multi-format report generator
  - **File**: `src/mcp_security_scanner/reporter.py`
  - **Classes**:
    - `ScanReport`: Data model for scan results (findings, summary, metadata)
    - `ReportFormatter`: Base class
    - `JSONReportFormatter(ReportFormatter)`
    - `HTMLReportFormatter(ReportFormatter)`
    - `SARIFReportFormatter(ReportFormatter)`
  - **JSON output**:
    - Structured findings array with severity, category, evidence, remediation
    - Server metadata (name, version, tool count)
    - Scan timestamp, duration, scanner version
  - **HTML output**:
    - Responsive design, severity color coding (red/orange/yellow/blue/gray)
    - Severity filter, sortable tables, OWASP mapping sidebar
    - Tool-by-tool summary + detailed findings
    - Generated with Jinja2 templates (src/mcp_security_scanner/templates/)
  - **SARIF output** (GitHub-compatible):
    - SARIF 2.1.0 format for integration with GitHub Code Scanning
    - Severity levels mapped to SARIF rules
    - File/line references where applicable
  - **Methods**:
    - `generate(findings: list[Finding], format: str) -> str`
    - `save_report(report: ScanReport, path: str, format: str)`
  - **AC**: All three formats produce valid output; HTML renders in browser; SARIF passes schema validation

### 3.2 CLI Interface
- [ ] Build comprehensive CLI with Click
  - **File**: `src/mcp_security_scanner/cli.py`
  - **Commands**:
    - `mcp-scan server <server-stdio-command>` — scan a single MCP server via stdio
      - `--timeout 30` — max seconds to wait for server response
      - `--format json|html|sarif` — output format
      - `--output report.json` — save to file (default: stdout)
      - `--severity critical|high|medium|low|all` — filter findings
      - Example: `mcp-scan server "python -m my_mcp_server" --format html --output scan.html`
    - `mcp-scan config <path/to/claude_desktop_config.json>` — scan all configured servers
      - `--format json|html|sarif`
      - `--output report.html` — aggregate report
      - Scans all servers in `claude_desktop_config.json` sequentially
    - `mcp-scan baseline <server> --save baseline.json` — save tool schema baseline
    - `mcp-scan compare <baseline.json> <server>` — detect tool mutations
    - Global flags:
      - `--verbose` — debug output
      - `--version` — show version
  - **Output**:
    - Progress bar with rich library
    - Color-coded severity levels
    - Summary: "Found 5 critical, 12 high, 8 medium vulnerabilities"
  - **AC**: All commands work end-to-end; help text is clear; exit codes are 0 (clean) or 1 (findings)

### 3.3 Comprehensive Test Suite
- [ ] Write unit and integration tests
  - **File structure**:
    - `tests/test_discovery.py` — test MCP server connection
    - `tests/analyzers/test_static.py` — test pattern detection
    - `tests/analyzers/test_dynamic.py` — test runtime behavior
    - `tests/analyzers/test_injection.py` — test injection detection
    - `tests/analyzers/test_poisoning.py` — test rug-pull detection
    - `tests/analyzers/test_escalation.py` — test risk scoring
    - `tests/analyzers/test_cross_tool.py` — test attack chains
    - `tests/test_reporter.py` — test all output formats
    - `tests/test_cli.py` — test CLI commands
  - **Mock servers** (src/tests/fixtures/mock_servers/):
    - `benign_server.py` — safe tools only
    - `malicious_server.py` — tools with all attack patterns
    - `rug_pull_server.py` — server that mutates tool schemas
  - **Fixtures** (src/tests/fixtures/):
    - `tool_definitions.py` — sample tool schemas for testing
    - `payloads.py` — injection/attack payloads
  - **Coverage target**: >80% code coverage
  - **AC**: `pytest` passes; coverage report shows >80%

---

## Phase 4: CI/CD & Distribution (Week 2)

### 4.1 GitHub Actions CI/CD
- [ ] Set up automated testing and release pipeline
  - **File**: `.github/workflows/ci.yml`
  - **Triggers**: push, pull_request, release
  - **Jobs**:
    - **Lint**: ruff check, black formatting check
    - **Type check**: mypy strict mode
    - **Test**: pytest with coverage report
    - **Build**: create wheel and sdist
    - **Release** (on tag): build artifacts, sign with Sigstore, push to PyPI
  - **AC**: Pipeline passes on every push; artifacts generated; PyPI release works

### 4.2 Docker Image
- [ ] Create multi-stage Docker image
  - **File**: `Dockerfile`
  - **Stages**:
    - Build stage: Python 3.11, install dependencies, build wheel
    - Runtime stage: distroless python base, copy wheel, install, set entrypoint
  - **Entrypoint**: `mcp-scan` CLI
  - **Size target**: <200MB
  - **AC**: `docker build -t mcp-scanner . && docker run mcp-scanner scan server <server>` works

### 4.3 PyPI Packaging
- [ ] Configure setuptools for PyPI distribution
  - **Modifications to pyproject.toml**:
    - Add classifiers (Programming Language :: Python :: 3.11+, Intended Audience :: Developers, etc.)
    - Add long_description (README.md), long_description_content_type
    - Add keywords for discoverability
    - Add project URLs (bug tracker, documentation, source)
  - **Build config**: uses pyproject.toml (PEP 517/518 compliant)
  - **AC**: `pip install mcp-security-scanner` installs from PyPI; `mcp-scan --version` works

### 4.4 GitHub Action for CI Integration
- [ ] Create reusable GitHub Action
  - **File**: `.github/actions/mcp-scan/action.yml`
  - **Inputs**:
    - `server-stdio-command` (required) — command to start MCP server
    - `config-file` (optional) — path to claude_desktop_config.json
    - `format` (default: sarif) — output format
    - `severity-threshold` (default: medium) — fail if this severity found
  - **Outputs**:
    - `report-path` — path to generated report
    - `critical-count`, `high-count`, `medium-count` — finding counts
    - `passed` — boolean (true if below threshold)
  - **Usage in workflow**:
    ```yaml
    - uses: actions/checkout@v4
    - uses: ./github/actions/mcp-scan
      with:
        server-stdio-command: "python -m my_mcp_server"
        severity-threshold: high
    - uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: ./mcp-scan-report.sarif
    ```
  - **AC**: Action can be called from any GitHub workflow; SARIF uploads to Code Scanning

---

## Phase 5: Documentation & Launch

### 5.1 README.md
- [ ] Write professional GitHub README
  - **Sections**:
    - Title + badges (CI, PyPI version, license, code coverage)
    - One-line description: "Security scanner for MCP servers"
    - **Why this matters?** — 2-3 paragraphs on MCP security gap, supply chain risk
    - **Features** — bullet list (10+ key capabilities)
    - **Quick Start** — install via pip, scan an example server
    - **Architecture** — Mermaid diagram (discovery → analysis → reporting)
    - **OWASP Mapping Table** — 10 categories × detection methods
    - **Examples**:
      - Scanning a single server
      - Scanning from Claude Desktop config
      - GitHub Actions integration
      - Reading reports
    - **Contributing** link to CONTRIBUTING.md
  - **AC**: Renders cleanly on GitHub; code examples are executable

### 5.2 mkdocs Site
- [ ] Set up documentation site with mkdocs
  - **File structure**: `docs/` with mkdocs.yml
  - **Pages**:
    - `index.md` — overview
    - `installation.md` — install options (pip, docker, source)
    - `quickstart.md` — 5-minute guide
    - `usage.md` — detailed CLI reference
    - `architecture.md` — design docs
    - `detections.md` — catalog of all detection rules
    - `api.md` — Python API documentation
    - `contributing.md` — development setup
    - `faq.md` — common questions
  - **Build**: GitHub Pages auto-deploy on push
  - **AC**: Site builds and deploys; links work

### 5.3 CONTRIBUTING.md
- [ ] Write contributor guide
  - **Sections**:
    - Code of conduct (Contributor Covenant)
    - Development setup (python -m venv, pip install -e .[dev])
    - Running tests locally
    - Code style (ruff, black, mypy)
    - Adding new detection rules (template)
    - Submission process (fork, branch, PR)
    - Recognizing contributors
  - **AC**: Clear enough for first-time contributors

### 5.4 Launch Materials
- [ ] Prepare launch content
  - **File**: `docs/launch_post.md`
  - **Content**:
    - "We built the first MCP security scanner" — problem statement
    - Why this matters now (MCP adoption increasing, no auditing tools)
    - What it detects (5 attack types)
    - How it works (4-step process)
    - Use cases (DevOps, AI engineering, security teams)
    - Roadmap for contributors
    - Call to action (test it, report issues, contribute)
  - **Channels**: Hacker News, dev.to, Twitter/X
  - **AC**: Post is compelling and shareable

### 5.5 MCP Community Registration
- [ ] Submit to MCP ecosystem
  - Add to: https://github.com/modelcontextprotocol/community-toolkits
  - Update README link once project has 50+ stars
  - **AC**: Listed in official MCP resources

---

## Success Criteria

By end of Phase 5:
- [ ] Scanner detects all 5 attack types with >90% accuracy on test suite
- [ ] CLI is simple and intuitive (mcp-scan <server> works out of box)
- [ ] Reports are actionable (engineers can understand and fix issues)
- [ ] Code is well-tested (>80% coverage) and documented
- [ ] Anyone can fork, extend, and contribute
- [ ] Available via pip, docker, GitHub Actions
- [ ] Featured in MCP community resources
