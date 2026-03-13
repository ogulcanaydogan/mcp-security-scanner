"""
CLI interface for the MCP Security Scanner.

Provides commands to scan MCP servers, generate reports, and manage baselines.
Uses Click for argument parsing and Rich for formatted output.
"""

import asyncio
import json
import shlex
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import click
from rich.console import Console

import mcp_security_scanner
from mcp_security_scanner.analyzers.base import Finding, Severity
from mcp_security_scanner.analyzers.injection import PromptInjectionAnalyzer
from mcp_security_scanner.analyzers.static import StaticAnalyzer
from mcp_security_scanner.discovery import MCPServerConnector, ServerCapabilities
from mcp_security_scanner.mutation import (
    build_baseline_document,
    build_tool_snapshot,
    compare_tool_snapshots,
    index_tool_snapshots,
    validate_baseline_document,
)
from mcp_security_scanner.reporter import ReportGenerator, ScanReport


@click.group()
@click.version_option(version=mcp_security_scanner.__version__)
def main() -> None:
    """
    MCP Security Scanner — Audit Model Context Protocol servers for vulnerabilities.

    Detects prompt injection, tool poisoning, capability escalation, and rug-pull attacks.
    Maps findings to OWASP LLM Top 10.

    Examples:
        mcp-scan server "python -m my_mcp_server" --format html --output report.html
        mcp-scan config claude_desktop_config.json --format sarif
        mcp-scan baseline "python -m my_mcp_server" --save baseline.json
    """


@main.command()
@click.argument("server_target", type=str)
@click.option(
    "--timeout",
    default=30,
    help="Timeout in seconds for server responses.",
    type=int,
)
@click.option(
    "--format",
    "output_format",
    default="json",
    type=click.Choice(["json", "html", "sarif"]),
    help="Output format for the report.",
)
@click.option(
    "--output",
    "output_path",
    default=None,
    type=click.Path(),
    help="Save report to file (default: stdout).",
)
@click.option(
    "--severity",
    default="all",
    type=click.Choice(["critical", "high", "medium", "low", "info", "all"]),
    help="Only show findings at this severity level or higher.",
)
@click.option(
    "--verbose",
    is_flag=True,
    help="Enable debug output.",
)
def server(
    server_target: str,
    timeout: int,
    output_format: str,
    output_path: str | None,
    severity: str,
    verbose: bool,
) -> None:
    """
    Scan a single MCP server.

    SERVER_TARGET is either:
      - stdio command (e.g., "python -m my_server")
      - SSE URL (e.g., "https://localhost:3000/sse")

    Examples:
        mcp-scan server "python -m my_server"
        mcp-scan server "node server.js" --format html --output report.html
        mcp-scan server "my_server" --severity critical
    """
    console = Console(stderr=True)

    if verbose:
        console.print(f"[debug]Scanning server: {server_target}[/debug]")
        console.print(f"[debug]Timeout: {timeout}s, Format: {output_format}, Severity: {severity}[/debug]")

    threshold = _parse_severity_threshold(severity)

    try:
        report, filtered_findings = asyncio.run(
            _scan_single_server(
                server_target=server_target,
                timeout=timeout,
                threshold=threshold,
            )
        )
    except (ConnectionError, RuntimeError, TimeoutError, ValueError) as exc:
        console.print(f"[red]Scan failed:[/red] {exc}")
        sys.exit(2)

    _write_report(report, output_format, output_path)

    if verbose:
        summary = report.summary
        console.print(
            "Findings after filter: "
            f"critical={summary['critical']} high={summary['high']} medium={summary['medium']} "
            f"low={summary['low']} info={summary['info']}"
        )

    sys.exit(1 if filtered_findings else 0)


@main.command()
@click.argument("config_file", type=click.Path(exists=True))
@click.option(
    "--timeout",
    default=30,
    help="Timeout in seconds for each server response.",
    type=int,
)
@click.option(
    "--format",
    "output_format",
    default="json",
    type=click.Choice(["json", "html", "sarif"]),
    help="Output format for the report.",
)
@click.option(
    "--output",
    "output_path",
    default=None,
    type=click.Path(),
    help="Save report to file (default: stdout).",
)
@click.option(
    "--severity",
    default="all",
    type=click.Choice(["critical", "high", "medium", "low", "info", "all"]),
    help="Only show findings at this severity level or higher.",
)
@click.option(
    "--verbose",
    is_flag=True,
    help="Enable debug output.",
)
def config(
    config_file: str,
    timeout: int,
    output_format: str,
    output_path: str | None,
    severity: str,
    verbose: bool,
) -> None:
    """
    Scan all MCP servers configured in Claude Desktop config.

    CONFIG_FILE is path to claude_desktop_config.json.

    This command reads the config file, discovers all configured MCP servers,
    and scans each one sequentially. An aggregate report is generated.

    Examples:
        mcp-scan config ~/.claude/claude_desktop_config.json
        mcp-scan config claude_desktop_config.json --format html --output report.html
    """
    console = Console(stderr=True)

    if verbose:
        console.print(f"[debug]Config file: {config_file}[/debug]")

    try:
        config_data = json.loads(Path(config_file).read_text(encoding="utf-8"))
        server_entries = _extract_config_server_entries(config_data)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        console.print(f"[red]Config scan failed:[/red] {exc}")
        sys.exit(2)

    threshold = _parse_severity_threshold(severity)

    try:
        findings = asyncio.run(_scan_config_entries(server_entries, timeout=timeout))
    except (ConnectionError, RuntimeError, TimeoutError, ValueError) as exc:
        console.print(f"[red]Config scan failed:[/red] {exc}")
        sys.exit(2)

    filtered_findings = _filter_findings(findings, threshold)
    report = ScanReport(
        scanner_version=mcp_security_scanner.__version__,
        server_name=f"config:{Path(config_file).name}",
        findings=filtered_findings,
    )

    _write_report(report, output_format, output_path)

    if verbose:
        summary = report.summary
        console.print(
            "Findings after filter: "
            f"critical={summary['critical']} high={summary['high']} medium={summary['medium']} "
            f"low={summary['low']} info={summary['info']}"
        )

    sys.exit(1 if filtered_findings else 0)


@main.command()
@click.argument("server_target", type=str)
@click.option(
    "--save",
    "baseline_path",
    required=True,
    type=click.Path(),
    help="Path to save baseline JSON file.",
)
@click.option(
    "--timeout",
    default=30,
    help="Timeout in seconds for server responses.",
    type=int,
)
@click.option(
    "--verbose",
    is_flag=True,
    help="Enable debug output.",
)
def baseline(server_target: str, baseline_path: str, timeout: int, verbose: bool) -> None:
    """
    Create a baseline snapshot of an MCP server's tool schemas.

    Useful for later comparing against to detect tool mutations (rug-pull attacks).

    Examples:
        mcp-scan baseline "python -m my_server" --save baseline.json
        mcp-scan baseline "node server.js" --save server_baseline.json
    """
    console = Console(stderr=True)
    server_name = _derive_server_name(server_target)

    if verbose:
        console.print(f"[debug]Creating baseline for: {server_target}[/debug]")
        console.print(f"[debug]Saving to: {baseline_path}[/debug]")

    connector_config = _build_target_connector_config(server_target, timeout)

    try:
        capabilities = asyncio.run(_discover_capabilities(server_name, connector_config))
        baseline_document = build_baseline_document(
            scanner_version=mcp_security_scanner.__version__,
            server_name=server_name,
            command=server_target,
            tools=capabilities.tools,
        )
        Path(baseline_path).write_text(json.dumps(baseline_document, indent=2, ensure_ascii=False), encoding="utf-8")
    except (ConnectionError, RuntimeError, TimeoutError, ValueError, OSError) as exc:
        console.print(f"[red]Baseline creation failed:[/red] {exc}")
        sys.exit(2)

    if verbose:
        console.print(f"[debug]Baseline saved with {len(capabilities.tools)} tools[/debug]")

    sys.exit(0)


@main.command()
@click.argument("baseline_path", type=click.Path(exists=True))
@click.argument("server_target", type=str)
@click.option(
    "--timeout",
    default=30,
    help="Timeout in seconds for server responses.",
    type=int,
)
@click.option(
    "--format",
    "output_format",
    default="json",
    type=click.Choice(["json", "html", "sarif"]),
    help="Output format for the report.",
)
@click.option(
    "--output",
    "output_path",
    default=None,
    type=click.Path(),
    help="Save report to file (default: stdout).",
)
@click.option(
    "--severity",
    default="all",
    type=click.Choice(["critical", "high", "medium", "low", "info", "all"]),
    help="Only show findings at this severity level or higher.",
)
@click.option(
    "--verbose",
    is_flag=True,
    help="Enable debug output.",
)
def compare(
    baseline_path: str,
    server_target: str,
    timeout: int,
    output_format: str,
    output_path: str | None,
    severity: str,
    verbose: bool,
) -> None:
    """
    Compare current server state against a baseline snapshot.

    Detects tool mutations (descriptions, schemas, removals) indicating rug-pull attacks.

    Examples:
        mcp-scan compare baseline.json "python -m my_server"
        mcp-scan compare baseline.json "node server.js" --format html --output mutations.html
    """
    console = Console(stderr=True)

    if verbose:
        console.print(f"[debug]Baseline: {baseline_path}[/debug]")
        console.print(f"[debug]Server: {server_target}[/debug]")

    threshold = _parse_severity_threshold(severity)
    server_name = _derive_server_name(server_target)

    try:
        baseline_data = json.loads(Path(baseline_path).read_text(encoding="utf-8"))
        baseline_document = validate_baseline_document(baseline_data)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        console.print(f"[red]Compare failed:[/red] {exc}")
        sys.exit(2)

    connector_config = _build_target_connector_config(server_target, timeout)

    try:
        capabilities = asyncio.run(_discover_capabilities(server_name, connector_config))
    except (ConnectionError, RuntimeError, TimeoutError, ValueError) as exc:
        console.print(f"[red]Compare failed:[/red] {exc}")
        sys.exit(2)

    baseline_index = index_tool_snapshots(baseline_document["tools"])
    current_snapshots = [build_tool_snapshot(tool) for tool in capabilities.tools]
    current_index = index_tool_snapshots(current_snapshots)
    mutations = compare_tool_snapshots(baseline_index, current_index)

    findings = [_mutation_to_finding(mutation) for mutation in mutations]
    filtered_findings = _filter_findings(findings, threshold)

    report = ScanReport(
        scanner_version=mcp_security_scanner.__version__,
        server_name=server_name,
        findings=filtered_findings,
    )

    _write_report(report, output_format, output_path)

    if verbose:
        summary = report.summary
        console.print(
            "Findings after filter: "
            f"critical={summary['critical']} high={summary['high']} medium={summary['medium']} "
            f"low={summary['low']} info={summary['info']}"
        )

    sys.exit(1 if filtered_findings else 0)


async def _scan_single_server(
    server_target: str,
    timeout: int,
    threshold: Severity | None,
) -> tuple[ScanReport, list[Finding]]:
    """Run discovery + MVP analyzers against one server target (stdio or sse)."""
    server_name = _derive_server_name(server_target)
    connector_config = _build_target_connector_config(server_target, timeout)

    findings = await _scan_server_findings(server_name, connector_config)
    filtered_findings = _filter_findings(findings, threshold)
    report = ScanReport(
        scanner_version=mcp_security_scanner.__version__,
        server_name=server_name,
        findings=filtered_findings,
    )
    return report, filtered_findings


async def _scan_config_entries(
    server_entries: dict[str, Any],
    timeout: int,
) -> list[Finding]:
    """Scan all entries under mcpServers and return aggregate findings."""
    findings: list[Finding] = []

    for server_name, raw_server_config in server_entries.items():
        connector_config, precheck_finding = _build_connector_config_from_config_entry(
            server_name,
            raw_server_config,
            timeout,
        )

        if precheck_finding is not None:
            findings.append(precheck_finding)
            continue

        assert connector_config is not None

        try:
            findings.extend(await _scan_server_findings(server_name, connector_config))
        except (ConnectionError, RuntimeError, TimeoutError, ValueError) as exc:
            findings.append(_build_scan_failure_finding(server_name, raw_server_config, exc))

    return findings


async def _scan_server_findings(server_name: str, connector_config: dict[str, Any]) -> list[Finding]:
    """Discover capabilities from one server and run MVP analyzers."""
    capabilities = await _discover_capabilities(server_name, connector_config)
    return await _run_mvp_analyzers(capabilities)


async def _discover_capabilities(server_name: str, connector_config: dict[str, Any]) -> ServerCapabilities:
    """Create connector session and retrieve capabilities from one server."""
    connector = MCPServerConnector(server_name=server_name)
    await connector.connect(connector_config)

    try:
        return await connector.get_server_capabilities()
    finally:
        await connector.disconnect()


async def _run_mvp_analyzers(capabilities: ServerCapabilities) -> list[Finding]:
    """Run the MVP analyzer set against discovered capabilities."""
    analyzers = [StaticAnalyzer(), PromptInjectionAnalyzer()]
    findings: list[Finding] = []

    for analyzer in analyzers:
        findings.extend(
            await analyzer.analyze(
                tools=capabilities.tools,
                resources=capabilities.resources,
                prompts=capabilities.prompts,
            )
        )

    return findings


def _build_target_connector_config(server_target: str, timeout: int) -> dict[str, Any]:
    """Build connector config from CLI target (stdio command or sse URL)."""
    target = server_target.strip()
    parsed = urlparse(target)

    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return {
            "type": "sse",
            "url": target,
            "timeout": timeout,
        }

    return {
        "type": "stdio",
        "command": server_target,
        "timeout": timeout,
    }


def _extract_config_server_entries(config_data: Any) -> dict[str, Any]:
    """Extract and validate mcpServers mapping from Claude Desktop config JSON."""
    if not isinstance(config_data, dict):
        raise ValueError("Config JSON must be an object.")

    server_entries = config_data.get("mcpServers")
    if not isinstance(server_entries, dict):
        raise ValueError("Config JSON must include an object field 'mcpServers'.")

    return server_entries


def _build_connector_config_from_config_entry(
    server_name: str,
    raw_server_config: Any,
    timeout: int,
) -> tuple[dict[str, Any] | None, Finding | None]:
    """Normalize one mcpServers entry into connector config or return finding."""
    if not isinstance(raw_server_config, dict):
        return None, _build_config_entry_finding(
            server_name=server_name,
            severity=Severity.HIGH,
            category="invalid_config_entry",
            title=f"Invalid config entry for {server_name}",
            description="Server entry must be a JSON object.",
            raw_server_config=raw_server_config,
            remediation="Ensure each mcpServers entry is an object with command/args fields.",
        )

    transport_value = raw_server_config.get("transport", raw_server_config.get("type", "stdio"))
    if not isinstance(transport_value, str):
        return None, _build_config_entry_finding(
            server_name=server_name,
            severity=Severity.HIGH,
            category="invalid_transport",
            title=f"Invalid transport value for {server_name}",
            description="Transport field must be a string when provided.",
            raw_server_config=raw_server_config,
            remediation="Set transport/type to 'stdio' or 'sse' for supported scanning.",
        )

    transport = transport_value.lower()
    if transport not in {"stdio", "sse"}:
        return None, _build_config_entry_finding(
            server_name=server_name,
            severity=Severity.MEDIUM,
            category="unsupported_transport",
            title=f"Unsupported transport for {server_name}",
            description="Only stdio and sse transports are supported; entry was skipped.",
            raw_server_config=raw_server_config,
            remediation="Use a stdio or sse MCP server entry.",
        )

    if transport == "sse":
        url_value = raw_server_config.get("url")
        if not isinstance(url_value, str) or not url_value.strip():
            return None, _build_config_entry_finding(
                server_name=server_name,
                severity=Severity.HIGH,
                category="invalid_config_entry",
                title=f"Missing url for {server_name}",
                description="sse entries must include a non-empty URL.",
                raw_server_config=raw_server_config,
                remediation="Set a valid http/https URL for sse transport.",
            )

        parsed_url = urlparse(url_value)
        if parsed_url.scheme not in {"http", "https"}:
            return None, _build_config_entry_finding(
                server_name=server_name,
                severity=Severity.HIGH,
                category="invalid_url",
                title=f"Invalid SSE URL for {server_name}",
                description="sse URL must use http or https scheme.",
                raw_server_config=raw_server_config,
                remediation="Use an http:// or https:// URL for sse transport.",
            )

        headers_value = raw_server_config.get("headers")
        headers: dict[str, str] | None = None
        if headers_value is not None:
            if not isinstance(headers_value, dict):
                return None, _build_config_entry_finding(
                    server_name=server_name,
                    severity=Severity.HIGH,
                    category="invalid_headers",
                    title=f"Invalid headers for {server_name}",
                    description="headers must be an object when provided.",
                    raw_server_config=raw_server_config,
                    remediation="Set headers as a key/value JSON object.",
                )
            headers = {str(key): str(value) for key, value in headers_value.items()}

        connector_config: dict[str, Any] = {
            "type": "sse",
            "url": url_value,
            "timeout": timeout,
        }
        if headers is not None:
            connector_config["headers"] = headers

        return connector_config, None

    command = raw_server_config.get("command")
    if not isinstance(command, str) or not command.strip():
        return None, _build_config_entry_finding(
            server_name=server_name,
            severity=Severity.HIGH,
            category="invalid_config_entry",
            title=f"Missing command for {server_name}",
            description="stdio entries must include a non-empty command string.",
            raw_server_config=raw_server_config,
            remediation="Set command and optional args for stdio server launch.",
        )

    composed_command = _compose_stdio_command(command, raw_server_config.get("args"))
    if composed_command is None:
        return None, _build_config_entry_finding(
            server_name=server_name,
            severity=Severity.HIGH,
            category="invalid_args",
            title=f"Invalid args for {server_name}",
            description="args must be an array of CLI arguments when provided.",
            raw_server_config=raw_server_config,
            remediation="Set args as an array of string-like values.",
        )

    env_value = raw_server_config.get("env")
    env: dict[str, str] | None = None
    if env_value is not None:
        if not isinstance(env_value, dict):
            return None, _build_config_entry_finding(
                server_name=server_name,
                severity=Severity.HIGH,
                category="invalid_env",
                title=f"Invalid env for {server_name}",
                description="env must be an object when provided.",
                raw_server_config=raw_server_config,
                remediation="Set env as a key/value JSON object.",
            )
        env = {str(key): str(value) for key, value in env_value.items()}

    connector_config = {
        "type": "stdio",
        "command": composed_command,
        "timeout": timeout,
    }
    if env is not None:
        connector_config["env"] = env

    return connector_config, None


def _compose_stdio_command(command: str, args: Any) -> str | None:
    """Compose a safe shell command from command + args array."""
    if args is None:
        return command

    if not isinstance(args, list):
        return None

    tokens = [command, *[str(item) for item in args]]
    return " ".join(shlex.quote(token) for token in tokens)


def _build_config_entry_finding(
    server_name: str,
    severity: Severity,
    category: str,
    title: str,
    description: str,
    raw_server_config: Any,
    remediation: str,
) -> Finding:
    """Create a standardized finding for config-entry parsing issues."""
    return Finding(
        analyzer_name="config_scanner",
        severity=severity,
        category=category,
        title=title,
        description=description,
        evidence=_safe_json_dump(raw_server_config),
        owasp_id="LLM10",
        remediation=remediation,
        metadata={"server_name": server_name},
    )


def _build_scan_failure_finding(server_name: str, raw_server_config: Any, error: Exception) -> Finding:
    """Create finding for runtime scan failures while processing config entries."""
    transport = "unknown"
    if isinstance(raw_server_config, dict):
        transport_value = raw_server_config.get("transport", raw_server_config.get("type", "stdio"))
        if isinstance(transport_value, str):
            transport = transport_value.lower()

    return Finding(
        analyzer_name="config_scanner",
        severity=Severity.HIGH,
        category="scan_failure",
        title=f"Failed to scan server {server_name}",
        description="Server scan failed and was skipped; this creates an unscanned security gap.",
        evidence=f"transport={transport}; error={error}; config={_safe_json_dump(raw_server_config)}",
        owasp_id="LLM10",
        remediation="Fix server startup/connectivity and rerun config scan.",
        metadata={"server_name": server_name, "transport": transport},
    )


def _mutation_to_finding(mutation: dict[str, Any]) -> Finding:
    """Convert one mutation record into a Finding instance."""
    mutation_type = str(mutation.get("type"))
    tool_name = str(mutation.get("tool_name"))

    baseline = mutation.get("baseline")
    current = mutation.get("current")
    changed_fields = mutation.get("changed_fields", [])

    if mutation_type == "added":
        severity = Severity.MEDIUM
        category = "tool_added"
        title = f"Tool added since baseline: {tool_name}"
        description = "A new tool exists in current server but did not exist in baseline snapshot."
        remediation = "Review and approve new tools before deployment."
    elif mutation_type == "removed":
        severity = Severity.HIGH
        category = "tool_removed"
        title = f"Tool removed since baseline: {tool_name}"
        description = "A baseline tool is missing from current server snapshot."
        remediation = "Verify removal is intentional and update baseline if approved."
    else:
        severity = Severity.HIGH
        category = "tool_changed"
        title = f"Tool changed since baseline: {tool_name}"
        description = "A tool hash changed compared to baseline, indicating potential rug-pull mutation."
        remediation = "Review schema/description diff and re-approve before rollout."

    evidence = _safe_json_dump(
        {
            "mutation_type": mutation_type,
            "tool_name": tool_name,
            "changed_fields": changed_fields,
            "baseline_overall_hash": baseline.get("overall_hash") if isinstance(baseline, dict) else None,
            "current_overall_hash": current.get("overall_hash") if isinstance(current, dict) else None,
        }
    )

    return Finding(
        analyzer_name="baseline_compare",
        severity=severity,
        category=category,
        title=title,
        description=description,
        evidence=evidence,
        owasp_id="LLM05",
        remediation=remediation,
        tool_name=tool_name,
        metadata={"mutation_type": mutation_type},
    )


def _write_report(report: ScanReport, output_format: str, output_path: str | None) -> None:
    """Write report to output file or print to stdout."""
    generator = ReportGenerator()
    if output_path:
        generator.save_report(report, output_path, output_format)
        return

    output = generator.generate(report, output_format)
    click.echo(output)


def _safe_json_dump(value: Any) -> str:
    """Serialize unknown payloads for evidence fields without raising."""
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    except TypeError:
        return repr(value)


def _derive_server_name(command: str) -> str:
    """Derive a compact display name from a command string."""
    stripped = command.strip()
    if not stripped:
        return "mcp-server"

    parsed = urlparse(stripped)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return parsed.netloc

    first_token = stripped.split()[0]
    return Path(first_token).name or "mcp-server"


def _parse_severity_threshold(severity: str) -> Severity | None:
    """Parse CLI severity threshold. Returns None when no filtering is requested."""
    if severity == "all":
        return None
    return Severity(severity)


def _filter_findings(findings: list[Finding], threshold: Severity | None) -> list[Finding]:
    """Filter findings by severity threshold (inclusive)."""
    if threshold is None:
        return findings
    return [finding for finding in findings if finding.severity >= threshold]


if __name__ == "__main__":
    main()
