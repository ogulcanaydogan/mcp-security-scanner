"""CLI tests for server/config/baseline/compare commands."""

import asyncio
import base64
import json
import shlex
import socket
import sys
import threading
import time
import types
from pathlib import Path
from typing import ClassVar
from urllib.parse import parse_qs, urlparse

import pytest
from click.testing import CliRunner

import mcp_security_scanner.cli as cli_module
from mcp_security_scanner.analyzers.base import Finding, Severity
from mcp_security_scanner.cli import (
    URLTargetOptions,
    _build_connector_config_from_config_entry,
    _build_target_connector_configs,
    _compose_stdio_command,
    _derive_server_name,
    _extract_config_server_entries,
    _filter_findings,
    _mutation_to_finding,
    _parse_severity_threshold,
    _safe_json_dump,
    main,
)
from mcp_security_scanner.discovery import ServerCapabilities, ToolDefinition
from mcp_security_scanner.mutation import BASELINE_SCHEMA_VERSION

FIXTURES_DIR = Path(__file__).parent / "fixtures"
MOCK_SERVER = FIXTURES_DIR / "mock_mcp_server.py"
MUTATED_SERVER = FIXTURES_DIR / "mock_mcp_server_mutated.py"


def _script_command(script_path: Path) -> str:
    """Build a shell-safe command to run a fixture with current Python."""
    return f"{shlex.quote(sys.executable)} {shlex.quote(str(script_path))}"


MOCK_SERVER_COMMAND = _script_command(MOCK_SERVER)
MUTATED_SERVER_COMMAND = _script_command(MUTATED_SERVER)
SLEEP_COMMAND = f"{shlex.quote(sys.executable)} -c {shlex.quote('import time; time.sleep(60)')}"


def _cross_tool_test_tools(include_medium_chain: bool = False) -> list[ToolDefinition]:
    """Build deterministic tool sets for cross-tool chain regression tests."""
    tools = [
        ToolDefinition(
            name="env_reader",
            description="Reads environment variable values from runtime context.",
            input_schema={"type": "object"},
        ),
        ToolDefinition(
            name="net_sender",
            description="Performs outbound network call to https://api.example.com/report.",
            input_schema={"type": "object"},
        ),
    ]

    if include_medium_chain:
        tools.extend(
            [
                ToolDefinition(
                    name="file_reader",
                    description="Reads /etc/app.conf file for context.",
                    input_schema={"type": "object"},
                ),
                ToolDefinition(
                    name="command_runner",
                    description="Acts as command runner for maintenance jobs.",
                    input_schema={"type": "object"},
                ),
            ]
        )

    return tools


def _generate_test_rsa_private_key_pem() -> str:
    """Generate an RSA private key PEM for private_key_jwt unit tests."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


class TestCLICommands:
    """CLI integration tests covering Sprint 2 command behavior."""

    @staticmethod
    def _create_baseline(tmp_path: Path, command: str = MOCK_SERVER_COMMAND) -> Path:
        """Create a baseline file and return its path."""
        runner = CliRunner()
        baseline_path = tmp_path / "baseline.json"

        result = runner.invoke(
            main,
            ["baseline", command, "--save", str(baseline_path), "--timeout", "2"],
        )

        assert result.exit_code == 0
        assert baseline_path.exists()
        return baseline_path

    def test_server_json_output_contains_findings(self):
        """`server` command should emit JSON and fail when findings exist."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["server", MOCK_SERVER_COMMAND, "--format", "json", "--timeout", "2"],
        )

        assert result.exit_code == 1
        payload = json.loads(result.output)
        assert payload["metadata"]["server_name"] == _derive_server_name(MOCK_SERVER_COMMAND)
        assert len(payload["findings"]) >= 1

    def test_server_includes_escalation_findings_by_default(self):
        """Default analyzer pipeline should include escalation findings."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["server", MOCK_SERVER_COMMAND, "--format", "json", "--timeout", "2"],
        )

        assert result.exit_code == 1
        payload = json.loads(result.output)
        escalation_findings = [item for item in payload["findings"] if item["category"].startswith("capability_")]
        assert escalation_findings
        assert any(item["metadata"].get("risk_profile") == "privileged" for item in escalation_findings)

    def test_server_includes_tool_poisoning_findings_by_default(self):
        """Default analyzer pipeline should include tool poisoning findings."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["server", MOCK_SERVER_COMMAND, "--format", "json", "--timeout", "2"],
        )

        assert result.exit_code == 1
        payload = json.loads(result.output)
        poisoning_findings = [item for item in payload["findings"] if item["category"].startswith("tool_poisoning_")]
        assert poisoning_findings
        assert any(item["owasp_id"] == "LLM03" for item in poisoning_findings)

    def test_server_includes_cross_tool_findings_by_default(self, monkeypatch):
        """Default analyzer pipeline should include cross-tool chain findings."""

        async def fake_discover(server_name: str, connector_configs: list[dict[str, object]]) -> ServerCapabilities:
            del connector_configs
            return ServerCapabilities(
                server_name=server_name,
                tools=_cross_tool_test_tools(),
                resources=[],
                prompts=[],
            )

        monkeypatch.setattr(cli_module, "_discover_capabilities", fake_discover)

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["server", "python -m fake_server", "--format", "json", "--timeout", "1"],
        )

        assert result.exit_code == 1
        payload = json.loads(result.output)
        categories = {finding["category"] for finding in payload["findings"]}

        assert "cross_tool_secret_exfiltration" in categories
        cross_findings = [item for item in payload["findings"] if item["category"] == "cross_tool_secret_exfiltration"]
        assert cross_findings
        assert all(item["owasp_id"] == "LLM07" for item in cross_findings)

    def test_server_severity_filter_critical_returns_clean_exit(self):
        """Critical threshold should return exit 0 when nothing critical exists."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "server",
                MOCK_SERVER_COMMAND,
                "--format",
                "json",
                "--severity",
                "critical",
                "--timeout",
                "2",
            ],
        )

        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["findings"] == []

    def test_server_writes_report_file(self, tmp_path: Path):
        """`server --output` should write report to file."""
        runner = CliRunner()
        output_path = tmp_path / "scan.json"

        result = runner.invoke(
            main,
            [
                "server",
                MOCK_SERVER_COMMAND,
                "--format",
                "json",
                "--output",
                str(output_path),
                "--timeout",
                "2",
            ],
        )

        assert result.exit_code == 1
        assert output_path.exists()

        payload = json.loads(output_path.read_text(encoding="utf-8"))
        assert "metadata" in payload
        assert "findings" in payload

    def test_server_failure_returns_exit_2(self):
        """Operational server failures should exit with code 2."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["server", SLEEP_COMMAND, "--timeout", "1"],
        )

        assert result.exit_code == 2
        assert "Scan failed" in result.output

    def test_server_url_target_uses_transport_candidates(self, monkeypatch):
        """Server command should route HTTP(S) target to streamable-http then sse."""
        captured: dict[str, object] = {}

        async def fake_discover(server_name: str, connector_configs: list[dict[str, object]]) -> ServerCapabilities:
            captured["server_name"] = server_name
            captured["connector_configs"] = connector_configs
            return ServerCapabilities(
                server_name=server_name,
                tools=[],
                resources=[],
                prompts=[],
            )

        monkeypatch.setattr(cli_module, "_discover_capabilities", fake_discover)

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["server", "https://example.com/sse", "--format", "json", "--timeout", "2"],
        )

        assert result.exit_code == 0
        connector_configs = captured["connector_configs"]
        assert isinstance(connector_configs, list)
        assert [item["type"] for item in connector_configs] == ["streamable-http", "sse"]
        assert all(item["url"] == "https://example.com/sse" for item in connector_configs)

    @pytest.mark.parametrize(
        ("dynamic_args", "expected_dynamic_enabled"),
        [
            ([], False),
            (["--dynamic"], True),
        ],
    )
    def test_server_dynamic_flag_forwarding(self, monkeypatch, dynamic_args: list[str], expected_dynamic_enabled: bool):
        """Server command should forward --dynamic state into scan pipeline."""
        captured: dict[str, object] = {}

        async def fake_scan_single_server(
            server_target: str,
            timeout: int,
            threshold: Severity | None,
            dynamic_enabled: bool = False,
            url_target_options: URLTargetOptions | None = None,
        ) -> tuple[cli_module.ScanReport, list[Finding]]:
            del timeout, threshold
            captured["server_target"] = server_target
            captured["dynamic_enabled"] = dynamic_enabled
            captured["url_target_options"] = url_target_options
            report = cli_module.ScanReport(
                scanner_version="0.1.0",
                server_name=server_target,
                findings=[],
            )
            return report, []

        monkeypatch.setattr(cli_module, "_scan_single_server", fake_scan_single_server)

        runner = CliRunner()
        result = runner.invoke(main, ["server", "python -m fake_server", "--format", "json", *dynamic_args])

        assert result.exit_code == 0
        assert captured["server_target"] == "python -m fake_server"
        assert captured["dynamic_enabled"] is expected_dynamic_enabled
        assert captured["url_target_options"] == URLTargetOptions()

    def test_baseline_url_target_uses_transport_candidates(self, monkeypatch, tmp_path: Path):
        """Baseline command should use streamable-http then sse candidates for URL targets."""
        captured: dict[str, object] = {}

        async def fake_discover(server_name: str, connector_configs: list[dict[str, object]]) -> ServerCapabilities:
            captured["connector_configs"] = connector_configs
            return ServerCapabilities(
                server_name=server_name,
                tools=[],
                resources=[],
                prompts=[],
            )

        monkeypatch.setattr(cli_module, "_discover_capabilities", fake_discover)

        runner = CliRunner()
        baseline_path = tmp_path / "sse-baseline.json"
        result = runner.invoke(
            main,
            ["baseline", "https://example.com/sse", "--save", str(baseline_path), "--timeout", "2"],
        )

        assert result.exit_code == 0
        connector_configs = captured["connector_configs"]
        assert isinstance(connector_configs, list)
        assert [item["type"] for item in connector_configs] == ["streamable-http", "sse"]
        assert all(item["url"] == "https://example.com/sse" for item in connector_configs)

    def test_compare_url_target_uses_transport_candidates(self, monkeypatch, tmp_path: Path):
        """Compare command should route URL target through streamable-http then sse."""
        captured: dict[str, object] = {}

        async def fake_discover(server_name: str, connector_configs: list[dict[str, object]]) -> ServerCapabilities:
            captured["connector_configs"] = connector_configs
            return ServerCapabilities(
                server_name=server_name,
                tools=[],
                resources=[],
                prompts=[],
            )

        monkeypatch.setattr(cli_module, "_discover_capabilities", fake_discover)

        runner = CliRunner()
        baseline_path = tmp_path / "baseline.json"
        baseline_path.write_text(
            json.dumps(
                {
                    "schema_version": BASELINE_SCHEMA_VERSION,
                    "scanner_version": "0.1.0",
                    "created_at": "2026-03-13T00:00:00Z",
                    "server": {"name": "example.com", "command": "https://example.com/sse"},
                    "tools": [],
                }
            ),
            encoding="utf-8",
        )

        result = runner.invoke(
            main,
            ["compare", str(baseline_path), "https://example.com/sse", "--format", "json", "--timeout", "2"],
        )

        assert result.exit_code == 0
        connector_configs = captured["connector_configs"]
        assert isinstance(connector_configs, list)
        assert [item["type"] for item in connector_configs] == ["streamable-http", "sse"]
        assert all(item["url"] == "https://example.com/sse" for item in connector_configs)

    def test_server_url_target_supports_headers_auth_and_transport_mtls(self, monkeypatch, tmp_path: Path):
        """URL server scans should forward headers/auth/mTLS options to both transport candidates."""
        captured: dict[str, object] = {}
        cert_file = tmp_path / "client.crt"
        key_file = tmp_path / "client.key"
        ca_file = tmp_path / "ca.pem"
        cert_file.write_text("cert", encoding="utf-8")
        key_file.write_text("key", encoding="utf-8")
        ca_file.write_text("ca", encoding="utf-8")
        monkeypatch.setenv("URL_API_KEY", "url-key-123")

        async def fake_discover(server_name: str, connector_configs: list[dict[str, object]]) -> ServerCapabilities:
            captured["server_name"] = server_name
            captured["connector_configs"] = connector_configs
            return ServerCapabilities(server_name=server_name, tools=[], resources=[], prompts=[])

        monkeypatch.setattr(cli_module, "_discover_capabilities", fake_discover)

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "server",
                "https://example.com/mcp",
                "--format",
                "json",
                "--timeout",
                "2",
                "--headers-json",
                json.dumps({"X-Trace": 42}),
                "--auth-json",
                json.dumps({"type": "api_key", "key_env": "URL_API_KEY"}),
                "--mtls-cert-file",
                str(cert_file),
                "--mtls-key-file",
                str(key_file),
                "--mtls-ca-bundle-file",
                str(ca_file),
            ],
        )

        assert result.exit_code == 0
        connector_configs = captured["connector_configs"]
        assert isinstance(connector_configs, list)
        assert [item["type"] for item in connector_configs] == ["streamable-http", "sse"]
        for item in connector_configs:
            assert item["url"] == "https://example.com/mcp"
            headers = item.get("headers")
            assert isinstance(headers, dict)
            assert headers["X-Trace"] == "42"
            assert headers["X-API-Key"] == "url-key-123"
            assert item["mtls_cert_file"] == str(cert_file)
            assert item["mtls_key_file"] == str(key_file)
            assert item["mtls_ca_bundle_file"] == str(ca_file)

    def test_baseline_url_target_supports_headers_auth_and_transport_mtls(self, monkeypatch, tmp_path: Path):
        """URL baseline scans should accept auth/mTLS options and pass them to connector candidates."""
        captured: dict[str, object] = {}
        cert_file = tmp_path / "client.crt"
        key_file = tmp_path / "client.key"
        cert_file.write_text("cert", encoding="utf-8")
        key_file.write_text("key", encoding="utf-8")
        monkeypatch.setenv("URL_BEARER_TOKEN", "token-value")

        async def fake_discover(server_name: str, connector_configs: list[dict[str, object]]) -> ServerCapabilities:
            captured["server_name"] = server_name
            captured["connector_configs"] = connector_configs
            return ServerCapabilities(server_name=server_name, tools=[], resources=[], prompts=[])

        monkeypatch.setattr(cli_module, "_discover_capabilities", fake_discover)

        runner = CliRunner()
        baseline_path = tmp_path / "url-baseline.json"
        result = runner.invoke(
            main,
            [
                "baseline",
                "https://example.com/mcp",
                "--save",
                str(baseline_path),
                "--timeout",
                "2",
                "--headers-json",
                json.dumps({"X-Req": "abc"}),
                "--auth-json",
                json.dumps({"type": "bearer", "token_env": "URL_BEARER_TOKEN"}),
                "--mtls-cert-file",
                str(cert_file),
                "--mtls-key-file",
                str(key_file),
            ],
        )

        assert result.exit_code == 0
        assert baseline_path.exists()
        connector_configs = captured["connector_configs"]
        assert isinstance(connector_configs, list)
        assert [item["type"] for item in connector_configs] == ["streamable-http", "sse"]
        for item in connector_configs:
            headers = item.get("headers")
            assert isinstance(headers, dict)
            assert headers["X-Req"] == "abc"
            assert headers["Authorization"] == "Bearer token-value"
            assert item["mtls_cert_file"] == str(cert_file)
            assert item["mtls_key_file"] == str(key_file)

    def test_compare_url_target_supports_headers_auth_and_transport_mtls(self, monkeypatch, tmp_path: Path):
        """URL compare scans should accept auth/mTLS options and pass them to connector candidates."""
        captured: dict[str, object] = {}
        cert_file = tmp_path / "client.crt"
        key_file = tmp_path / "client.key"
        cert_file.write_text("cert", encoding="utf-8")
        key_file.write_text("key", encoding="utf-8")
        monkeypatch.setenv("URL_SESSION_ID", "sess-123")

        async def fake_discover(server_name: str, connector_configs: list[dict[str, object]]) -> ServerCapabilities:
            captured["server_name"] = server_name
            captured["connector_configs"] = connector_configs
            return ServerCapabilities(server_name=server_name, tools=[], resources=[], prompts=[])

        monkeypatch.setattr(cli_module, "_discover_capabilities", fake_discover)

        baseline_path = tmp_path / "baseline.json"
        baseline_path.write_text(
            json.dumps(
                {
                    "schema_version": BASELINE_SCHEMA_VERSION,
                    "scanner_version": "0.1.0",
                    "created_at": "2026-03-13T00:00:00Z",
                    "server": {"name": "example.com", "command": "https://example.com/mcp"},
                    "tools": [],
                }
            ),
            encoding="utf-8",
        )

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "compare",
                str(baseline_path),
                "https://example.com/mcp",
                "--format",
                "json",
                "--timeout",
                "2",
                "--headers-json",
                json.dumps({"Cookie": "existing=1"}),
                "--auth-json",
                json.dumps({"type": "session_cookie", "cookie_env": "URL_SESSION_ID", "cookie_name": "session"}),
                "--mtls-cert-file",
                str(cert_file),
                "--mtls-key-file",
                str(key_file),
            ],
        )

        assert result.exit_code == 0
        connector_configs = captured["connector_configs"]
        assert isinstance(connector_configs, list)
        assert [item["type"] for item in connector_configs] == ["streamable-http", "sse"]
        for item in connector_configs:
            headers = item.get("headers")
            assert isinstance(headers, dict)
            assert headers["Cookie"] == "existing=1; session=sess-123"
            assert item["mtls_cert_file"] == str(cert_file)
            assert item["mtls_key_file"] == str(key_file)

    def test_server_url_target_invalid_json_options_return_exit_2(self):
        """Malformed headers-json/auth-json values should fail URL scans as operational errors."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "server",
                "https://example.com/mcp",
                "--headers-json",
                "{bad-json",
                "--timeout",
                "1",
            ],
        )

        assert result.exit_code == 2
        assert "must be valid JSON" in result.output

    @pytest.mark.parametrize("command_name", ["server", "baseline", "compare"])
    def test_url_options_with_stdio_target_return_exit_2(self, command_name: str, tmp_path: Path):
        """URL auth/mTLS CLI options must be rejected for stdio targets."""
        runner = CliRunner()
        baseline_path = tmp_path / "baseline.json"
        baseline_path.write_text(
            json.dumps(
                {
                    "schema_version": BASELINE_SCHEMA_VERSION,
                    "scanner_version": "0.1.0",
                    "created_at": "2026-03-13T00:00:00Z",
                    "server": {"name": "example.com", "command": "python -m my_server"},
                    "tools": [],
                }
            ),
            encoding="utf-8",
        )

        if command_name == "server":
            args = [command_name, "python -m fake_server", "--headers-json", "{}"]
        elif command_name == "baseline":
            args = [
                command_name,
                "python -m fake_server",
                "--save",
                str(tmp_path / "out-baseline.json"),
                "--headers-json",
                "{}",
            ]
        else:
            args = [
                command_name,
                str(baseline_path),
                "python -m fake_server",
                "--headers-json",
                "{}",
            ]

        result = runner.invoke(main, args)
        assert result.exit_code == 2
        assert "URL auth/mTLS options are only supported" in result.output

    def test_server_url_target_invalid_transport_mtls_returns_exit_2(self, tmp_path: Path):
        """Transport mTLS pair/path validation should fail URL scans as operational errors."""
        runner = CliRunner()
        cert_file = tmp_path / "client.crt"
        cert_file.write_text("cert", encoding="utf-8")
        result = runner.invoke(
            main,
            [
                "server",
                "https://example.com/mcp",
                "--mtls-cert-file",
                str(cert_file),
                "--timeout",
                "1",
            ],
        )

        assert result.exit_code == 2
        assert "must be provided together" in result.output

    def test_server_url_target_auth_resolution_error_returns_exit_2(self):
        """Auth resolution failures in URL options should fail command as operational error."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "server",
                "https://example.com/mcp",
                "--auth-json",
                json.dumps({"type": "bearer", "token_env": "MISSING_URL_TOKEN"}),
                "--timeout",
                "1",
            ],
        )

        assert result.exit_code == 2
        assert "MISSING_URL_TOKEN is missing or empty" in result.output

    def test_server_url_target_failure_after_all_attempts_returns_exit_2(self, monkeypatch):
        """Server URL scans should fail operationally when all transport attempts fail."""
        runner = CliRunner()

        async def failing_discover(server_name: str, connector_configs: list[dict[str, object]]) -> ServerCapabilities:
            del server_name, connector_configs
            raise ConnectionError("all attempts failed")

        monkeypatch.setattr(cli_module, "_discover_capabilities", failing_discover)

        result = runner.invoke(main, ["server", "https://example.com/mcp", "--timeout", "1"])

        assert result.exit_code == 2
        assert "Scan failed" in result.output

    def test_baseline_url_target_failure_after_all_attempts_returns_exit_2(self, monkeypatch, tmp_path: Path):
        """Baseline URL scans should fail operationally when all transport attempts fail."""
        runner = CliRunner()
        baseline_path = tmp_path / "baseline.json"

        async def failing_discover(server_name: str, connector_configs: list[dict[str, object]]) -> ServerCapabilities:
            del server_name, connector_configs
            raise ConnectionError("all attempts failed")

        monkeypatch.setattr(cli_module, "_discover_capabilities", failing_discover)

        result = runner.invoke(
            main,
            ["baseline", "https://example.com/mcp", "--save", str(baseline_path), "--timeout", "1"],
        )

        assert result.exit_code == 2
        assert "Baseline creation failed" in result.output

    def test_compare_url_target_failure_after_all_attempts_returns_exit_2(self, monkeypatch, tmp_path: Path):
        """Compare URL scans should fail operationally when all transport attempts fail."""
        runner = CliRunner()
        baseline_path = tmp_path / "baseline.json"
        baseline_path.write_text(
            json.dumps(
                {
                    "schema_version": BASELINE_SCHEMA_VERSION,
                    "scanner_version": "0.1.0",
                    "created_at": "2026-03-13T00:00:00Z",
                    "server": {"name": "example.com", "command": "https://example.com/mcp"},
                    "tools": [],
                }
            ),
            encoding="utf-8",
        )

        async def failing_discover(server_name: str, connector_configs: list[dict[str, object]]) -> ServerCapabilities:
            del server_name, connector_configs
            raise ConnectionError("all attempts failed")

        monkeypatch.setattr(cli_module, "_discover_capabilities", failing_discover)

        result = runner.invoke(
            main,
            ["compare", str(baseline_path), "https://example.com/mcp", "--timeout", "1"],
        )

        assert result.exit_code == 2
        assert "Compare failed" in result.output

    def test_config_invalid_json_returns_exit_2(self, tmp_path: Path):
        """Invalid config JSON should be treated as operational error."""
        runner = CliRunner()
        config_path = tmp_path / "invalid.json"
        config_path.write_text("{bad", encoding="utf-8")

        result = runner.invoke(main, ["config", str(config_path)])

        assert result.exit_code == 2
        assert "Config scan failed" in result.output

    def test_config_requires_mcp_servers_object(self, tmp_path: Path):
        """Config without `mcpServers` should fail with operational exit code."""
        runner = CliRunner()
        config_path = tmp_path / "config.json"
        config_path.write_text("{}", encoding="utf-8")

        result = runner.invoke(main, ["config", str(config_path)])

        assert result.exit_code == 2
        assert "mcpServers" in result.output

    def test_config_scans_multiple_servers_and_continues_on_errors(self, tmp_path: Path):
        """Config scan should continue after per-server errors and aggregate findings."""
        runner = CliRunner()
        config_path = tmp_path / "claude_desktop_config.json"
        config_path.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "healthy": {
                            "transport": "stdio",
                            "command": sys.executable,
                            "args": [str(MOCK_SERVER)],
                        },
                        "sse_failing": {
                            "transport": "sse",
                            "url": "http://127.0.0.1:1/sse",
                        },
                        "streamable_failing": {
                            "transport": "streamable_http",
                            "url": "http://127.0.0.1:1/mcp",
                        },
                        "invalid_args": {
                            "transport": "stdio",
                            "command": sys.executable,
                            "args": "--bad",
                        },
                        "unsupported": {
                            "transport": "grpc",
                            "url": "grpc://localhost:9000",
                        },
                        "failing": {
                            "transport": "stdio",
                            "command": sys.executable,
                            "args": ["-c", "import time; time.sleep(60)"],
                        },
                    }
                }
            ),
            encoding="utf-8",
        )

        result = runner.invoke(
            main,
            ["config", str(config_path), "--format", "json", "--timeout", "1"],
        )

        assert result.exit_code == 1
        payload = json.loads(result.output)
        categories = {finding["category"] for finding in payload["findings"]}

        assert "unsupported_transport" in categories
        assert "invalid_args" in categories
        assert "scan_failure" in categories
        assert "capability_privileged" in categories
        assert "tool_poisoning_instruction" in categories

        scan_failures = [item for item in payload["findings"] if item["category"] == "scan_failure"]
        assert any(item["metadata"].get("server_name") == "failing" for item in scan_failures)
        assert any(item["metadata"].get("server_name") == "sse_failing" for item in scan_failures)
        assert any(item["metadata"].get("server_name") == "streamable_failing" for item in scan_failures)
        assert any(item["metadata"].get("transport") == "sse" for item in scan_failures)
        assert any(item["metadata"].get("transport") == "streamable-http" for item in scan_failures)

    def test_config_aggregate_includes_cross_tool_findings(self, monkeypatch, tmp_path: Path):
        """Config command should include cross-tool findings in aggregate report."""

        async def fake_discover(server_name: str, connector_configs: list[dict[str, object]]) -> ServerCapabilities:
            del connector_configs
            return ServerCapabilities(
                server_name=server_name,
                tools=_cross_tool_test_tools(),
                resources=[],
                prompts=[],
            )

        monkeypatch.setattr(cli_module, "_discover_capabilities", fake_discover)

        runner = CliRunner()
        config_path = tmp_path / "claude_desktop_config.json"
        config_path.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "chain_server": {
                            "transport": "stdio",
                            "command": "python -m fake_server",
                        }
                    }
                }
            ),
            encoding="utf-8",
        )

        result = runner.invoke(
            main,
            ["config", str(config_path), "--format", "json", "--timeout", "1"],
        )

        assert result.exit_code == 1
        payload = json.loads(result.output)
        categories = {finding["category"] for finding in payload["findings"]}
        assert "cross_tool_secret_exfiltration" in categories

    def test_config_dynamic_flag_forwarding_and_output(self, monkeypatch, tmp_path: Path):
        """Config command should forward --dynamic and include resulting dynamic findings."""
        captured: dict[str, object] = {}

        async def fake_scan_entries(
            server_entries: dict[str, object],
            timeout: int,
            dynamic_enabled: bool = False,
        ) -> list[Finding]:
            del server_entries, timeout
            captured["dynamic_enabled"] = dynamic_enabled
            return [
                Finding(
                    analyzer_name="dynamic_analyzer",
                    severity=Severity.HIGH,
                    category="dynamic_sensitive_output",
                    title="Dynamic sensitive output",
                    description="Dynamic probe observed sensitive output markers.",
                    evidence="-----BEGIN PRIVATE KEY-----",
                    owasp_id="LLM06",
                    remediation="Sanitize dynamic output.",
                    tool_name="dynamic_tool",
                )
            ]

        monkeypatch.setattr(cli_module, "_scan_config_entries", fake_scan_entries)

        runner = CliRunner()
        config_path = tmp_path / "claude_desktop_config.json"
        config_path.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "dynamic_server": {
                            "transport": "stdio",
                            "command": "python -m fake_server",
                        }
                    }
                }
            ),
            encoding="utf-8",
        )

        result = runner.invoke(
            main,
            ["config", str(config_path), "--format", "json", "--timeout", "1", "--dynamic"],
        )

        assert result.exit_code == 1
        assert captured["dynamic_enabled"] is True
        payload = json.loads(result.output)
        categories = {finding["category"] for finding in payload["findings"]}
        assert "dynamic_sensitive_output" in categories

    def test_config_dynamic_disabled_by_default(self, monkeypatch, tmp_path: Path):
        """Config command should keep dynamic analyzer disabled unless --dynamic is passed."""
        captured: dict[str, object] = {}

        async def fake_scan_entries(
            server_entries: dict[str, object],
            timeout: int,
            dynamic_enabled: bool = False,
        ) -> list[Finding]:
            del server_entries, timeout
            captured["dynamic_enabled"] = dynamic_enabled
            return []

        monkeypatch.setattr(cli_module, "_scan_config_entries", fake_scan_entries)

        runner = CliRunner()
        config_path = tmp_path / "claude_desktop_config.json"
        config_path.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "dynamic_server": {
                            "transport": "stdio",
                            "command": "python -m fake_server",
                        }
                    }
                }
            ),
            encoding="utf-8",
        )

        result = runner.invoke(
            main,
            ["config", str(config_path), "--format", "json", "--timeout", "1"],
        )

        assert result.exit_code == 0
        assert captured["dynamic_enabled"] is False

    def test_config_auth_error_emits_finding_and_continues(self, monkeypatch, tmp_path: Path):
        """Auth resolution failures should produce finding and continue scanning other servers."""
        captured: list[dict[str, object]] = []

        async def fake_discover(server_name: str, connector_configs: list[dict[str, object]]) -> ServerCapabilities:
            captured.append(
                {
                    "server_name": server_name,
                    "connector_config": connector_configs[0],
                }
            )
            return ServerCapabilities(server_name=server_name, tools=[], resources=[], prompts=[])

        monkeypatch.setattr(cli_module, "_discover_capabilities", fake_discover)
        monkeypatch.setenv("GOOD_API_KEY", "api-key-123")
        monkeypatch.delenv("MISSING_BEARER_TOKEN", raising=False)

        runner = CliRunner()
        config_path = tmp_path / "claude_desktop_config.json"
        config_path.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "auth_bad": {
                            "transport": "sse",
                            "url": "https://example.com/bad",
                            "auth": {"type": "bearer", "token_env": "MISSING_BEARER_TOKEN"},
                        },
                        "auth_good": {
                            "transport": "streamable-http",
                            "url": "https://example.com/good",
                            "headers": {"X-Trace": 7},
                            "auth": {"type": "api_key", "key_env": "GOOD_API_KEY"},
                        },
                    }
                }
            ),
            encoding="utf-8",
        )

        result = runner.invoke(
            main,
            ["config", str(config_path), "--format", "json", "--timeout", "1"],
        )

        assert result.exit_code == 1
        payload = json.loads(result.output)
        categories = {finding["category"] for finding in payload["findings"]}
        assert "auth_config_error" in categories

        auth_errors = [item for item in payload["findings"] if item["category"] == "auth_config_error"]
        assert any(item["metadata"].get("server_name") == "auth_bad" for item in auth_errors)
        assert any(item["metadata"].get("transport") == "sse" for item in auth_errors)
        assert any(item["metadata"].get("auth_type") == "bearer" for item in auth_errors)
        assert any(item["metadata"].get("env_var") == "MISSING_BEARER_TOKEN" for item in auth_errors)

        assert len(captured) == 1
        assert captured[0]["server_name"] == "auth_good"
        connector_config = captured[0]["connector_config"]
        assert isinstance(connector_config, dict)
        assert connector_config["type"] == "streamable-http"
        headers = connector_config.get("headers")
        assert isinstance(headers, dict)
        assert headers["X-Trace"] == "7"
        assert headers["X-API-Key"] == "api-key-123"

    def test_config_oauth_auth_generates_headers_and_uses_cache(self, monkeypatch, tmp_path: Path):
        """OAuth auth should inject Authorization header and reuse token per command run."""
        captured: list[dict[str, object]] = []
        cli_module._clear_oauth_token_cache()

        async def fake_discover(server_name: str, connector_configs: list[dict[str, object]]) -> ServerCapabilities:
            captured.append(
                {
                    "server_name": server_name,
                    "connector_config": connector_configs[0],
                }
            )
            return ServerCapabilities(server_name=server_name, tools=[], resources=[], prompts=[])

        monkeypatch.setattr(cli_module, "_discover_capabilities", fake_discover)
        monkeypatch.setenv("OAUTH_CLIENT_ID", "client-app")
        monkeypatch.setenv("OAUTH_CLIENT_SECRET", "secret-app")

        token_calls = {"value": 0}

        def fake_request(
            *,
            token_url: str,
            client_id: str,
            client_secret: str,
            scope: str | None,
            audience: str | None,
            token_endpoint_auth_method: str,
            timeout_seconds: int,
        ) -> tuple[str | None, float | None, str | None, int | None]:
            token_calls["value"] += 1
            assert token_url == "https://auth.example.com/token"
            assert client_id == "client-app"
            assert client_secret == "secret-app"
            assert scope == "mcp.read"
            assert audience == "scanner"
            assert token_endpoint_auth_method == "client_secret_post"
            assert timeout_seconds == 4
            return "oauth-shared-token", 3600.0, None, 200

        monkeypatch.setattr(cli_module, "_request_oauth_client_credentials_token", fake_request)

        runner = CliRunner()
        config_path = tmp_path / "claude_desktop_config.json"
        config_path.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "oauth_sse": {
                            "transport": "sse",
                            "url": "https://example.com/sse",
                            "headers": {"X-Trace": "1"},
                            "auth": {
                                "type": "oauth_client_credentials",
                                "token_url": "https://auth.example.com/token",
                                "client_id_env": "OAUTH_CLIENT_ID",
                                "client_secret_env": "OAUTH_CLIENT_SECRET",
                                "scope": "mcp.read",
                                "audience": "scanner",
                            },
                        },
                        "oauth_streamable": {
                            "transport": "streamable-http",
                            "url": "https://example.com/mcp",
                            "auth": {
                                "type": "oauth_client_credentials",
                                "token_url": "https://auth.example.com/token",
                                "client_id_env": "OAUTH_CLIENT_ID",
                                "client_secret_env": "OAUTH_CLIENT_SECRET",
                                "scope": "mcp.read",
                                "audience": "scanner",
                            },
                        },
                    }
                }
            ),
            encoding="utf-8",
        )

        result = runner.invoke(
            main,
            ["config", str(config_path), "--format", "json", "--timeout", "4"],
        )

        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["findings"] == []
        assert token_calls["value"] == 1
        assert len(captured) == 2

        for item in captured:
            connector_config = item["connector_config"]
            assert isinstance(connector_config, dict)
            headers = connector_config.get("headers")
            assert isinstance(headers, dict)
            assert headers["Authorization"] == "Bearer oauth-shared-token"
        sse_headers = captured[0]["connector_config"]["headers"]
        assert isinstance(sse_headers, dict)
        assert sse_headers["X-Trace"] == "1"

    def test_config_oauth_persistent_cache_reuses_token_across_runs(self, monkeypatch, tmp_path: Path):
        """Persistent cache should reuse token between separate config command runs."""
        captured: list[dict[str, object]] = []

        async def fake_discover(server_name: str, connector_configs: list[dict[str, object]]) -> ServerCapabilities:
            captured.append(
                {
                    "server_name": server_name,
                    "connector_config": connector_configs[0],
                }
            )
            return ServerCapabilities(server_name=server_name, tools=[], resources=[], prompts=[])

        monkeypatch.setattr(cli_module, "_discover_capabilities", fake_discover)
        monkeypatch.setattr(cli_module, "_OAUTH_PERSISTENT_CACHE_FILE", tmp_path / "oauth-cache-v1.json.enc")
        monkeypatch.setattr(cli_module, "_OAUTH_PERSISTENT_KEY_FILE", tmp_path / "cache.key")
        monkeypatch.setattr(cli_module, "_read_oauth_cache_key_from_keyring", lambda: None)
        monkeypatch.setenv("OAUTH_CLIENT_ID", "client-app")
        monkeypatch.setenv("OAUTH_CLIENT_SECRET", "secret-app")

        token_calls = {"value": 0}

        def fake_request(
            *,
            token_url: str,
            client_id: str,
            client_secret: str,
            scope: str | None,
            audience: str | None,
            token_endpoint_auth_method: str,
            timeout_seconds: int,
        ) -> tuple[str | None, float | None, str | None, int | None]:
            token_calls["value"] += 1
            assert token_url == "https://auth.example.com/token"
            assert client_id == "client-app"
            assert client_secret == "secret-app"
            assert scope == "mcp.read"
            assert audience == "scanner"
            assert token_endpoint_auth_method == "client_secret_post"
            assert timeout_seconds == 4
            return "oauth-persistent-token", 3600.0, None, 200

        monkeypatch.setattr(cli_module, "_request_oauth_client_credentials_token", fake_request)

        runner = CliRunner()
        config_path = tmp_path / "claude_desktop_config.json"
        config_path.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "oauth_sse": {
                            "transport": "sse",
                            "url": "https://example.com/sse",
                            "auth": {
                                "type": "oauth_client_credentials",
                                "token_url": "https://auth.example.com/token",
                                "client_id_env": "OAUTH_CLIENT_ID",
                                "client_secret_env": "OAUTH_CLIENT_SECRET",
                                "scope": "mcp.read",
                                "audience": "scanner",
                                "cache": {"persistent": True, "namespace": "team-a"},
                            },
                        }
                    }
                }
            ),
            encoding="utf-8",
        )

        first_result = runner.invoke(
            main,
            ["config", str(config_path), "--format", "json", "--timeout", "4"],
        )
        second_result = runner.invoke(
            main,
            ["config", str(config_path), "--format", "json", "--timeout", "4"],
        )

        assert first_result.exit_code == 0
        assert second_result.exit_code == 0
        assert token_calls["value"] == 1
        assert len(captured) == 2
        for item in captured:
            connector_config = item["connector_config"]
            assert isinstance(connector_config, dict)
            headers = connector_config.get("headers")
            assert isinstance(headers, dict)
            assert headers["Authorization"] == "Bearer oauth-persistent-token"

    def test_config_oauth_persistent_cache_corrupt_file_bypasses(self, monkeypatch, tmp_path: Path):
        """Corrupt persistent cache should be ignored and fall back to live token request."""
        captured: list[dict[str, object]] = []

        async def fake_discover(server_name: str, connector_configs: list[dict[str, object]]) -> ServerCapabilities:
            captured.append(
                {
                    "server_name": server_name,
                    "connector_config": connector_configs[0],
                }
            )
            return ServerCapabilities(server_name=server_name, tools=[], resources=[], prompts=[])

        persistent_cache_file = tmp_path / "oauth-cache-v1.json.enc"
        persistent_cache_file.write_bytes(b"not-a-valid-cache")
        monkeypatch.setattr(cli_module, "_discover_capabilities", fake_discover)
        monkeypatch.setattr(cli_module, "_OAUTH_PERSISTENT_CACHE_FILE", persistent_cache_file)
        monkeypatch.setattr(cli_module, "_OAUTH_PERSISTENT_KEY_FILE", tmp_path / "cache.key")
        monkeypatch.setattr(cli_module, "_read_oauth_cache_key_from_keyring", lambda: None)
        monkeypatch.setenv("OAUTH_CLIENT_ID", "client-app")
        monkeypatch.setenv("OAUTH_CLIENT_SECRET", "secret-app")

        token_calls = {"value": 0}

        def fake_request(
            *,
            token_url: str,
            client_id: str,
            client_secret: str,
            scope: str | None,
            audience: str | None,
            token_endpoint_auth_method: str,
            timeout_seconds: int,
        ) -> tuple[str | None, float | None, str | None, int | None]:
            token_calls["value"] += 1
            del token_url, client_id, client_secret, scope, audience, token_endpoint_auth_method, timeout_seconds
            return "live-token", 3600.0, None, 200

        monkeypatch.setattr(cli_module, "_request_oauth_client_credentials_token", fake_request)

        runner = CliRunner()
        config_path = tmp_path / "claude_desktop_config.json"
        config_path.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "oauth_sse": {
                            "transport": "sse",
                            "url": "https://example.com/sse",
                            "auth": {
                                "type": "oauth_client_credentials",
                                "token_url": "https://auth.example.com/token",
                                "client_id_env": "OAUTH_CLIENT_ID",
                                "client_secret_env": "OAUTH_CLIENT_SECRET",
                                "cache": {"persistent": True},
                            },
                        }
                    }
                }
            ),
            encoding="utf-8",
        )

        result = runner.invoke(
            main,
            ["config", str(config_path), "--format", "json", "--timeout", "4"],
        )

        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["findings"] == []
        assert token_calls["value"] == 1
        assert len(captured) == 1
        quarantine_files = sorted(tmp_path.glob("oauth-cache-v1.json.enc.corrupt.*"))
        assert quarantine_files

    def test_config_oauth_token_error_emits_finding_and_continues(self, monkeypatch, tmp_path: Path):
        """OAuth token failures should emit auth_token_error and continue with other servers."""
        captured: list[dict[str, object]] = []
        cli_module._clear_oauth_token_cache()

        async def fake_discover(server_name: str, connector_configs: list[dict[str, object]]) -> ServerCapabilities:
            captured.append(
                {
                    "server_name": server_name,
                    "connector_config": connector_configs[0],
                }
            )
            return ServerCapabilities(server_name=server_name, tools=[], resources=[], prompts=[])

        monkeypatch.setattr(cli_module, "_discover_capabilities", fake_discover)
        monkeypatch.setenv("OAUTH_CLIENT_ID", "client-app")
        monkeypatch.setenv("OAUTH_CLIENT_SECRET", "secret-app")
        monkeypatch.setenv("GOOD_API_KEY", "api-key-123")

        def fake_request(
            *,
            token_url: str,
            client_id: str,
            client_secret: str,
            scope: str | None,
            audience: str | None,
            token_endpoint_auth_method: str,
            timeout_seconds: int,
        ) -> tuple[str | None, float | None, str | None, int | None]:
            del token_url, client_id, client_secret, scope, audience, token_endpoint_auth_method, timeout_seconds
            return None, None, "Token endpoint returned HTTP 401.", 401

        monkeypatch.setattr(cli_module, "_request_oauth_client_credentials_token", fake_request)

        runner = CliRunner()
        config_path = tmp_path / "claude_desktop_config.json"
        config_path.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "oauth_bad": {
                            "transport": "sse",
                            "url": "https://example.com/sse",
                            "auth": {
                                "type": "oauth_client_credentials",
                                "token_url": "https://auth.example.com/token",
                                "client_id_env": "OAUTH_CLIENT_ID",
                                "client_secret_env": "OAUTH_CLIENT_SECRET",
                            },
                        },
                        "api_key_good": {
                            "transport": "streamable-http",
                            "url": "https://example.com/mcp",
                            "auth": {"type": "api_key", "key_env": "GOOD_API_KEY"},
                        },
                    }
                }
            ),
            encoding="utf-8",
        )

        result = runner.invoke(
            main,
            ["config", str(config_path), "--format", "json", "--timeout", "2"],
        )

        assert result.exit_code == 1
        payload = json.loads(result.output)
        categories = {finding["category"] for finding in payload["findings"]}
        assert "auth_token_error" in categories

        token_errors = [item for item in payload["findings"] if item["category"] == "auth_token_error"]
        assert any(item["metadata"].get("server_name") == "oauth_bad" for item in token_errors)
        assert any(item["metadata"].get("transport") == "sse" for item in token_errors)
        assert any(item["metadata"].get("auth_type") == "oauth_client_credentials" for item in token_errors)
        assert any(item["metadata"].get("token_url") == "https://auth.example.com/token" for item in token_errors)
        assert any(item["metadata"].get("http_status") == 401 for item in token_errors)

        assert len(captured) == 1
        assert captured[0]["server_name"] == "api_key_good"
        connector_config = captured[0]["connector_config"]
        assert isinstance(connector_config, dict)
        headers = connector_config.get("headers")
        assert isinstance(headers, dict)
        assert headers["X-API-Key"] == "api-key-123"

    def test_config_oauth_device_code_success_and_cache(self, monkeypatch, tmp_path: Path):
        """Device-code auth should emit Authorization header and reuse cached token."""
        captured: list[dict[str, object]] = []
        cli_module._clear_oauth_token_cache()

        async def fake_discover(server_name: str, connector_configs: list[dict[str, object]]) -> ServerCapabilities:
            captured.append(
                {
                    "server_name": server_name,
                    "connector_config": connector_configs[0],
                }
            )
            return ServerCapabilities(server_name=server_name, tools=[], resources=[], prompts=[])

        monkeypatch.setattr(cli_module, "_discover_capabilities", fake_discover)
        monkeypatch.setattr(cli_module, "_is_interactive_tty", lambda: True)
        monkeypatch.setattr(
            cli_module,
            "_emit_oauth_device_code_instructions",
            lambda server_name, verification_uri, verification_uri_complete, user_code: None,
        )
        monkeypatch.setenv("OAUTH_DEVICE_CLIENT_ID", "device-client")

        device_calls = {"value": 0}
        poll_calls = {"value": 0}

        def fake_device_authorization(
            *,
            device_authorization_url: str,
            client_id: str,
            client_secret: str | None,
            scope: str | None,
            audience: str | None,
            timeout_seconds: int,
        ) -> tuple[dict[str, object] | None, str | None, int | None]:
            device_calls["value"] += 1
            assert device_authorization_url == "https://auth.example.com/device"
            assert client_id == "device-client"
            assert client_secret is None
            assert scope == "mcp.read"
            assert audience == "scanner"
            assert timeout_seconds == 4
            return (
                {
                    "device_code": "device-code-123",
                    "verification_uri": "https://auth.example.com/verify",
                    "user_code": "ABCD-1234",
                    "interval": 2,
                    "expires_in": 120,
                },
                None,
                200,
            )

        def fake_poll(
            *,
            token_url: str,
            device_code: str,
            client_id: str,
            client_secret: str | None,
            token_endpoint_auth_method: str,
            timeout_seconds: int,
            poll_interval_seconds: int,
            device_expires_in: float | None,
        ) -> tuple[str | None, float | None, str | None, str | None, int | None]:
            poll_calls["value"] += 1
            assert token_url == "https://auth.example.com/token"
            assert device_code == "device-code-123"
            assert client_id == "device-client"
            assert client_secret is None
            assert token_endpoint_auth_method == "client_secret_post"
            assert timeout_seconds == 4
            assert poll_interval_seconds == 2
            assert device_expires_in == 120.0
            return "device-access-token", 3600.0, "refresh-token-1", None, 200

        monkeypatch.setattr(cli_module, "_request_oauth_device_authorization", fake_device_authorization)
        monkeypatch.setattr(cli_module, "_poll_oauth_device_code_token", fake_poll)

        runner = CliRunner()
        config_path = tmp_path / "claude_desktop_config.json"
        config_path.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "device_one": {
                            "transport": "sse",
                            "url": "https://example.com/sse",
                            "headers": {"X-Trace": "1"},
                            "auth": {
                                "type": "oauth_device_code",
                                "device_authorization_url": "https://auth.example.com/device",
                                "token_url": "https://auth.example.com/token",
                                "client_id_env": "OAUTH_DEVICE_CLIENT_ID",
                                "scope": "mcp.read",
                                "audience": "scanner",
                            },
                        },
                        "device_two": {
                            "transport": "streamable-http",
                            "url": "https://example.com/mcp",
                            "auth": {
                                "type": "oauth_device_code",
                                "device_authorization_url": "https://auth.example.com/device",
                                "token_url": "https://auth.example.com/token",
                                "client_id_env": "OAUTH_DEVICE_CLIENT_ID",
                                "scope": "mcp.read",
                                "audience": "scanner",
                            },
                        },
                    }
                }
            ),
            encoding="utf-8",
        )

        result = runner.invoke(
            main,
            ["config", str(config_path), "--format", "json", "--timeout", "4"],
        )

        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["findings"] == []
        assert device_calls["value"] == 1
        assert poll_calls["value"] == 1
        assert len(captured) == 2

        for item in captured:
            connector_config = item["connector_config"]
            assert isinstance(connector_config, dict)
            headers = connector_config.get("headers")
            assert isinstance(headers, dict)
            assert headers["Authorization"] == "Bearer device-access-token"
        first_headers = captured[0]["connector_config"]["headers"]
        assert isinstance(first_headers, dict)
        assert first_headers["X-Trace"] == "1"

    def test_config_oauth_device_code_headless_emits_finding_and_continues(self, monkeypatch, tmp_path: Path):
        """Headless device-code auth should emit auth_token_error and continue scanning."""
        captured: list[dict[str, object]] = []
        cli_module._clear_oauth_token_cache()

        async def fake_discover(server_name: str, connector_configs: list[dict[str, object]]) -> ServerCapabilities:
            captured.append(
                {
                    "server_name": server_name,
                    "connector_config": connector_configs[0],
                }
            )
            return ServerCapabilities(server_name=server_name, tools=[], resources=[], prompts=[])

        monkeypatch.setattr(cli_module, "_discover_capabilities", fake_discover)
        monkeypatch.setattr(cli_module, "_is_interactive_tty", lambda: False)
        monkeypatch.setenv("OAUTH_DEVICE_CLIENT_ID", "device-client")
        monkeypatch.setenv("GOOD_API_KEY", "api-key-123")

        runner = CliRunner()
        config_path = tmp_path / "claude_desktop_config.json"
        config_path.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "device_headless": {
                            "transport": "sse",
                            "url": "https://example.com/sse",
                            "auth": {
                                "type": "oauth_device_code",
                                "device_authorization_url": "https://auth.example.com/device",
                                "token_url": "https://auth.example.com/token",
                                "client_id_env": "OAUTH_DEVICE_CLIENT_ID",
                            },
                        },
                        "api_key_good": {
                            "transport": "streamable-http",
                            "url": "https://example.com/mcp",
                            "auth": {"type": "api_key", "key_env": "GOOD_API_KEY"},
                        },
                    }
                }
            ),
            encoding="utf-8",
        )

        result = runner.invoke(
            main,
            ["config", str(config_path), "--format", "json", "--timeout", "2"],
        )

        assert result.exit_code == 1
        payload = json.loads(result.output)
        categories = {finding["category"] for finding in payload["findings"]}
        assert "auth_token_error" in categories

        token_errors = [item for item in payload["findings"] if item["category"] == "auth_token_error"]
        assert any(item["metadata"].get("server_name") == "device_headless" for item in token_errors)
        assert any(item["metadata"].get("auth_type") == "oauth_device_code" for item in token_errors)
        assert any(item["metadata"].get("transport") == "sse" for item in token_errors)

        assert len(captured) == 1
        assert captured[0]["server_name"] == "api_key_good"

    def test_config_oauth_auth_code_pkce_success_and_cache(self, monkeypatch, tmp_path: Path):
        """Auth-code PKCE should reuse cache and inject Authorization header."""
        captured: list[dict[str, object]] = []
        cli_module._clear_oauth_token_cache()

        async def fake_discover(server_name: str, connector_configs: list[dict[str, object]]) -> ServerCapabilities:
            captured.append(
                {
                    "server_name": server_name,
                    "connector_config": connector_configs[0],
                }
            )
            return ServerCapabilities(server_name=server_name, tools=[], resources=[], prompts=[])

        monkeypatch.setattr(cli_module, "_discover_capabilities", fake_discover)
        monkeypatch.setattr(cli_module, "_is_interactive_tty", lambda: True)
        monkeypatch.setenv("AUTH_CODE_CLIENT_ID", "client-auth-code")
        monkeypatch.setattr(cli_module, "_generate_pkce_code_verifier", lambda: "verifier-fixed")
        monkeypatch.setattr(cli_module, "_generate_oauth_state", lambda: "state-fixed")

        flow_calls = {"value": 0}
        token_calls = {"value": 0}

        def fake_auth_code_flow(
            *,
            server_name: str,
            authorization_url: str,
            client_id: str,
            scope: str | None,
            audience: str | None,
            redirect_host: str,
            redirect_port: int,
            callback_path: str,
            code_challenge: str,
            expected_state: str,
            timeout_seconds: int,
        ) -> tuple[str | None, str | None, str | None, str | None]:
            flow_calls["value"] += 1
            assert authorization_url == "https://auth.example.com/authorize"
            assert client_id == "client-auth-code"
            assert scope == "mcp.read"
            assert audience == "scanner"
            assert redirect_host == "127.0.0.1"
            assert redirect_port == 8765
            assert callback_path == "/callback"
            assert code_challenge
            assert expected_state == "state-fixed"
            assert timeout_seconds == 5
            return "auth-code-1", "state-fixed", "http://127.0.0.1:8765/callback", None

        def fake_auth_code_token(
            *,
            token_url: str,
            auth_code: str,
            redirect_uri: str,
            client_id: str,
            code_verifier: str,
            scope: str | None,
            audience: str | None,
            timeout_seconds: int,
        ) -> tuple[str | None, float | None, str | None, str | None, int | None]:
            token_calls["value"] += 1
            assert token_url == "https://auth.example.com/token"
            assert auth_code == "auth-code-1"
            assert redirect_uri == "http://127.0.0.1:8765/callback"
            assert client_id == "client-auth-code"
            assert code_verifier == "verifier-fixed"
            assert scope == "mcp.read"
            assert audience == "scanner"
            assert timeout_seconds == 5
            return "access-auth-code", 3600.0, "refresh-auth-code", None, 200

        monkeypatch.setattr(cli_module, "_run_oauth_auth_code_pkce_flow", fake_auth_code_flow)
        monkeypatch.setattr(cli_module, "_request_oauth_auth_code_token", fake_auth_code_token)

        runner = CliRunner()
        config_path = tmp_path / "claude_desktop_config.json"
        config_path.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "auth_code_one": {
                            "transport": "sse",
                            "url": "https://example.com/sse",
                            "headers": {"X-Trace": "1"},
                            "auth": {
                                "type": "oauth_auth_code_pkce",
                                "authorization_url": "https://auth.example.com/authorize",
                                "token_url": "https://auth.example.com/token",
                                "client_id_env": "AUTH_CODE_CLIENT_ID",
                                "scope": "mcp.read",
                                "audience": "scanner",
                            },
                        },
                        "auth_code_two": {
                            "transport": "streamable-http",
                            "url": "https://example.com/mcp",
                            "auth": {
                                "type": "oauth_auth_code_pkce",
                                "authorization_url": "https://auth.example.com/authorize",
                                "token_url": "https://auth.example.com/token",
                                "client_id_env": "AUTH_CODE_CLIENT_ID",
                                "scope": "mcp.read",
                                "audience": "scanner",
                            },
                        },
                    }
                }
            ),
            encoding="utf-8",
        )

        result = runner.invoke(
            main,
            ["config", str(config_path), "--format", "json", "--timeout", "5"],
        )

        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["findings"] == []
        assert flow_calls["value"] == 1
        assert token_calls["value"] == 1
        assert len(captured) == 2
        for item in captured:
            headers = item["connector_config"]["headers"]
            assert isinstance(headers, dict)
            assert headers["Authorization"] == "Bearer access-auth-code"

    def test_config_oauth_auth_code_pkce_headless_emits_finding_and_continues(self, monkeypatch, tmp_path: Path):
        """Headless auth-code PKCE should emit auth_token_error and continue scanning."""
        captured: list[dict[str, object]] = []
        cli_module._clear_oauth_token_cache()

        async def fake_discover(server_name: str, connector_configs: list[dict[str, object]]) -> ServerCapabilities:
            captured.append(
                {
                    "server_name": server_name,
                    "connector_config": connector_configs[0],
                }
            )
            return ServerCapabilities(server_name=server_name, tools=[], resources=[], prompts=[])

        monkeypatch.setattr(cli_module, "_discover_capabilities", fake_discover)
        monkeypatch.setattr(cli_module, "_is_interactive_tty", lambda: False)
        monkeypatch.setenv("AUTH_CODE_CLIENT_ID", "client-auth-code")
        monkeypatch.setenv("GOOD_API_KEY", "api-key-123")

        runner = CliRunner()
        config_path = tmp_path / "claude_desktop_config.json"
        config_path.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "auth_code_headless": {
                            "transport": "sse",
                            "url": "https://example.com/sse",
                            "auth": {
                                "type": "oauth_auth_code_pkce",
                                "authorization_url": "https://auth.example.com/authorize",
                                "token_url": "https://auth.example.com/token",
                                "client_id_env": "AUTH_CODE_CLIENT_ID",
                            },
                        },
                        "api_key_good": {
                            "transport": "streamable-http",
                            "url": "https://example.com/mcp",
                            "auth": {"type": "api_key", "key_env": "GOOD_API_KEY"},
                        },
                    }
                }
            ),
            encoding="utf-8",
        )

        result = runner.invoke(
            main,
            ["config", str(config_path), "--format", "json", "--timeout", "2"],
        )

        assert result.exit_code == 1
        payload = json.loads(result.output)
        categories = {finding["category"] for finding in payload["findings"]}
        assert "auth_token_error" in categories
        token_errors = [item for item in payload["findings"] if item["category"] == "auth_token_error"]
        assert any(item["metadata"].get("server_name") == "auth_code_headless" for item in token_errors)
        assert any(item["metadata"].get("auth_type") == "oauth_auth_code_pkce" for item in token_errors)
        assert len(captured) == 1
        assert captured[0]["server_name"] == "api_key_good"

    def test_config_severity_filter_can_clear_medium_only_findings(self, tmp_path: Path):
        """Severity filter should remove findings below threshold."""
        runner = CliRunner()
        config_path = tmp_path / "claude_desktop_config.json"
        config_path.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "unsupported": {
                            "transport": "grpc",
                            "url": "grpc://localhost:50051",
                        }
                    }
                }
            ),
            encoding="utf-8",
        )

        result = runner.invoke(
            main,
            ["config", str(config_path), "--format", "json", "--severity", "high", "--timeout", "1"],
        )

        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["findings"] == []

    def test_server_severity_high_keeps_only_secret_exfiltration_cross_tool(self, monkeypatch):
        """High severity threshold should keep only high cross-tool chain findings."""

        async def fake_discover(server_name: str, connector_configs: list[dict[str, object]]) -> ServerCapabilities:
            del connector_configs
            return ServerCapabilities(
                server_name=server_name,
                tools=_cross_tool_test_tools(include_medium_chain=True),
                resources=[],
                prompts=[],
            )

        monkeypatch.setattr(cli_module, "_discover_capabilities", fake_discover)

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "server",
                "python -m fake_server",
                "--format",
                "json",
                "--severity",
                "high",
                "--timeout",
                "1",
            ],
        )

        assert result.exit_code == 1
        payload = json.loads(result.output)
        categories = {finding["category"] for finding in payload["findings"]}
        assert categories == {"cross_tool_secret_exfiltration"}

    def test_config_auth_error_visible_with_high_threshold(self, monkeypatch, tmp_path: Path):
        """auth_config_error findings should remain visible under high severity filter."""
        monkeypatch.delenv("MISSING_BEARER_TOKEN", raising=False)

        runner = CliRunner()
        config_path = tmp_path / "claude_desktop_config.json"
        config_path.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "auth_bad": {
                            "transport": "sse",
                            "url": "https://example.com/bad",
                            "auth": {"type": "bearer", "token_env": "MISSING_BEARER_TOKEN"},
                        }
                    }
                }
            ),
            encoding="utf-8",
        )

        result = runner.invoke(
            main,
            ["config", str(config_path), "--format", "json", "--severity", "high", "--timeout", "1"],
        )

        assert result.exit_code == 1
        payload = json.loads(result.output)
        categories = {finding["category"] for finding in payload["findings"]}
        assert categories == {"auth_config_error"}

    def test_config_oauth_token_error_visible_with_high_threshold(self, monkeypatch, tmp_path: Path):
        """auth_token_error findings should remain visible under high severity filter."""
        monkeypatch.setenv("OAUTH_CLIENT_ID", "client-app")
        monkeypatch.setenv("OAUTH_CLIENT_SECRET", "secret-app")

        def fake_request(
            *,
            token_url: str,
            client_id: str,
            client_secret: str,
            scope: str | None,
            audience: str | None,
            token_endpoint_auth_method: str,
            timeout_seconds: int,
        ) -> tuple[str | None, float | None, str | None, int | None]:
            del token_url, client_id, client_secret, scope, audience, token_endpoint_auth_method, timeout_seconds
            return None, None, "Token endpoint request failed: timeout", None

        monkeypatch.setattr(cli_module, "_request_oauth_client_credentials_token", fake_request)

        runner = CliRunner()
        config_path = tmp_path / "claude_desktop_config.json"
        config_path.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "oauth_bad": {
                            "transport": "streamable-http",
                            "url": "https://example.com/mcp",
                            "auth": {
                                "type": "oauth_client_credentials",
                                "token_url": "https://auth.example.com/token",
                                "client_id_env": "OAUTH_CLIENT_ID",
                                "client_secret_env": "OAUTH_CLIENT_SECRET",
                            },
                        }
                    }
                }
            ),
            encoding="utf-8",
        )

        result = runner.invoke(
            main,
            ["config", str(config_path), "--format", "json", "--severity", "high", "--timeout", "2"],
        )

        assert result.exit_code == 1
        payload = json.loads(result.output)
        categories = {finding["category"] for finding in payload["findings"]}
        assert categories == {"auth_token_error"}

    def test_baseline_writes_v1_document(self, tmp_path: Path):
        """`baseline` command should create baseline-v1 JSON."""
        runner = CliRunner()
        baseline_path = tmp_path / "baseline.json"

        result = runner.invoke(
            main,
            ["baseline", MOCK_SERVER_COMMAND, "--save", str(baseline_path), "--timeout", "2"],
        )

        assert result.exit_code == 0
        data = json.loads(baseline_path.read_text(encoding="utf-8"))

        assert data["schema_version"] == BASELINE_SCHEMA_VERSION
        assert "scanner_version" in data
        assert "created_at" in data
        assert data["server"]["name"] == _derive_server_name(MOCK_SERVER_COMMAND)
        assert data["server"]["command"] == MOCK_SERVER_COMMAND
        assert [item["name"] for item in data["tools"]] == ["dangerous_exec", "safe_echo"]
        assert all(item["overall_hash"] for item in data["tools"])

    def test_baseline_tool_hashes_are_deterministic(self, tmp_path: Path):
        """Baseline hash output should be deterministic for same tool set."""
        runner = CliRunner()
        baseline_one = tmp_path / "baseline_one.json"
        baseline_two = tmp_path / "baseline_two.json"

        result_one = runner.invoke(
            main,
            ["baseline", MOCK_SERVER_COMMAND, "--save", str(baseline_one), "--timeout", "2"],
        )
        result_two = runner.invoke(
            main,
            ["baseline", MOCK_SERVER_COMMAND, "--save", str(baseline_two), "--timeout", "2"],
        )

        assert result_one.exit_code == 0
        assert result_two.exit_code == 0

        data_one = json.loads(baseline_one.read_text(encoding="utf-8"))
        data_two = json.loads(baseline_two.read_text(encoding="utf-8"))
        hashes_one = {item["name"]: item["overall_hash"] for item in data_one["tools"]}
        hashes_two = {item["name"]: item["overall_hash"] for item in data_two["tools"]}

        assert hashes_one == hashes_two

    def test_baseline_failure_returns_exit_2(self, tmp_path: Path):
        """Operational baseline failures should exit with code 2."""
        runner = CliRunner()
        baseline_path = tmp_path / "baseline.json"

        result = runner.invoke(
            main,
            ["baseline", SLEEP_COMMAND, "--save", str(baseline_path), "--timeout", "1"],
        )

        assert result.exit_code == 2
        assert "Baseline creation failed" in result.output

    def test_compare_no_change_returns_exit_0(self, tmp_path: Path):
        """Compare should pass cleanly when baseline and live snapshot match."""
        baseline_path = self._create_baseline(tmp_path)
        runner = CliRunner()

        result = runner.invoke(
            main,
            ["compare", str(baseline_path), MOCK_SERVER_COMMAND, "--format", "json", "--timeout", "2"],
        )

        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["findings"] == []

    def test_compare_detects_added_removed_and_changed_tools(self, tmp_path: Path):
        """Compare should report added/removed/changed mutations as findings."""
        baseline_path = self._create_baseline(tmp_path)
        runner = CliRunner()

        result = runner.invoke(
            main,
            ["compare", str(baseline_path), MUTATED_SERVER_COMMAND, "--format", "json", "--timeout", "2"],
        )

        assert result.exit_code == 1
        payload = json.loads(result.output)
        categories = {finding["category"] for finding in payload["findings"]}

        assert categories == {"tool_added", "tool_removed", "tool_changed"}
        assert all(item["owasp_id"] == "LLM05" for item in payload["findings"])

    def test_compare_severity_filter_critical_returns_exit_0(self, tmp_path: Path):
        """Critical threshold should filter compare findings down to empty set."""
        baseline_path = self._create_baseline(tmp_path)
        runner = CliRunner()

        result = runner.invoke(
            main,
            [
                "compare",
                str(baseline_path),
                MUTATED_SERVER_COMMAND,
                "--format",
                "json",
                "--severity",
                "critical",
                "--timeout",
                "2",
            ],
        )

        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["findings"] == []

    def test_compare_invalid_baseline_json_returns_exit_2(self, tmp_path: Path):
        """Malformed baseline JSON should fail compare with operational exit code."""
        runner = CliRunner()
        baseline_path = tmp_path / "bad_baseline.json"
        baseline_path.write_text("{bad", encoding="utf-8")

        result = runner.invoke(main, ["compare", str(baseline_path), MOCK_SERVER_COMMAND, "--timeout", "2"])

        assert result.exit_code == 2
        assert "Compare failed" in result.output

    def test_compare_invalid_baseline_schema_returns_exit_2(self, tmp_path: Path):
        """Unsupported baseline schema should fail compare as operational error."""
        runner = CliRunner()
        baseline_path = tmp_path / "baseline.json"
        baseline_path.write_text(
            json.dumps(
                {
                    "schema_version": "baseline-v0",
                    "tools": [],
                }
            ),
            encoding="utf-8",
        )

        result = runner.invoke(main, ["compare", str(baseline_path), MOCK_SERVER_COMMAND, "--timeout", "2"])

        assert result.exit_code == 2
        assert "Unsupported baseline schema_version" in result.output

    def test_cache_rotate_command_success_with_fallback_file(self, monkeypatch, tmp_path: Path):
        """Cache rotate should succeed and persist metadata key file when keyring is unavailable."""
        monkeypatch.setattr(cli_module, "_OAUTH_PERSISTENT_CACHE_FILE", tmp_path / "oauth-cache-v1.json.enc")
        monkeypatch.setattr(cli_module, "_OAUTH_PERSISTENT_CACHE_LOCK_FILE", tmp_path / "oauth-cache-v1.lock")
        monkeypatch.setattr(cli_module, "_OAUTH_PERSISTENT_KEY_FILE", tmp_path / "cache.key")
        monkeypatch.setattr(cli_module, "_read_oauth_cache_key_set_from_keyring", lambda: None)
        monkeypatch.setattr(cli_module, "_write_oauth_cache_key_set_to_keyring", lambda key_set: False)

        runner = CliRunner()
        result = runner.invoke(main, ["cache", "rotate"])

        assert result.exit_code == 0
        assert "source=file" in result.output
        key_payload = json.loads((tmp_path / "cache.key").read_text(encoding="utf-8"))
        assert "active" in key_payload
        assert "key_id" in key_payload["active"]
        assert "fernet_key" in key_payload["active"]

    def test_cache_rotate_command_success_with_keyring(self, monkeypatch, tmp_path: Path):
        """Cache rotate should report keyring source when keyring write succeeds."""
        monkeypatch.setattr(cli_module, "_OAUTH_PERSISTENT_CACHE_FILE", tmp_path / "oauth-cache-v1.json.enc")
        monkeypatch.setattr(cli_module, "_OAUTH_PERSISTENT_CACHE_LOCK_FILE", tmp_path / "oauth-cache-v1.lock")
        monkeypatch.setattr(cli_module, "_OAUTH_PERSISTENT_KEY_FILE", tmp_path / "cache.key")
        monkeypatch.setattr(cli_module, "_read_oauth_cache_key_set_from_keyring", lambda: None)

        wrote: list[str] = []

        def fake_write_to_keyring(key_set: cli_module.OAuthCacheKeySet) -> bool:
            wrote.append(key_set.active.key_id)
            return True

        monkeypatch.setattr(cli_module, "_write_oauth_cache_key_set_to_keyring", fake_write_to_keyring)
        monkeypatch.setattr(cli_module, "_write_oauth_cache_key_set_to_file", lambda key_set: False)

        runner = CliRunner()
        result = runner.invoke(main, ["cache", "rotate"])

        assert result.exit_code == 0
        assert "source=keyring" in result.output
        assert len(wrote) == 1

    def test_cache_rotate_command_operational_error_returns_exit_2(self, monkeypatch):
        """Cache rotate should return operational error when lock cannot be acquired."""
        monkeypatch.setattr(
            cli_module,
            "_acquire_oauth_cache_lock",
            lambda: (None, "Timed out acquiring OAuth cache lock after 2.0s."),
        )

        runner = CliRunner()
        result = runner.invoke(main, ["cache", "rotate"])

        assert result.exit_code == 2
        assert "Cache rotation failed" in result.output

    def test_cache_rotate_command_remains_local_only(self, monkeypatch, tmp_path: Path):
        """Cache rotate should not touch remote provider client builders."""
        monkeypatch.setattr(cli_module, "_OAUTH_PERSISTENT_CACHE_FILE", tmp_path / "oauth-cache-v1.json.enc")
        monkeypatch.setattr(cli_module, "_OAUTH_PERSISTENT_CACHE_LOCK_FILE", tmp_path / "oauth-cache-v1.lock")
        monkeypatch.setattr(cli_module, "_OAUTH_PERSISTENT_KEY_FILE", tmp_path / "cache.key")
        monkeypatch.setattr(cli_module, "_read_oauth_cache_key_set_from_keyring", lambda: None)
        monkeypatch.setattr(cli_module, "_write_oauth_cache_key_set_to_keyring", lambda key_set: False)

        def fail_remote_builder(*args: object, **kwargs: object) -> None:
            del args, kwargs
            raise AssertionError("remote provider builder must not be called by cache rotate")

        monkeypatch.setattr(cli_module, "_build_aws_secrets_manager_client", fail_remote_builder)
        monkeypatch.setattr(cli_module, "_build_aws_ssm_parameter_store_client", fail_remote_builder)
        monkeypatch.setattr(cli_module, "_build_gcp_secret_manager_client", fail_remote_builder)
        monkeypatch.setattr(cli_module, "_build_azure_key_vault_client", fail_remote_builder)
        monkeypatch.setattr(cli_module, "_build_hashicorp_vault_client", fail_remote_builder)
        monkeypatch.setattr(cli_module, "_build_kubernetes_secret_client", fail_remote_builder)
        monkeypatch.setattr(cli_module, "_build_oci_secrets_client", fail_remote_builder)
        monkeypatch.setattr(cli_module, "_build_oci_vault_client", fail_remote_builder)
        monkeypatch.setattr(cli_module, "_build_doppler_http_client", fail_remote_builder)
        monkeypatch.setattr(cli_module, "_build_onepassword_connect_http_client", fail_remote_builder)
        monkeypatch.setattr(cli_module, "_build_bitwarden_http_client", fail_remote_builder)
        monkeypatch.setattr(cli_module, "_build_infisical_http_client", fail_remote_builder)
        monkeypatch.setattr(cli_module, "_build_akeyless_http_client", fail_remote_builder)
        monkeypatch.setattr(cli_module, "_build_gitlab_http_client", fail_remote_builder)
        monkeypatch.setattr(cli_module, "_build_github_http_client", fail_remote_builder)
        monkeypatch.setattr(cli_module, "_build_consul_http_client", fail_remote_builder)
        monkeypatch.setattr(cli_module, "_build_redis_client", fail_remote_builder)
        monkeypatch.setattr(cli_module, "_build_cloudflare_http_client", fail_remote_builder)
        monkeypatch.setattr(cli_module, "_build_etcd_http_client", fail_remote_builder)
        monkeypatch.setattr(cli_module, "_build_postgres_connection", fail_remote_builder)
        monkeypatch.setattr(cli_module, "_build_mysql_connection", fail_remote_builder)

        runner = CliRunner()
        result = runner.invoke(main, ["cache", "rotate"])

        assert result.exit_code == 0
        assert "source=file" in result.output


class TestCLIHelpers:
    """Unit tests for CLI helper functions and normalization paths."""

    def test_extract_config_server_entries_validation(self):
        """mcpServers extraction should validate object structure."""
        with pytest.raises(ValueError, match="object"):
            _extract_config_server_entries([])

        with pytest.raises(ValueError, match="mcpServers"):
            _extract_config_server_entries({})

        entries = _extract_config_server_entries({"mcpServers": {"a": {"transport": "stdio"}}})
        assert list(entries.keys()) == ["a"]

    def test_build_connector_config_success_includes_env(self):
        """Valid stdio entry should normalize command/args/env into connector config."""
        connector_config, finding = _build_connector_config_from_config_entry(
            server_name="sample",
            raw_server_config={
                "transport": "stdio",
                "command": sys.executable,
                "args": [str(MOCK_SERVER)],
                "env": {"MCP_TEST_ENV": 123},
            },
            timeout=17,
        )

        assert finding is None
        assert connector_config is not None
        assert connector_config["type"] == "stdio"
        assert connector_config["timeout"] == 17
        assert connector_config["env"] == {"MCP_TEST_ENV": "123"}
        assert shlex.split(connector_config["command"]) == [sys.executable, str(MOCK_SERVER)]

    def test_build_connector_config_success_for_sse(self):
        """Valid SSE entry should normalize URL and headers."""
        connector_config, finding = _build_connector_config_from_config_entry(
            server_name="sse_server",
            raw_server_config={
                "transport": "sse",
                "url": "https://example.com/sse",
                "headers": {"Authorization": "Bearer 123", "X-Trace": 99},
            },
            timeout=11,
        )

        assert finding is None
        assert connector_config is not None
        assert connector_config["type"] == "sse"
        assert connector_config["url"] == "https://example.com/sse"
        assert connector_config["timeout"] == 11
        assert connector_config["headers"] == {"Authorization": "Bearer 123", "X-Trace": "99"}

    def test_build_connector_config_success_for_streamable_http_alias(self):
        """streamable_http alias should normalize to streamable-http transport."""
        connector_config, finding = _build_connector_config_from_config_entry(
            server_name="streamable_server",
            raw_server_config={
                "transport": "streamable_http",
                "url": "https://example.com/mcp",
                "headers": {"Authorization": "Bearer 123", "X-Trace": 99},
            },
            timeout=11,
        )

        assert finding is None
        assert connector_config is not None
        assert connector_config["type"] == "streamable-http"
        assert connector_config["url"] == "https://example.com/mcp"
        assert connector_config["timeout"] == 11
        assert connector_config["headers"] == {"Authorization": "Bearer 123", "X-Trace": "99"}

    def test_build_connector_config_success_for_bearer_auth(self, monkeypatch):
        """Bearer auth should resolve token from env and override explicit header."""
        monkeypatch.setenv("MCP_TEST_BEARER", "token-abc")
        connector_config, finding = _build_connector_config_from_config_entry(
            server_name="auth_server",
            raw_server_config={
                "transport": "sse",
                "url": "https://example.com/sse",
                "headers": {"Authorization": "Bearer old", "X-Trace": 99},
                "auth": {"type": "bearer", "token_env": "MCP_TEST_BEARER"},
            },
            timeout=9,
        )

        assert finding is None
        assert connector_config is not None
        assert connector_config["headers"]["Authorization"] == "Bearer token-abc"
        assert connector_config["headers"]["X-Trace"] == "99"

    def test_build_connector_config_success_for_api_key_auth(self, monkeypatch):
        """API key auth should resolve key from env into configured header."""
        monkeypatch.setenv("MCP_TEST_API_KEY", "key-123")
        connector_config, finding = _build_connector_config_from_config_entry(
            server_name="auth_server",
            raw_server_config={
                "transport": "streamable-http",
                "url": "https://example.com/mcp",
                "auth": {"type": "api_key", "key_env": "MCP_TEST_API_KEY", "header": "X-Service-Key"},
            },
            timeout=9,
        )

        assert finding is None
        assert connector_config is not None
        assert connector_config["headers"]["X-Service-Key"] == "key-123"

    def test_build_connector_config_success_for_session_cookie_auth(self, monkeypatch):
        """Session cookie auth should merge with existing Cookie header."""
        monkeypatch.setenv("MCP_TEST_SESSION", "session-xyz")
        connector_config, finding = _build_connector_config_from_config_entry(
            server_name="auth_server",
            raw_server_config={
                "transport": "sse",
                "url": "https://example.com/sse",
                "headers": {"Cookie": "existing=1"},
                "auth": {"type": "session_cookie", "cookie_env": "MCP_TEST_SESSION", "cookie_name": "session"},
            },
            timeout=9,
        )

        assert finding is None
        assert connector_config is not None
        assert connector_config["headers"]["Cookie"] == "existing=1; session=session-xyz"

    def test_build_connector_config_success_for_oauth_client_credentials_auth(self, monkeypatch):
        """OAuth client-credentials auth should resolve token and override explicit header."""
        cli_module._clear_oauth_token_cache()
        monkeypatch.setenv("MCP_OAUTH_CLIENT_ID", "client-123")
        monkeypatch.setenv("MCP_OAUTH_CLIENT_SECRET", "secret-456")
        calls: list[dict[str, object]] = []

        def fake_request(
            *,
            token_url: str,
            client_id: str,
            client_secret: str,
            scope: str | None,
            audience: str | None,
            token_endpoint_auth_method: str,
            timeout_seconds: int,
        ) -> tuple[str | None, float | None, str | None, int | None]:
            calls.append(
                {
                    "token_url": token_url,
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "scope": scope,
                    "audience": audience,
                    "token_endpoint_auth_method": token_endpoint_auth_method,
                    "timeout_seconds": timeout_seconds,
                }
            )
            return "oauth-token-xyz", 3600.0, None, 200

        monkeypatch.setattr(cli_module, "_request_oauth_client_credentials_token", fake_request)

        connector_config, finding = _build_connector_config_from_config_entry(
            server_name="oauth_server",
            raw_server_config={
                "transport": "sse",
                "url": "https://example.com/sse",
                "headers": {"Authorization": "Bearer old", "X-Trace": 5},
                "auth": {
                    "type": "oauth_client_credentials",
                    "token_url": "https://auth.example.com/token",
                    "client_id_env": "MCP_OAUTH_CLIENT_ID",
                    "client_secret_env": "MCP_OAUTH_CLIENT_SECRET",
                    "scope": "mcp.read",
                    "audience": "mcp-api",
                },
            },
            timeout=12,
        )

        assert finding is None
        assert connector_config is not None
        assert connector_config["headers"]["Authorization"] == "Bearer oauth-token-xyz"
        assert connector_config["headers"]["X-Trace"] == "5"
        assert len(calls) == 1
        assert calls[0]["token_url"] == "https://auth.example.com/token"
        assert calls[0]["client_id"] == "client-123"
        assert calls[0]["scope"] == "mcp.read"
        assert calls[0]["audience"] == "mcp-api"
        assert calls[0]["token_endpoint_auth_method"] == "client_secret_post"
        assert calls[0]["timeout_seconds"] == 12

    def test_build_connector_config_oauth_client_credentials_supports_client_secret_basic(self, monkeypatch):
        """OAuth client credentials should pass client_secret_basic and use token_type when scheme is omitted."""
        cli_module._clear_oauth_token_cache()
        monkeypatch.setenv("MCP_OAUTH_CLIENT_ID", "client-basic")
        monkeypatch.setenv("MCP_OAUTH_CLIENT_SECRET", "secret-basic")

        calls: list[str] = []

        def fake_request(
            *,
            token_url: str,
            client_id: str,
            client_secret: str,
            scope: str | None,
            audience: str | None,
            token_endpoint_auth_method: str,
            timeout_seconds: int,
        ) -> tuple[str | None, float | None, str | None, int | None, str | None]:
            assert token_url == "https://auth.example.com/token"
            assert client_id == "client-basic"
            assert client_secret == "secret-basic"
            assert scope is None
            assert audience is None
            assert timeout_seconds == 10
            calls.append(token_endpoint_auth_method)
            return "oauth-basic-token", 3600.0, None, 200, "DPoP"

        monkeypatch.setattr(cli_module, "_request_oauth_client_credentials_token", fake_request)

        connector_config, finding = _build_connector_config_from_config_entry(
            server_name="oauth_basic_server",
            raw_server_config={
                "transport": "sse",
                "url": "https://example.com/sse",
                "auth": {
                    "type": "oauth_client_credentials",
                    "token_url": "https://auth.example.com/token",
                    "client_id_env": "MCP_OAUTH_CLIENT_ID",
                    "client_secret_env": "MCP_OAUTH_CLIENT_SECRET",
                    "token_endpoint_auth_method": "client_secret_basic",
                },
            },
            timeout=10,
        )

        assert finding is None
        assert connector_config is not None
        assert connector_config["headers"]["Authorization"] == "DPoP oauth-basic-token"
        assert calls == ["client_secret_basic"]

    def test_build_connector_config_oauth_scheme_overrides_token_type(self, monkeypatch):
        """auth.scheme should take precedence over token_type from token endpoint."""
        cli_module._clear_oauth_token_cache()
        monkeypatch.setenv("MCP_OAUTH_CLIENT_ID", "client-basic")
        monkeypatch.setenv("MCP_OAUTH_CLIENT_SECRET", "secret-basic")

        def fake_request(
            *,
            token_url: str,
            client_id: str,
            client_secret: str,
            scope: str | None,
            audience: str | None,
            token_endpoint_auth_method: str,
            timeout_seconds: int,
        ) -> tuple[str | None, float | None, str | None, int | None, str | None]:
            del token_url, client_id, client_secret, scope, audience, token_endpoint_auth_method, timeout_seconds
            return "oauth-token", 3600.0, None, 200, "DPoP"

        monkeypatch.setattr(cli_module, "_request_oauth_client_credentials_token", fake_request)

        connector_config, finding = _build_connector_config_from_config_entry(
            server_name="oauth_scheme_server",
            raw_server_config={
                "transport": "sse",
                "url": "https://example.com/sse",
                "auth": {
                    "type": "oauth_client_credentials",
                    "token_url": "https://auth.example.com/token",
                    "client_id_env": "MCP_OAUTH_CLIENT_ID",
                    "client_secret_env": "MCP_OAUTH_CLIENT_SECRET",
                    "scheme": "Bearer",
                },
            },
            timeout=10,
        )

        assert finding is None
        assert connector_config is not None
        assert connector_config["headers"]["Authorization"] == "Bearer oauth-token"

    def test_build_connector_config_oauth_persistent_cache_with_client_secret_basic(self, monkeypatch, tmp_path: Path):
        """Persistent cache should work with client_secret_basic flow."""
        cli_module._clear_oauth_token_cache()
        monkeypatch.setenv("MCP_OAUTH_CLIENT_ID", "client-basic")
        monkeypatch.setenv("MCP_OAUTH_CLIENT_SECRET", "secret-basic")
        monkeypatch.setattr(cli_module, "_OAUTH_PERSISTENT_CACHE_FILE", tmp_path / "oauth-cache-v1.json.enc")
        monkeypatch.setattr(cli_module, "_OAUTH_PERSISTENT_KEY_FILE", tmp_path / "cache.key")
        monkeypatch.setattr(cli_module, "_read_oauth_cache_key_from_keyring", lambda: None)

        call_count = {"value": 0}

        def fake_request(
            *,
            token_url: str,
            client_id: str,
            client_secret: str,
            scope: str | None,
            audience: str | None,
            token_endpoint_auth_method: str,
            timeout_seconds: int,
        ) -> tuple[str | None, float | None, str | None, int | None]:
            call_count["value"] += 1
            assert token_url == "https://auth.example.com/token"
            assert client_id == "client-basic"
            assert client_secret == "secret-basic"
            assert scope is None
            assert audience is None
            assert timeout_seconds == 10
            assert token_endpoint_auth_method == "client_secret_basic"
            return "oauth-basic-token", 3600.0, None, 200

        monkeypatch.setattr(cli_module, "_request_oauth_client_credentials_token", fake_request)

        raw_server_config = {
            "transport": "sse",
            "url": "https://example.com/sse",
            "auth": {
                "type": "oauth_client_credentials",
                "token_url": "https://auth.example.com/token",
                "client_id_env": "MCP_OAUTH_CLIENT_ID",
                "client_secret_env": "MCP_OAUTH_CLIENT_SECRET",
                "token_endpoint_auth_method": "client_secret_basic",
                "cache": {"persistent": True, "namespace": "ns-basic"},
            },
        }

        first_config, first_finding = _build_connector_config_from_config_entry(
            server_name="oauth_basic_server",
            raw_server_config=raw_server_config,
            timeout=10,
        )
        assert first_finding is None
        assert first_config is not None
        assert first_config["headers"]["Authorization"] == "Bearer oauth-basic-token"
        assert call_count["value"] == 1

        cli_module._clear_oauth_token_cache()
        second_config, second_finding = _build_connector_config_from_config_entry(
            server_name="oauth_basic_server",
            raw_server_config=raw_server_config,
            timeout=10,
        )
        assert second_finding is None
        assert second_config is not None
        assert second_config["headers"]["Authorization"] == "Bearer oauth-basic-token"
        assert call_count["value"] == 1

    def test_oauth_cache_namespace_isolation(self, monkeypatch):
        """Different cache namespaces should not share OAuth token entries."""
        cli_module._clear_oauth_token_cache()
        monkeypatch.setenv("MCP_OAUTH_CLIENT_ID", "client-cache")
        monkeypatch.setenv("MCP_OAUTH_CLIENT_SECRET", "secret-cache")

        call_count = {"value": 0}

        def fake_request(
            *,
            token_url: str,
            client_id: str,
            client_secret: str,
            scope: str | None,
            audience: str | None,
            token_endpoint_auth_method: str,
            timeout_seconds: int,
        ) -> tuple[str | None, float | None, str | None, int | None]:
            del token_url, client_id, client_secret, scope, audience, token_endpoint_auth_method, timeout_seconds
            call_count["value"] += 1
            return f"token-{call_count['value']}", 3600.0, None, 200

        monkeypatch.setattr(cli_module, "_request_oauth_client_credentials_token", fake_request)

        base_config = {
            "transport": "sse",
            "url": "https://example.com/sse",
            "auth": {
                "type": "oauth_client_credentials",
                "token_url": "https://auth.example.com/token",
                "client_id_env": "MCP_OAUTH_CLIENT_ID",
                "client_secret_env": "MCP_OAUTH_CLIENT_SECRET",
                "cache": {"persistent": False},
            },
        }

        first_config = json.loads(json.dumps(base_config))
        first_config["auth"]["cache"]["namespace"] = "alpha"
        second_config = json.loads(json.dumps(base_config))
        second_config["auth"]["cache"]["namespace"] = "beta"

        first_connector, first_finding = _build_connector_config_from_config_entry(
            server_name="oauth_alpha",
            raw_server_config=first_config,
            timeout=8,
        )
        second_connector, second_finding = _build_connector_config_from_config_entry(
            server_name="oauth_beta",
            raw_server_config=second_config,
            timeout=8,
        )

        assert first_finding is None
        assert second_finding is None
        assert first_connector is not None
        assert second_connector is not None
        assert first_connector["headers"]["Authorization"] == "Bearer token-1"
        assert second_connector["headers"]["Authorization"] == "Bearer token-2"
        assert call_count["value"] == 2

    def test_coerce_oauth_cache_settings_accepts_aws_backend(self):
        """OAuth cache settings should accept aws_secrets_manager backend with required fields."""
        settings, error = cli_module._coerce_oauth_cache_settings(
            auth_type="oauth_client_credentials",
            auth_value={
                "cache": {
                    "persistent": True,
                    "namespace": "prod-security",
                    "backend": "aws_secrets_manager",
                    "aws_secret_id": "mcp-security/oauth-cache",
                    "aws_region": "eu-west-1",
                    "aws_endpoint_url": "https://secretsmanager.eu-west-1.amazonaws.com",
                }
            },
        )

        assert error is None
        assert settings is not None
        assert settings.persistent is True
        assert settings.namespace == "prod-security"
        assert settings.backend == "aws_secrets_manager"
        assert settings.aws_secret_id == "mcp-security/oauth-cache"
        assert settings.aws_region == "eu-west-1"
        assert settings.aws_endpoint_url == "https://secretsmanager.eu-west-1.amazonaws.com"

    def test_coerce_oauth_cache_settings_accepts_aws_ssm_backend(self):
        """OAuth cache settings should accept aws_ssm_parameter_store backend with required fields."""
        settings, error = cli_module._coerce_oauth_cache_settings(
            auth_type="oauth_client_credentials",
            auth_value={
                "cache": {
                    "persistent": True,
                    "namespace": "prod-security",
                    "backend": "aws_ssm_parameter_store",
                    "aws_ssm_parameter_name": "/mcp-security/oauth-cache",
                    "aws_region": "eu-west-1",
                    "aws_endpoint_url": "https://ssm.eu-west-1.amazonaws.com",
                }
            },
        )

        assert error is None
        assert settings is not None
        assert settings.persistent is True
        assert settings.namespace == "prod-security"
        assert settings.backend == "aws_ssm_parameter_store"
        assert settings.aws_ssm_parameter_name == "/mcp-security/oauth-cache"
        assert settings.aws_region == "eu-west-1"
        assert settings.aws_endpoint_url == "https://ssm.eu-west-1.amazonaws.com"

    def test_coerce_oauth_cache_settings_accepts_gcp_backend(self):
        """OAuth cache settings should accept gcp_secret_manager backend with required fields."""
        settings, error = cli_module._coerce_oauth_cache_settings(
            auth_type="oauth_client_credentials",
            auth_value={
                "cache": {
                    "persistent": True,
                    "namespace": "prod-security",
                    "backend": "gcp_secret_manager",
                    "gcp_secret_name": "projects/demo-project/secrets/mcp-oauth-cache",
                    "gcp_endpoint_url": "https://secretmanager.googleapis.com",
                }
            },
        )

        assert error is None
        assert settings is not None
        assert settings.persistent is True
        assert settings.namespace == "prod-security"
        assert settings.backend == "gcp_secret_manager"
        assert settings.gcp_secret_name == "projects/demo-project/secrets/mcp-oauth-cache"
        assert settings.gcp_endpoint_url == "https://secretmanager.googleapis.com"

    def test_coerce_oauth_cache_settings_accepts_azure_backend(self):
        """OAuth cache settings should accept azure_key_vault backend with required fields."""
        settings, error = cli_module._coerce_oauth_cache_settings(
            auth_type="oauth_client_credentials",
            auth_value={
                "cache": {
                    "persistent": True,
                    "namespace": "prod-security",
                    "backend": "azure_key_vault",
                    "azure_vault_url": "https://mcp-security.vault.azure.net",
                    "azure_secret_name": "mcp-security-oauth-cache",
                }
            },
        )

        assert error is None
        assert settings is not None
        assert settings.persistent is True
        assert settings.namespace == "prod-security"
        assert settings.backend == "azure_key_vault"
        assert settings.azure_vault_url == "https://mcp-security.vault.azure.net"
        assert settings.azure_secret_name == "mcp-security-oauth-cache"
        assert settings.azure_secret_version == "latest"

    def test_coerce_oauth_cache_settings_accepts_hashicorp_vault_backend(self):
        """OAuth cache settings should accept hashicorp_vault backend with required fields."""
        settings, error = cli_module._coerce_oauth_cache_settings(
            auth_type="oauth_client_credentials",
            auth_value={
                "cache": {
                    "persistent": True,
                    "namespace": "prod-security",
                    "backend": "hashicorp_vault",
                    "vault_url": "https://vault.example.com",
                    "vault_secret_path": "kv/mcp-security/oauth-cache",
                    "vault_token_env": "VAULT_TOKEN",
                    "vault_namespace": "team-security",
                }
            },
        )

        assert error is None
        assert settings is not None
        assert settings.persistent is True
        assert settings.namespace == "prod-security"
        assert settings.backend == "hashicorp_vault"
        assert settings.vault_url == "https://vault.example.com"
        assert settings.vault_secret_path == "kv/mcp-security/oauth-cache"
        assert settings.vault_token_env == "VAULT_TOKEN"
        assert settings.vault_namespace == "team-security"

    def test_coerce_oauth_cache_settings_accepts_kubernetes_backend(self):
        """OAuth cache settings should accept kubernetes_secrets backend with required fields."""
        settings, error = cli_module._coerce_oauth_cache_settings(
            auth_type="oauth_client_credentials",
            auth_value={
                "cache": {
                    "persistent": True,
                    "namespace": "prod-security",
                    "backend": "kubernetes_secrets",
                    "k8s_secret_namespace": "mcp-security",
                    "k8s_secret_name": "oauth-cache",
                }
            },
        )

        assert error is None
        assert settings is not None
        assert settings.persistent is True
        assert settings.namespace == "prod-security"
        assert settings.backend == "kubernetes_secrets"
        assert settings.k8s_secret_namespace == "mcp-security"
        assert settings.k8s_secret_name == "oauth-cache"
        assert settings.k8s_secret_key == "oauth_cache"

    def test_coerce_oauth_cache_settings_accepts_oci_backend(self):
        """OAuth cache settings should accept oci_vault backend with required fields."""
        settings, error = cli_module._coerce_oauth_cache_settings(
            auth_type="oauth_client_credentials",
            auth_value={
                "cache": {
                    "persistent": True,
                    "namespace": "prod-security",
                    "backend": "oci_vault",
                    "oci_secret_ocid": "ocid1.secret.oc1.iad.exampleuniqueid1234567890",
                    "oci_region": "eu-frankfurt-1",
                    "oci_endpoint_url": "https://vaults.eu-frankfurt-1.oci.oraclecloud.com",
                }
            },
        )

        assert error is None
        assert settings is not None
        assert settings.persistent is True
        assert settings.namespace == "prod-security"
        assert settings.backend == "oci_vault"
        assert settings.oci_secret_ocid == "ocid1.secret.oc1.iad.exampleuniqueid1234567890"
        assert settings.oci_region == "eu-frankfurt-1"
        assert settings.oci_endpoint_url == "https://vaults.eu-frankfurt-1.oci.oraclecloud.com"

    def test_coerce_oauth_cache_settings_accepts_doppler_backend(self):
        """OAuth cache settings should accept doppler_secrets backend with required fields."""
        settings, error = cli_module._coerce_oauth_cache_settings(
            auth_type="oauth_client_credentials",
            auth_value={
                "cache": {
                    "persistent": True,
                    "namespace": "prod-security",
                    "backend": "doppler_secrets",
                    "doppler_project": "security-platform",
                    "doppler_config": "prd",
                    "doppler_secret_name": "MCP_OAUTH_CACHE",
                    "doppler_token_env": "DOPPLER_TOKEN_PROD",
                    "doppler_api_url": "https://api.doppler.com",
                }
            },
        )

        assert error is None
        assert settings is not None
        assert settings.persistent is True
        assert settings.namespace == "prod-security"
        assert settings.backend == "doppler_secrets"
        assert settings.doppler_project == "security-platform"
        assert settings.doppler_config == "prd"
        assert settings.doppler_secret_name == "MCP_OAUTH_CACHE"
        assert settings.doppler_token_env == "DOPPLER_TOKEN_PROD"
        assert settings.doppler_api_url == "https://api.doppler.com"

    def test_coerce_oauth_cache_settings_accepts_onepassword_connect_backend(self):
        """OAuth cache settings should accept onepassword_connect backend with required fields."""
        settings, error = cli_module._coerce_oauth_cache_settings(
            auth_type="oauth_client_credentials",
            auth_value={
                "cache": {
                    "persistent": True,
                    "namespace": "prod-security",
                    "backend": "onepassword_connect",
                    "op_connect_host": "https://op-connect.example.com",
                    "op_vault_id": "vault-123",
                    "op_item_id": "item-456",
                    "op_field_label": "oauth_cache",
                    "op_connect_token_env": "OP_CONNECT_TOKEN_PROD",
                }
            },
        )

        assert error is None
        assert settings is not None
        assert settings.persistent is True
        assert settings.namespace == "prod-security"
        assert settings.backend == "onepassword_connect"
        assert settings.op_connect_host == "https://op-connect.example.com"
        assert settings.op_vault_id == "vault-123"
        assert settings.op_item_id == "item-456"
        assert settings.op_field_label == "oauth_cache"
        assert settings.op_connect_token_env == "OP_CONNECT_TOKEN_PROD"

    def test_coerce_oauth_cache_settings_sets_onepassword_defaults(self):
        """OAuth cache settings should apply default onepassword_connect optional values."""
        settings, error = cli_module._coerce_oauth_cache_settings(
            auth_type="oauth_client_credentials",
            auth_value={
                "cache": {
                    "persistent": True,
                    "namespace": "prod-security",
                    "backend": "onepassword_connect",
                    "op_connect_host": "https://op-connect.example.com",
                    "op_vault_id": "vault-123",
                    "op_item_id": "item-456",
                }
            },
        )

        assert error is None
        assert settings is not None
        assert settings.op_field_label == "oauth_cache"
        assert settings.op_connect_token_env == "OP_CONNECT_TOKEN"

    def test_coerce_oauth_cache_settings_accepts_bitwarden_backend(self):
        """OAuth cache settings should accept bitwarden_secrets backend with required fields."""
        settings, error = cli_module._coerce_oauth_cache_settings(
            auth_type="oauth_client_credentials",
            auth_value={
                "cache": {
                    "persistent": True,
                    "namespace": "prod-security",
                    "backend": "bitwarden_secrets",
                    "bw_secret_id": "11111111-2222-3333-4444-555555555555",
                    "bw_access_token_env": "BWS_ACCESS_TOKEN_PROD",
                    "bw_api_url": "https://api.bitwarden.com",
                }
            },
        )

        assert error is None
        assert settings is not None
        assert settings.persistent is True
        assert settings.namespace == "prod-security"
        assert settings.backend == "bitwarden_secrets"
        assert settings.bw_secret_id == "11111111-2222-3333-4444-555555555555"
        assert settings.bw_access_token_env == "BWS_ACCESS_TOKEN_PROD"
        assert settings.bw_api_url == "https://api.bitwarden.com"

    def test_coerce_oauth_cache_settings_sets_bitwarden_defaults(self):
        """OAuth cache settings should apply default bitwarden_secrets optional values."""
        settings, error = cli_module._coerce_oauth_cache_settings(
            auth_type="oauth_client_credentials",
            auth_value={
                "cache": {
                    "persistent": True,
                    "namespace": "prod-security",
                    "backend": "bitwarden_secrets",
                    "bw_secret_id": "11111111-2222-3333-4444-555555555555",
                }
            },
        )

        assert error is None
        assert settings is not None
        assert settings.bw_access_token_env == "BWS_ACCESS_TOKEN"
        assert settings.bw_api_url is None

    def test_coerce_oauth_cache_settings_accepts_infisical_backend(self):
        """OAuth cache settings should accept infisical_secrets backend with required fields."""
        settings, error = cli_module._coerce_oauth_cache_settings(
            auth_type="oauth_client_credentials",
            auth_value={
                "cache": {
                    "persistent": True,
                    "namespace": "prod-security",
                    "backend": "infisical_secrets",
                    "infisical_project_id": "workspace-123",
                    "infisical_environment": "prod",
                    "infisical_secret_name": "MCP_OAUTH_CACHE",
                    "infisical_token_env": "INFISICAL_TOKEN_PROD",
                    "infisical_api_url": "https://app.infisical.com/api",
                }
            },
        )

        assert error is None
        assert settings is not None
        assert settings.persistent is True
        assert settings.namespace == "prod-security"
        assert settings.backend == "infisical_secrets"
        assert settings.infisical_project_id == "workspace-123"
        assert settings.infisical_environment == "prod"
        assert settings.infisical_secret_name == "MCP_OAUTH_CACHE"
        assert settings.infisical_token_env == "INFISICAL_TOKEN_PROD"
        assert settings.infisical_api_url == "https://app.infisical.com/api"

    def test_coerce_oauth_cache_settings_sets_infisical_defaults(self):
        """OAuth cache settings should apply default infisical_secrets optional values."""
        settings, error = cli_module._coerce_oauth_cache_settings(
            auth_type="oauth_client_credentials",
            auth_value={
                "cache": {
                    "persistent": True,
                    "namespace": "prod-security",
                    "backend": "infisical_secrets",
                    "infisical_project_id": "workspace-123",
                    "infisical_environment": "prod",
                    "infisical_secret_name": "MCP_OAUTH_CACHE",
                }
            },
        )

        assert error is None
        assert settings is not None
        assert settings.infisical_token_env == "INFISICAL_TOKEN"
        assert settings.infisical_api_url is None

    def test_coerce_oauth_cache_settings_accepts_akeyless_backend(self):
        """OAuth cache settings should accept akeyless_secrets backend with required fields."""
        settings, error = cli_module._coerce_oauth_cache_settings(
            auth_type="oauth_client_credentials",
            auth_value={
                "cache": {
                    "persistent": True,
                    "namespace": "prod-security",
                    "backend": "akeyless_secrets",
                    "akeyless_secret_name": "/prod/mcp/oauth_cache",
                    "akeyless_token_env": "AKEYLESS_TOKEN_PROD",
                    "akeyless_api_url": "https://api.akeyless.io",
                }
            },
        )

        assert error is None
        assert settings is not None
        assert settings.persistent is True
        assert settings.namespace == "prod-security"
        assert settings.backend == "akeyless_secrets"
        assert settings.akeyless_secret_name == "/prod/mcp/oauth_cache"
        assert settings.akeyless_token_env == "AKEYLESS_TOKEN_PROD"
        assert settings.akeyless_api_url == "https://api.akeyless.io"

    def test_coerce_oauth_cache_settings_sets_akeyless_defaults(self):
        """OAuth cache settings should apply default akeyless_secrets optional values."""
        settings, error = cli_module._coerce_oauth_cache_settings(
            auth_type="oauth_client_credentials",
            auth_value={
                "cache": {
                    "persistent": True,
                    "namespace": "prod-security",
                    "backend": "akeyless_secrets",
                    "akeyless_secret_name": "/prod/mcp/oauth_cache",
                }
            },
        )

        assert error is None
        assert settings is not None
        assert settings.akeyless_token_env == "AKEYLESS_TOKEN"
        assert settings.akeyless_api_url is None

    def test_coerce_oauth_cache_settings_accepts_gitlab_backend(self):
        """OAuth cache settings should accept gitlab_variables backend with required fields."""
        settings, error = cli_module._coerce_oauth_cache_settings(
            auth_type="oauth_client_credentials",
            auth_value={
                "cache": {
                    "persistent": True,
                    "namespace": "prod-security",
                    "backend": "gitlab_variables",
                    "gitlab_project_id": "12345",
                    "gitlab_variable_key": "MCP_OAUTH_CACHE",
                    "gitlab_environment_scope": "production",
                    "gitlab_token_env": "GITLAB_TOKEN_PROD",
                    "gitlab_api_url": "https://gitlab.example.com/api/v4",
                }
            },
        )

        assert error is None
        assert settings is not None
        assert settings.backend == "gitlab_variables"
        assert settings.gitlab_project_id == "12345"
        assert settings.gitlab_variable_key == "MCP_OAUTH_CACHE"
        assert settings.gitlab_environment_scope == "production"
        assert settings.gitlab_token_env == "GITLAB_TOKEN_PROD"
        assert settings.gitlab_api_url == "https://gitlab.example.com/api/v4"

    def test_coerce_oauth_cache_settings_sets_gitlab_defaults(self):
        """OAuth cache settings should apply default gitlab_variables optional values."""
        settings, error = cli_module._coerce_oauth_cache_settings(
            auth_type="oauth_client_credentials",
            auth_value={
                "cache": {
                    "persistent": True,
                    "namespace": "prod-security",
                    "backend": "gitlab_variables",
                    "gitlab_project_id": "12345",
                    "gitlab_variable_key": "MCP_OAUTH_CACHE",
                }
            },
        )

        assert error is None
        assert settings is not None
        assert settings.gitlab_environment_scope == "*"
        assert settings.gitlab_token_env == "GITLAB_TOKEN"
        assert settings.gitlab_api_url is None

    def test_coerce_oauth_cache_settings_accepts_gitlab_group_backend(self):
        """OAuth cache settings should accept gitlab_group_variables backend with required fields."""
        settings, error = cli_module._coerce_oauth_cache_settings(
            auth_type="oauth_client_credentials",
            auth_value={
                "cache": {
                    "persistent": True,
                    "namespace": "prod-security",
                    "backend": "gitlab_group_variables",
                    "gitlab_group_id": "67890",
                    "gitlab_variable_key": "MCP_OAUTH_CACHE",
                    "gitlab_environment_scope": "staging",
                    "gitlab_token_env": "GITLAB_TOKEN_PROD",
                    "gitlab_api_url": "https://gitlab.example.com/api/v4",
                }
            },
        )

        assert error is None
        assert settings is not None
        assert settings.backend == "gitlab_group_variables"
        assert settings.gitlab_group_id == "67890"
        assert settings.gitlab_variable_key == "MCP_OAUTH_CACHE"
        assert settings.gitlab_environment_scope == "staging"
        assert settings.gitlab_token_env == "GITLAB_TOKEN_PROD"
        assert settings.gitlab_api_url == "https://gitlab.example.com/api/v4"

    def test_coerce_oauth_cache_settings_sets_gitlab_group_defaults(self):
        """OAuth cache settings should apply default gitlab_group_variables optional values."""
        settings, error = cli_module._coerce_oauth_cache_settings(
            auth_type="oauth_client_credentials",
            auth_value={
                "cache": {
                    "persistent": True,
                    "namespace": "prod-security",
                    "backend": "gitlab_group_variables",
                    "gitlab_group_id": "67890",
                    "gitlab_variable_key": "MCP_OAUTH_CACHE",
                }
            },
        )

        assert error is None
        assert settings is not None
        assert settings.gitlab_environment_scope == "*"
        assert settings.gitlab_token_env == "GITLAB_TOKEN"
        assert settings.gitlab_api_url is None

    def test_coerce_oauth_cache_settings_accepts_gitlab_instance_backend(self):
        """OAuth cache settings should accept gitlab_instance_variables backend with required fields."""
        settings, error = cli_module._coerce_oauth_cache_settings(
            auth_type="oauth_client_credentials",
            auth_value={
                "cache": {
                    "persistent": True,
                    "namespace": "prod-security",
                    "backend": "gitlab_instance_variables",
                    "gitlab_variable_key": "MCP_OAUTH_CACHE",
                    "gitlab_token_env": "GITLAB_TOKEN_ADMIN",
                    "gitlab_api_url": "https://gitlab.example.com/api/v4",
                }
            },
        )

        assert error is None
        assert settings is not None
        assert settings.backend == "gitlab_instance_variables"
        assert settings.gitlab_variable_key == "MCP_OAUTH_CACHE"
        assert settings.gitlab_token_env == "GITLAB_TOKEN_ADMIN"
        assert settings.gitlab_api_url == "https://gitlab.example.com/api/v4"
        assert settings.gitlab_environment_scope is None

    def test_coerce_oauth_cache_settings_sets_gitlab_instance_defaults(self):
        """OAuth cache settings should apply default gitlab_instance_variables optional values."""
        settings, error = cli_module._coerce_oauth_cache_settings(
            auth_type="oauth_client_credentials",
            auth_value={
                "cache": {
                    "persistent": True,
                    "namespace": "prod-security",
                    "backend": "gitlab_instance_variables",
                    "gitlab_variable_key": "MCP_OAUTH_CACHE",
                }
            },
        )

        assert error is None
        assert settings is not None
        assert settings.gitlab_token_env == "GITLAB_TOKEN"
        assert settings.gitlab_api_url is None
        assert settings.gitlab_environment_scope is None

    def test_coerce_oauth_cache_settings_accepts_github_backend(self):
        """OAuth cache settings should accept github_actions_variables backend with required fields."""
        settings, error = cli_module._coerce_oauth_cache_settings(
            auth_type="oauth_client_credentials",
            auth_value={
                "cache": {
                    "persistent": True,
                    "namespace": "prod-security",
                    "backend": "github_actions_variables",
                    "github_repository": "ogulcanaydogan/mcp-security-scanner",
                    "github_variable_name": "MCP_OAUTH_CACHE",
                    "github_token_env": "GITHUB_TOKEN_PROD",
                    "github_api_url": "https://api.github.com",
                }
            },
        )

        assert error is None
        assert settings is not None
        assert settings.backend == "github_actions_variables"
        assert settings.github_repository == "ogulcanaydogan/mcp-security-scanner"
        assert settings.github_variable_name == "MCP_OAUTH_CACHE"
        assert settings.github_token_env == "GITHUB_TOKEN_PROD"
        assert settings.github_api_url == "https://api.github.com"

    def test_coerce_oauth_cache_settings_sets_github_defaults(self):
        """OAuth cache settings should apply default github_actions_variables optional values."""
        settings, error = cli_module._coerce_oauth_cache_settings(
            auth_type="oauth_client_credentials",
            auth_value={
                "cache": {
                    "persistent": True,
                    "namespace": "prod-security",
                    "backend": "github_actions_variables",
                    "github_repository": "ogulcanaydogan/mcp-security-scanner",
                    "github_variable_name": "MCP_OAUTH_CACHE",
                }
            },
        )

        assert error is None
        assert settings is not None
        assert settings.github_token_env == "GITHUB_TOKEN"
        assert settings.github_api_url is None

    def test_coerce_oauth_cache_settings_accepts_github_environment_backend(self):
        """OAuth cache settings should accept github_environment_variables backend with required fields."""
        settings, error = cli_module._coerce_oauth_cache_settings(
            auth_type="oauth_client_credentials",
            auth_value={
                "cache": {
                    "persistent": True,
                    "namespace": "prod-security",
                    "backend": "github_environment_variables",
                    "github_repository": "ogulcanaydogan/mcp-security-scanner",
                    "github_environment_name": "production",
                    "github_variable_name": "MCP_OAUTH_CACHE",
                    "github_token_env": "GITHUB_TOKEN_PROD",
                    "github_api_url": "https://api.github.com",
                }
            },
        )

        assert error is None
        assert settings is not None
        assert settings.backend == "github_environment_variables"
        assert settings.github_repository == "ogulcanaydogan/mcp-security-scanner"
        assert settings.github_environment_name == "production"
        assert settings.github_variable_name == "MCP_OAUTH_CACHE"
        assert settings.github_token_env == "GITHUB_TOKEN_PROD"
        assert settings.github_api_url == "https://api.github.com"

    def test_coerce_oauth_cache_settings_sets_github_environment_defaults(self):
        """OAuth cache settings should apply default github_environment_variables optional values."""
        settings, error = cli_module._coerce_oauth_cache_settings(
            auth_type="oauth_client_credentials",
            auth_value={
                "cache": {
                    "persistent": True,
                    "namespace": "prod-security",
                    "backend": "github_environment_variables",
                    "github_repository": "ogulcanaydogan/mcp-security-scanner",
                    "github_environment_name": "production",
                    "github_variable_name": "MCP_OAUTH_CACHE",
                }
            },
        )

        assert error is None
        assert settings is not None
        assert settings.github_token_env == "GITHUB_TOKEN"
        assert settings.github_api_url is None

    def test_coerce_oauth_cache_settings_accepts_github_organization_backend(self):
        """OAuth cache settings should accept github_organization_variables backend with required fields."""
        settings, error = cli_module._coerce_oauth_cache_settings(
            auth_type="oauth_client_credentials",
            auth_value={
                "cache": {
                    "persistent": True,
                    "namespace": "prod-security",
                    "backend": "github_organization_variables",
                    "github_organization": "ogulcanaydogan",
                    "github_variable_name": "MCP_OAUTH_CACHE",
                    "github_token_env": "GITHUB_TOKEN_PROD",
                    "github_api_url": "https://api.github.com",
                }
            },
        )

        assert error is None
        assert settings is not None
        assert settings.backend == "github_organization_variables"
        assert settings.github_organization == "ogulcanaydogan"
        assert settings.github_variable_name == "MCP_OAUTH_CACHE"
        assert settings.github_token_env == "GITHUB_TOKEN_PROD"
        assert settings.github_api_url == "https://api.github.com"

    def test_coerce_oauth_cache_settings_sets_github_organization_defaults(self):
        """OAuth cache settings should apply default github_organization_variables optional values."""
        settings, error = cli_module._coerce_oauth_cache_settings(
            auth_type="oauth_client_credentials",
            auth_value={
                "cache": {
                    "persistent": True,
                    "namespace": "prod-security",
                    "backend": "github_organization_variables",
                    "github_organization": "ogulcanaydogan",
                    "github_variable_name": "MCP_OAUTH_CACHE",
                }
            },
        )

        assert error is None
        assert settings is not None
        assert settings.github_token_env == "GITHUB_TOKEN"
        assert settings.github_api_url is None

    def test_coerce_oauth_cache_settings_accepts_consul_backend(self):
        """OAuth cache settings should accept consul_kv backend with required fields."""
        settings, error = cli_module._coerce_oauth_cache_settings(
            auth_type="oauth_client_credentials",
            auth_value={
                "cache": {
                    "persistent": True,
                    "namespace": "prod-security",
                    "backend": "consul_kv",
                    "consul_key_path": "mcp/security/oauth/cache",
                    "consul_token_env": "CONSUL_HTTP_TOKEN_PROD",
                    "consul_api_url": "https://consul.example.com",
                }
            },
        )

        assert error is None
        assert settings is not None
        assert settings.backend == "consul_kv"
        assert settings.consul_key_path == "mcp/security/oauth/cache"
        assert settings.consul_token_env == "CONSUL_HTTP_TOKEN_PROD"
        assert settings.consul_api_url == "https://consul.example.com"

    def test_coerce_oauth_cache_settings_sets_consul_defaults(self):
        """OAuth cache settings should apply default consul_kv optional values."""
        settings, error = cli_module._coerce_oauth_cache_settings(
            auth_type="oauth_client_credentials",
            auth_value={
                "cache": {
                    "persistent": True,
                    "namespace": "prod-security",
                    "backend": "consul_kv",
                    "consul_key_path": "mcp/security/oauth/cache",
                }
            },
        )

        assert error is None
        assert settings is not None
        assert settings.consul_token_env == "CONSUL_HTTP_TOKEN"
        assert settings.consul_api_url is None

    def test_coerce_oauth_cache_settings_accepts_redis_backend(self):
        """OAuth cache settings should accept redis_kv backend with required fields."""
        settings, error = cli_module._coerce_oauth_cache_settings(
            auth_type="oauth_client_credentials",
            auth_value={
                "cache": {
                    "persistent": True,
                    "namespace": "prod-security",
                    "backend": "redis_kv",
                    "redis_key": "mcp/security/oauth/cache",
                    "redis_url": "rediss://redis.example.com:6380/0",
                    "redis_password_env": "REDIS_PASSWORD_PROD",
                }
            },
        )

        assert error is None
        assert settings is not None
        assert settings.backend == "redis_kv"
        assert settings.redis_key == "mcp/security/oauth/cache"
        assert settings.redis_url == "rediss://redis.example.com:6380/0"
        assert settings.redis_password_env == "REDIS_PASSWORD_PROD"

    def test_coerce_oauth_cache_settings_sets_redis_defaults(self):
        """OAuth cache settings should apply default redis_kv optional values."""
        settings, error = cli_module._coerce_oauth_cache_settings(
            auth_type="oauth_client_credentials",
            auth_value={
                "cache": {
                    "persistent": True,
                    "namespace": "prod-security",
                    "backend": "redis_kv",
                    "redis_key": "mcp/security/oauth/cache",
                }
            },
        )

        assert error is None
        assert settings is not None
        assert settings.redis_url is None
        assert settings.redis_password_env == "REDIS_PASSWORD"

    def test_coerce_oauth_cache_settings_accepts_cloudflare_backend(self):
        """OAuth cache settings should accept cloudflare_kv backend with required fields."""
        settings, error = cli_module._coerce_oauth_cache_settings(
            auth_type="oauth_client_credentials",
            auth_value={
                "cache": {
                    "persistent": True,
                    "namespace": "prod-security",
                    "backend": "cloudflare_kv",
                    "cf_account_id": "1234567890abcdef1234567890abcdef",
                    "cf_namespace_id": "fedcba0987654321fedcba0987654321",
                    "cf_kv_key": "mcp/security/oauth/cache",
                    "cf_api_token_env": "CLOUDFLARE_API_TOKEN_PROD",
                    "cf_api_url": "https://api.cloudflare.com/client/v4",
                }
            },
        )

        assert error is None
        assert settings is not None
        assert settings.backend == "cloudflare_kv"
        assert settings.cf_account_id == "1234567890abcdef1234567890abcdef"
        assert settings.cf_namespace_id == "fedcba0987654321fedcba0987654321"
        assert settings.cf_kv_key == "mcp/security/oauth/cache"
        assert settings.cf_api_token_env == "CLOUDFLARE_API_TOKEN_PROD"
        assert settings.cf_api_url == "https://api.cloudflare.com/client/v4"

    def test_coerce_oauth_cache_settings_sets_cloudflare_defaults(self):
        """OAuth cache settings should apply default cloudflare_kv optional values."""
        settings, error = cli_module._coerce_oauth_cache_settings(
            auth_type="oauth_client_credentials",
            auth_value={
                "cache": {
                    "persistent": True,
                    "namespace": "prod-security",
                    "backend": "cloudflare_kv",
                    "cf_account_id": "1234567890abcdef1234567890abcdef",
                    "cf_namespace_id": "fedcba0987654321fedcba0987654321",
                    "cf_kv_key": "mcp/security/oauth/cache",
                }
            },
        )

        assert error is None
        assert settings is not None
        assert settings.cf_api_token_env == "CLOUDFLARE_API_TOKEN"
        assert settings.cf_api_url == "https://api.cloudflare.com/client/v4"

    def test_coerce_oauth_cache_settings_accepts_etcd_backend(self):
        """OAuth cache settings should accept etcd_kv backend with required fields."""
        settings, error = cli_module._coerce_oauth_cache_settings(
            auth_type="oauth_client_credentials",
            auth_value={
                "cache": {
                    "persistent": True,
                    "namespace": "prod-security",
                    "backend": "etcd_kv",
                    "etcd_key": "mcp/security/oauth/cache",
                    "etcd_api_url": "https://etcd.example.com:2379",
                    "etcd_token_env": "ETCD_TOKEN_PROD",
                }
            },
        )

        assert error is None
        assert settings is not None
        assert settings.backend == "etcd_kv"
        assert settings.etcd_key == "mcp/security/oauth/cache"
        assert settings.etcd_api_url == "https://etcd.example.com:2379"
        assert settings.etcd_token_env == "ETCD_TOKEN_PROD"

    def test_coerce_oauth_cache_settings_sets_etcd_defaults(self):
        """OAuth cache settings should apply default etcd_kv optional values."""
        settings, error = cli_module._coerce_oauth_cache_settings(
            auth_type="oauth_client_credentials",
            auth_value={
                "cache": {
                    "persistent": True,
                    "namespace": "prod-security",
                    "backend": "etcd_kv",
                    "etcd_key": "mcp/security/oauth/cache",
                }
            },
        )

        assert error is None
        assert settings is not None
        assert settings.etcd_api_url == "http://127.0.0.1:2379"
        assert settings.etcd_token_env == "ETCD_TOKEN"

    def test_coerce_oauth_cache_settings_accepts_postgres_backend(self):
        """OAuth cache settings should accept postgres_kv backend with required fields."""
        settings, error = cli_module._coerce_oauth_cache_settings(
            auth_type="oauth_client_credentials",
            auth_value={
                "cache": {
                    "persistent": True,
                    "namespace": "prod-security",
                    "backend": "postgres_kv",
                    "postgres_cache_key": "mcp/security/oauth/cache",
                    "postgres_dsn_env": "POSTGRES_DSN_PROD",
                }
            },
        )

        assert error is None
        assert settings is not None
        assert settings.backend == "postgres_kv"
        assert settings.postgres_cache_key == "mcp/security/oauth/cache"
        assert settings.postgres_dsn_env == "POSTGRES_DSN_PROD"

    def test_coerce_oauth_cache_settings_sets_postgres_defaults(self):
        """OAuth cache settings should apply default postgres_kv optional values."""
        settings, error = cli_module._coerce_oauth_cache_settings(
            auth_type="oauth_client_credentials",
            auth_value={
                "cache": {
                    "persistent": True,
                    "namespace": "prod-security",
                    "backend": "postgres_kv",
                    "postgres_cache_key": "mcp/security/oauth/cache",
                }
            },
        )

        assert error is None
        assert settings is not None
        assert settings.postgres_dsn_env == "POSTGRES_DSN"

    def test_coerce_oauth_cache_settings_accepts_mysql_backend(self):
        """OAuth cache settings should accept mysql_kv backend with required fields."""
        settings, error = cli_module._coerce_oauth_cache_settings(
            auth_type="oauth_client_credentials",
            auth_value={
                "cache": {
                    "persistent": True,
                    "namespace": "prod-security",
                    "backend": "mysql_kv",
                    "mysql_cache_key": "mcp/security/oauth/cache",
                    "mysql_dsn_env": "MYSQL_DSN_PROD",
                }
            },
        )

        assert error is None
        assert settings is not None
        assert settings.backend == "mysql_kv"
        assert settings.mysql_cache_key == "mcp/security/oauth/cache"
        assert settings.mysql_dsn_env == "MYSQL_DSN_PROD"

    def test_coerce_oauth_cache_settings_sets_mysql_defaults(self):
        """OAuth cache settings should apply default mysql_kv optional values."""
        settings, error = cli_module._coerce_oauth_cache_settings(
            auth_type="oauth_client_credentials",
            auth_value={
                "cache": {
                    "persistent": True,
                    "namespace": "prod-security",
                    "backend": "mysql_kv",
                    "mysql_cache_key": "mcp/security/oauth/cache",
                }
            },
        )

        assert error is None
        assert settings is not None
        assert settings.mysql_dsn_env == "MYSQL_DSN"

    def test_coerce_oauth_cache_settings_accepts_mongo_backend(self):
        """OAuth cache settings should accept mongo_kv backend with required fields."""
        settings, error = cli_module._coerce_oauth_cache_settings(
            auth_type="oauth_client_credentials",
            auth_value={
                "cache": {
                    "persistent": True,
                    "namespace": "prod-security",
                    "backend": "mongo_kv",
                    "mongo_cache_key": "mcp/security/oauth/cache",
                    "mongo_dsn_env": "MONGODB_URI_PROD",
                }
            },
        )

        assert error is None
        assert settings is not None
        assert settings.backend == "mongo_kv"
        assert settings.mongo_cache_key == "mcp/security/oauth/cache"
        assert settings.mongo_dsn_env == "MONGODB_URI_PROD"

    def test_coerce_oauth_cache_settings_sets_mongo_defaults(self):
        """OAuth cache settings should apply default mongo_kv optional values."""
        settings, error = cli_module._coerce_oauth_cache_settings(
            auth_type="oauth_client_credentials",
            auth_value={
                "cache": {
                    "persistent": True,
                    "namespace": "prod-security",
                    "backend": "mongo_kv",
                    "mongo_cache_key": "mcp/security/oauth/cache",
                }
            },
        )

        assert error is None
        assert settings is not None
        assert settings.mongo_dsn_env == "MONGODB_URI"

    def test_coerce_oauth_cache_settings_accepts_dynamodb_backend(self):
        """OAuth cache settings should accept dynamodb_kv backend with required fields."""
        settings, error = cli_module._coerce_oauth_cache_settings(
            auth_type="oauth_client_credentials",
            auth_value={
                "cache": {
                    "persistent": True,
                    "namespace": "prod-security",
                    "backend": "dynamodb_kv",
                    "dynamodb_cache_key": "mcp/security/oauth/cache",
                    "aws_region": "eu-west-2",
                    "aws_endpoint_url": "https://dynamodb.eu-west-2.amazonaws.com",
                }
            },
        )

        assert error is None
        assert settings is not None
        assert settings.backend == "dynamodb_kv"
        assert settings.dynamodb_cache_key == "mcp/security/oauth/cache"
        assert settings.aws_region == "eu-west-2"
        assert settings.aws_endpoint_url == "https://dynamodb.eu-west-2.amazonaws.com"

    def test_coerce_oauth_cache_settings_sets_dynamodb_defaults(self):
        """OAuth cache settings should apply dynamodb_kv optional defaults."""
        settings, error = cli_module._coerce_oauth_cache_settings(
            auth_type="oauth_client_credentials",
            auth_value={
                "cache": {
                    "persistent": True,
                    "namespace": "prod-security",
                    "backend": "dynamodb_kv",
                    "dynamodb_cache_key": "mcp/security/oauth/cache",
                }
            },
        )

        assert error is None
        assert settings is not None
        assert settings.aws_region is None
        assert settings.aws_endpoint_url is None

    def test_coerce_oauth_cache_settings_accepts_s3_object_backend(self):
        """OAuth cache settings should accept s3_object_kv backend with required fields."""
        settings, error = cli_module._coerce_oauth_cache_settings(
            auth_type="oauth_client_credentials",
            auth_value={
                "cache": {
                    "persistent": True,
                    "namespace": "prod-security",
                    "backend": "s3_object_kv",
                    "s3_bucket": "mcp-security-cache-prod",
                    "s3_object_key": "mcp/security/oauth/cache.json",
                    "aws_region": "eu-west-2",
                    "aws_endpoint_url": "https://s3.eu-west-2.amazonaws.com",
                }
            },
        )

        assert error is None
        assert settings is not None
        assert settings.backend == "s3_object_kv"
        assert settings.s3_bucket == "mcp-security-cache-prod"
        assert settings.s3_object_key == "mcp/security/oauth/cache.json"
        assert settings.aws_region == "eu-west-2"
        assert settings.aws_endpoint_url == "https://s3.eu-west-2.amazonaws.com"

    def test_coerce_oauth_cache_settings_sets_s3_object_defaults(self):
        """OAuth cache settings should apply s3_object_kv optional defaults."""
        settings, error = cli_module._coerce_oauth_cache_settings(
            auth_type="oauth_client_credentials",
            auth_value={
                "cache": {
                    "persistent": True,
                    "namespace": "prod-security",
                    "backend": "s3_object_kv",
                    "s3_bucket": "mcp-security-cache-prod",
                    "s3_object_key": "mcp/security/oauth/cache.json",
                }
            },
        )

        assert error is None
        assert settings is not None
        assert settings.aws_region is None
        assert settings.aws_endpoint_url is None

    def test_coerce_oauth_cache_settings_rejects_backend_contract_drift(self, monkeypatch):
        """OAuth cache settings should fail closed when backend contract maps are inconsistent."""
        monkeypatch.setattr(
            cli_module,
            "_oauth_cache_backend_contract_error",
            lambda: "auth.cache backend contract is inconsistent (test drift).",
        )

        settings, error = cli_module._coerce_oauth_cache_settings(
            auth_type="oauth_client_credentials",
            auth_value={"cache": {"backend": "local"}},
        )

        assert settings is None
        assert error == "auth.cache backend contract is inconsistent (test drift)."

    @pytest.mark.parametrize(
        ("cache_value", "expected_error"),
        [
            (
                {"backend": "invalid"},
                "auth.cache.backend must be one of",
            ),
            (
                {"backend": "aws_secrets_manager"},
                "auth.cache.aws_secret_id is required",
            ),
            (
                {"backend": "local", "aws_secret_id": "mcp-security/oauth-cache"},
                "auth.cache.aws_secret_id, auth.cache.aws_ssm_parameter_name",
            ),
            (
                {"backend": "aws_ssm_parameter_store"},
                "auth.cache.aws_ssm_parameter_name is required",
            ),
            (
                {"backend": "local", "aws_ssm_parameter_name": "/mcp-security/oauth-cache"},
                "auth.cache.aws_secret_id, auth.cache.aws_ssm_parameter_name",
            ),
            (
                {
                    "backend": "aws_secrets_manager",
                    "aws_secret_id": "mcp-security/oauth-cache",
                    "aws_endpoint_url": "ftp://invalid",
                },
                "auth.cache.aws_endpoint_url must be a valid http/https URL.",
            ),
            (
                {"backend": "gcp_secret_manager"},
                "auth.cache.gcp_secret_name is required",
            ),
            (
                {"backend": "local", "gcp_secret_name": "projects/demo/secrets/cache"},
                "only supported when auth.cache.backend='gcp_secret_manager'",
            ),
            (
                {"backend": "gcp_secret_manager", "gcp_secret_name": "invalid"},
                "auth.cache.gcp_secret_name must match",
            ),
            (
                {
                    "backend": "gcp_secret_manager",
                    "gcp_secret_name": "projects/demo/secrets/cache",
                    "gcp_endpoint_url": "ftp://invalid",
                },
                "auth.cache.gcp_endpoint_url must be a valid http/https URL.",
            ),
            (
                {"backend": "azure_key_vault"},
                "auth.cache.azure_vault_url is required",
            ),
            (
                {
                    "backend": "azure_key_vault",
                    "azure_vault_url": "http://mcp-security.vault.azure.net",
                    "azure_secret_name": "mcp-security-oauth-cache",
                },
                "auth.cache.azure_vault_url must be a valid https://<name>.vault.azure.net URL.",
            ),
            (
                {
                    "backend": "azure_key_vault",
                    "azure_vault_url": "https://example.com",
                    "azure_secret_name": "mcp-security-oauth-cache",
                },
                "auth.cache.azure_vault_url must be a valid https://<name>.vault.azure.net URL.",
            ),
            (
                {
                    "backend": "azure_key_vault",
                    "azure_vault_url": "https://mcp-security.vault.azure.net",
                },
                "auth.cache.azure_secret_name is required",
            ),
            (
                {
                    "backend": "azure_key_vault",
                    "azure_vault_url": "https://mcp-security.vault.azure.net",
                    "azure_secret_name": "invalid/name",
                },
                "auth.cache.azure_secret_name must match Azure secret naming rules",
            ),
            (
                {"backend": "local", "azure_vault_url": "https://mcp-security.vault.azure.net"},
                "only supported when auth.cache.backend='azure_key_vault'",
            ),
            (
                {
                    "backend": "azure_key_vault",
                    "azure_vault_url": "https://mcp-security.vault.azure.net",
                    "azure_secret_name": "mcp-security-oauth-cache",
                    "azure_secret_version": "",
                },
                "auth.cache.azure_secret_version must be a non-empty string when provided.",
            ),
            (
                {"backend": "hashicorp_vault"},
                "auth.cache.vault_url is required",
            ),
            (
                {
                    "backend": "hashicorp_vault",
                    "vault_url": "ftp://vault.example.com",
                    "vault_secret_path": "kv/mcp-security/oauth-cache",
                },
                "auth.cache.vault_url must be a valid http/https URL.",
            ),
            (
                {
                    "backend": "hashicorp_vault",
                    "vault_url": "https://vault.example.com",
                },
                "auth.cache.vault_secret_path is required",
            ),
            (
                {
                    "backend": "hashicorp_vault",
                    "vault_url": "https://vault.example.com",
                    "vault_secret_path": "invalid path",
                },
                "auth.cache.vault_secret_path must be a valid Vault KV path.",
            ),
            (
                {"backend": "local", "vault_url": "https://vault.example.com"},
                "only supported when auth.cache.backend='hashicorp_vault'",
            ),
            (
                {"backend": "kubernetes_secrets"},
                "auth.cache.k8s_secret_namespace is required",
            ),
            (
                {"backend": "kubernetes_secrets", "k8s_secret_namespace": "mcp-security"},
                "auth.cache.k8s_secret_name is required",
            ),
            (
                {
                    "backend": "kubernetes_secrets",
                    "k8s_secret_namespace": "INVALID/namespace",
                    "k8s_secret_name": "oauth-cache",
                },
                "auth.cache.k8s_secret_namespace must match Kubernetes DNS subdomain naming rules.",
            ),
            (
                {"backend": "local", "k8s_secret_name": "oauth-cache"},
                "only supported when auth.cache.backend='kubernetes_secrets'",
            ),
            (
                {"backend": "oci_vault"},
                "auth.cache.oci_secret_ocid is required",
            ),
            (
                {"backend": "oci_vault", "oci_secret_ocid": "invalid"},
                "auth.cache.oci_secret_ocid must be a valid OCI OCID.",
            ),
            (
                {
                    "backend": "oci_vault",
                    "oci_secret_ocid": "ocid1.secret.oc1.iad.exampleuniqueid1234567890",
                    "oci_endpoint_url": "ftp://invalid",
                },
                "auth.cache.oci_endpoint_url must be a valid http/https URL.",
            ),
            (
                {"backend": "local", "oci_secret_ocid": "ocid1.secret.oc1.iad.exampleuniqueid1234567890"},
                "only supported when auth.cache.backend='oci_vault'",
            ),
            (
                {"backend": "doppler_secrets"},
                "auth.cache.doppler_project is required",
            ),
            (
                {"backend": "doppler_secrets", "doppler_project": "security-platform"},
                "auth.cache.doppler_config is required",
            ),
            (
                {
                    "backend": "doppler_secrets",
                    "doppler_project": "security-platform",
                    "doppler_config": "prd",
                },
                "auth.cache.doppler_secret_name is required",
            ),
            (
                {
                    "backend": "doppler_secrets",
                    "doppler_project": "security-platform",
                    "doppler_config": "prd",
                    "doppler_secret_name": "MCP_OAUTH_CACHE",
                    "doppler_token_env": "9INVALID",
                },
                "auth.cache.doppler_token_env must be a valid environment variable name.",
            ),
            (
                {
                    "backend": "doppler_secrets",
                    "doppler_project": "security-platform",
                    "doppler_config": "prd",
                    "doppler_secret_name": "MCP_OAUTH_CACHE",
                    "doppler_api_url": "http://api.doppler.com",
                },
                "auth.cache.doppler_api_url must be a valid https URL.",
            ),
            (
                {"backend": "local", "doppler_project": "security-platform"},
                "only supported when auth.cache.backend='doppler_secrets'",
            ),
            (
                {"backend": "onepassword_connect"},
                "auth.cache.op_connect_host is required",
            ),
            (
                {"backend": "onepassword_connect", "op_connect_host": "http://op-connect.example.com"},
                "auth.cache.op_connect_host must be a valid https URL.",
            ),
            (
                {
                    "backend": "onepassword_connect",
                    "op_connect_host": "https://op-connect.example.com",
                },
                "auth.cache.op_vault_id is required",
            ),
            (
                {
                    "backend": "onepassword_connect",
                    "op_connect_host": "https://op-connect.example.com",
                    "op_vault_id": "vault-123",
                },
                "auth.cache.op_item_id is required",
            ),
            (
                {
                    "backend": "onepassword_connect",
                    "op_connect_host": "https://op-connect.example.com",
                    "op_vault_id": "vault-123",
                    "op_item_id": "item-456",
                    "op_connect_token_env": "9INVALID",
                },
                "auth.cache.op_connect_token_env must be a valid environment variable name.",
            ),
            (
                {"backend": "local", "op_connect_host": "https://op-connect.example.com"},
                "only supported when auth.cache.backend='onepassword_connect'",
            ),
            (
                {"backend": "bitwarden_secrets"},
                "auth.cache.bw_secret_id is required",
            ),
            (
                {"backend": "bitwarden_secrets", "bw_secret_id": "invalid"},
                "auth.cache.bw_secret_id must be a valid Bitwarden secret identifier.",
            ),
            (
                {
                    "backend": "bitwarden_secrets",
                    "bw_secret_id": "11111111-2222-3333-4444-555555555555",
                    "bw_access_token_env": "9INVALID",
                },
                "auth.cache.bw_access_token_env must be a valid environment variable name.",
            ),
            (
                {
                    "backend": "bitwarden_secrets",
                    "bw_secret_id": "11111111-2222-3333-4444-555555555555",
                    "bw_api_url": "http://api.bitwarden.com",
                },
                "auth.cache.bw_api_url must be a valid https URL.",
            ),
            (
                {"backend": "local", "bw_secret_id": "11111111-2222-3333-4444-555555555555"},
                "only supported when auth.cache.backend='bitwarden_secrets'",
            ),
            (
                {"backend": "infisical_secrets"},
                "auth.cache.infisical_project_id is required",
            ),
            (
                {"backend": "infisical_secrets", "infisical_project_id": "workspace-123"},
                "auth.cache.infisical_environment is required",
            ),
            (
                {
                    "backend": "infisical_secrets",
                    "infisical_project_id": "workspace/123",
                    "infisical_environment": "prod",
                    "infisical_secret_name": "MCP_OAUTH_CACHE",
                },
                "auth.cache.infisical_project_id must match Infisical identifier rules",
            ),
            (
                {
                    "backend": "infisical_secrets",
                    "infisical_project_id": "workspace-123",
                    "infisical_environment": "prod",
                },
                "auth.cache.infisical_secret_name is required",
            ),
            (
                {
                    "backend": "infisical_secrets",
                    "infisical_project_id": "workspace-123",
                    "infisical_environment": "prod",
                    "infisical_secret_name": "MCP_OAUTH_CACHE",
                    "infisical_token_env": "9INVALID",
                },
                "auth.cache.infisical_token_env must be a valid environment variable name.",
            ),
            (
                {
                    "backend": "infisical_secrets",
                    "infisical_project_id": "workspace-123",
                    "infisical_environment": "prod",
                    "infisical_secret_name": "MCP_OAUTH_CACHE",
                    "infisical_api_url": "http://app.infisical.com/api",
                },
                "auth.cache.infisical_api_url must be a valid https URL.",
            ),
            (
                {"backend": "local", "infisical_project_id": "workspace-123"},
                "only supported when auth.cache.backend='infisical_secrets'",
            ),
            (
                {"backend": "akeyless_secrets"},
                "auth.cache.akeyless_secret_name is required",
            ),
            (
                {
                    "backend": "akeyless_secrets",
                    "akeyless_secret_name": "/prod/mcp/oauth cache",
                },
                "auth.cache.akeyless_secret_name must match Akeyless secret naming rules",
            ),
            (
                {
                    "backend": "akeyless_secrets",
                    "akeyless_secret_name": "/prod/mcp/oauth_cache",
                    "akeyless_token_env": "9INVALID",
                },
                "auth.cache.akeyless_token_env must be a valid environment variable name.",
            ),
            (
                {
                    "backend": "akeyless_secrets",
                    "akeyless_secret_name": "/prod/mcp/oauth_cache",
                    "akeyless_api_url": "http://api.akeyless.io",
                },
                "auth.cache.akeyless_api_url must be a valid https URL.",
            ),
            (
                {"backend": "local", "akeyless_secret_name": "/prod/mcp/oauth_cache"},
                "only supported when auth.cache.backend='akeyless_secrets'",
            ),
            (
                {"backend": "gitlab_variables"},
                "auth.cache.gitlab_project_id is required",
            ),
            (
                {"backend": "gitlab_variables", "gitlab_project_id": "project/path"},
                "auth.cache.gitlab_project_id must be a numeric GitLab project ID.",
            ),
            (
                {"backend": "gitlab_variables", "gitlab_project_id": "12345"},
                "auth.cache.gitlab_variable_key is required",
            ),
            (
                {
                    "backend": "gitlab_variables",
                    "gitlab_project_id": "12345",
                    "gitlab_variable_key": "INVALID KEY",
                },
                "auth.cache.gitlab_variable_key must match environment-style key naming rules.",
            ),
            (
                {
                    "backend": "gitlab_variables",
                    "gitlab_project_id": "12345",
                    "gitlab_variable_key": "MCP_OAUTH_CACHE",
                    "gitlab_environment_scope": "   ",
                },
                "auth.cache.gitlab_environment_scope must be a non-empty string when provided.",
            ),
            (
                {
                    "backend": "gitlab_variables",
                    "gitlab_project_id": "12345",
                    "gitlab_variable_key": "MCP_OAUTH_CACHE",
                    "gitlab_token_env": "9INVALID",
                },
                "auth.cache.gitlab_token_env must be a valid environment variable name.",
            ),
            (
                {
                    "backend": "gitlab_variables",
                    "gitlab_project_id": "12345",
                    "gitlab_variable_key": "MCP_OAUTH_CACHE",
                    "gitlab_api_url": "http://gitlab.example.com/api/v4",
                },
                "auth.cache.gitlab_api_url must be a valid https URL.",
            ),
            (
                {"backend": "local", "gitlab_project_id": "12345"},
                "auth.cache.backend is 'gitlab_variables', 'gitlab_group_variables', or " "'gitlab_instance_variables'",
            ),
            (
                {"backend": "local", "gitlab_environment_scope": "production"},
                "auth.cache.backend is 'gitlab_variables', 'gitlab_group_variables', or " "'gitlab_instance_variables'",
            ),
            (
                {"backend": "gitlab_group_variables"},
                "auth.cache.gitlab_group_id is required",
            ),
            (
                {"backend": "gitlab_group_variables", "gitlab_group_id": "group/path"},
                "auth.cache.gitlab_group_id must be a numeric GitLab group ID.",
            ),
            (
                {"backend": "gitlab_group_variables", "gitlab_group_id": "67890"},
                "auth.cache.gitlab_variable_key is required",
            ),
            (
                {
                    "backend": "gitlab_group_variables",
                    "gitlab_group_id": "67890",
                    "gitlab_variable_key": "MCP_OAUTH_CACHE",
                    "gitlab_project_id": "12345",
                },
                "auth.cache.gitlab_project_id is only supported when auth.cache.backend='gitlab_variables'.",
            ),
            (
                {"backend": "gitlab_instance_variables"},
                "auth.cache.gitlab_variable_key is required",
            ),
            (
                {
                    "backend": "gitlab_instance_variables",
                    "gitlab_variable_key": "MCP_OAUTH_CACHE",
                    "gitlab_project_id": "12345",
                },
                "auth.cache.gitlab_project_id is only supported when auth.cache.backend='gitlab_variables'.",
            ),
            (
                {
                    "backend": "gitlab_instance_variables",
                    "gitlab_variable_key": "MCP_OAUTH_CACHE",
                    "gitlab_group_id": "67890",
                },
                "auth.cache.gitlab_group_id is only supported when auth.cache.backend='gitlab_group_variables'.",
            ),
            (
                {
                    "backend": "gitlab_instance_variables",
                    "gitlab_variable_key": "MCP_OAUTH_CACHE",
                    "gitlab_environment_scope": "production",
                },
                "auth.cache.gitlab_environment_scope is only supported when auth.cache.backend is "
                "'gitlab_variables' or 'gitlab_group_variables'.",
            ),
            (
                {"backend": "github_actions_variables"},
                "auth.cache.github_repository is required",
            ),
            (
                {"backend": "github_actions_variables", "github_repository": "org"},
                "auth.cache.github_repository must match '<owner>/<repo>' format.",
            ),
            (
                {
                    "backend": "github_actions_variables",
                    "github_repository": "ogulcanaydogan/mcp-security-scanner",
                },
                "auth.cache.github_variable_name is required",
            ),
            (
                {
                    "backend": "github_actions_variables",
                    "github_repository": "ogulcanaydogan/mcp-security-scanner",
                    "github_variable_name": "INVALID KEY",
                },
                "auth.cache.github_variable_name must match environment-style key naming rules.",
            ),
            (
                {
                    "backend": "github_actions_variables",
                    "github_repository": "ogulcanaydogan/mcp-security-scanner",
                    "github_variable_name": "MCP_OAUTH_CACHE",
                    "github_token_env": "9INVALID",
                },
                "auth.cache.github_token_env must be a valid environment variable name.",
            ),
            (
                {
                    "backend": "github_actions_variables",
                    "github_repository": "ogulcanaydogan/mcp-security-scanner",
                    "github_variable_name": "MCP_OAUTH_CACHE",
                    "github_api_url": "http://api.github.com",
                },
                "auth.cache.github_api_url must be a valid https URL.",
            ),
            (
                {"backend": "local", "github_repository": "ogulcanaydogan/mcp-security-scanner"},
                "only supported when auth.cache.backend is 'github_actions_variables' or "
                "'github_environment_variables'",
            ),
            (
                {"backend": "github_environment_variables"},
                "auth.cache.github_repository is required",
            ),
            (
                {
                    "backend": "github_environment_variables",
                    "github_repository": "ogulcanaydogan/mcp-security-scanner",
                },
                "auth.cache.github_variable_name is required",
            ),
            (
                {
                    "backend": "github_environment_variables",
                    "github_repository": "ogulcanaydogan/mcp-security-scanner",
                    "github_variable_name": "MCP_OAUTH_CACHE",
                },
                "auth.cache.github_environment_name is required",
            ),
            (
                {
                    "backend": "github_environment_variables",
                    "github_repository": "ogulcanaydogan/mcp-security-scanner",
                    "github_environment_name": "   ",
                    "github_variable_name": "MCP_OAUTH_CACHE",
                },
                "auth.cache.github_environment_name must be a non-empty string when provided.",
            ),
            (
                {
                    "backend": "github_actions_variables",
                    "github_repository": "ogulcanaydogan/mcp-security-scanner",
                    "github_variable_name": "MCP_OAUTH_CACHE",
                    "github_environment_name": "production",
                },
                "auth.cache.github_environment_name is only supported when auth.cache.backend='github_environment_variables'.",
            ),
            (
                {"backend": "local", "github_environment_name": "production"},
                "auth.cache.github_environment_name is only supported when auth.cache.backend='github_environment_variables'.",
            ),
            (
                {"backend": "github_organization_variables"},
                "auth.cache.github_variable_name is required",
            ),
            (
                {
                    "backend": "github_organization_variables",
                    "github_variable_name": "MCP_OAUTH_CACHE",
                },
                "auth.cache.github_organization is required",
            ),
            (
                {
                    "backend": "github_organization_variables",
                    "github_organization": "invalid/org",
                    "github_variable_name": "MCP_OAUTH_CACHE",
                },
                "auth.cache.github_organization must match GitHub organization naming rules.",
            ),
            (
                {
                    "backend": "github_organization_variables",
                    "github_organization": "ogulcanaydogan",
                    "github_variable_name": "INVALID KEY",
                },
                "auth.cache.github_variable_name must match environment-style key naming rules.",
            ),
            (
                {
                    "backend": "github_organization_variables",
                    "github_organization": "ogulcanaydogan",
                    "github_variable_name": "MCP_OAUTH_CACHE",
                    "github_token_env": "9INVALID",
                },
                "auth.cache.github_token_env must be a valid environment variable name.",
            ),
            (
                {
                    "backend": "github_organization_variables",
                    "github_organization": "ogulcanaydogan",
                    "github_variable_name": "MCP_OAUTH_CACHE",
                    "github_api_url": "http://api.github.com",
                },
                "auth.cache.github_api_url must be a valid https URL.",
            ),
            (
                {
                    "backend": "github_organization_variables",
                    "github_organization": "ogulcanaydogan",
                    "github_variable_name": "MCP_OAUTH_CACHE",
                    "github_repository": "ogulcanaydogan/mcp-security-scanner",
                },
                "auth.cache.github_repository is only supported when auth.cache.backend is "
                "'github_actions_variables' or 'github_environment_variables'.",
            ),
            (
                {"backend": "local", "github_organization": "ogulcanaydogan"},
                "auth.cache.github_organization is only supported when auth.cache.backend='github_organization_variables'.",
            ),
            (
                {"backend": "consul_kv"},
                "auth.cache.consul_key_path is required",
            ),
            (
                {
                    "backend": "consul_kv",
                    "consul_key_path": "invalid key path",
                },
                "auth.cache.consul_key_path must be a valid Consul KV path.",
            ),
            (
                {
                    "backend": "consul_kv",
                    "consul_key_path": "mcp/security/oauth/cache",
                    "consul_token_env": "9INVALID",
                },
                "auth.cache.consul_token_env must be a valid environment variable name.",
            ),
            (
                {
                    "backend": "consul_kv",
                    "consul_key_path": "mcp/security/oauth/cache",
                    "consul_api_url": "ftp://consul.example.com",
                },
                "auth.cache.consul_api_url must be a valid http/https URL.",
            ),
            (
                {"backend": "local", "consul_key_path": "mcp/security/oauth/cache"},
                "only supported when auth.cache.backend='consul_kv'",
            ),
            (
                {"backend": "redis_kv"},
                "auth.cache.redis_key is required",
            ),
            (
                {
                    "backend": "redis_kv",
                    "redis_key": "invalid key",
                },
                "auth.cache.redis_key must be a valid Redis key path.",
            ),
            (
                {
                    "backend": "redis_kv",
                    "redis_key": "mcp/security/oauth/cache",
                    "redis_password_env": "9INVALID",
                },
                "auth.cache.redis_password_env must be a valid environment variable name.",
            ),
            (
                {
                    "backend": "redis_kv",
                    "redis_key": "mcp/security/oauth/cache",
                    "redis_url": "http://redis.example.com:6379/0",
                },
                "auth.cache.redis_url must be a valid redis:// or rediss:// URL.",
            ),
            (
                {"backend": "local", "redis_key": "mcp/security/oauth/cache"},
                "only supported when auth.cache.backend='redis_kv'",
            ),
            (
                {"backend": "cloudflare_kv"},
                "auth.cache.cf_account_id is required",
            ),
            (
                {
                    "backend": "cloudflare_kv",
                    "cf_account_id": "1234567890abcdef1234567890abcdef",
                },
                "auth.cache.cf_namespace_id is required",
            ),
            (
                {
                    "backend": "cloudflare_kv",
                    "cf_account_id": "1234567890abcdef1234567890abcdef",
                    "cf_namespace_id": "fedcba0987654321fedcba0987654321",
                },
                "auth.cache.cf_kv_key is required",
            ),
            (
                {
                    "backend": "cloudflare_kv",
                    "cf_account_id": "invalid id",
                    "cf_namespace_id": "fedcba0987654321fedcba0987654321",
                    "cf_kv_key": "mcp/security/oauth/cache",
                },
                "auth.cache.cf_account_id must match Cloudflare identifier naming rules.",
            ),
            (
                {
                    "backend": "cloudflare_kv",
                    "cf_account_id": "1234567890abcdef1234567890abcdef",
                    "cf_namespace_id": "invalid id",
                    "cf_kv_key": "mcp/security/oauth/cache",
                },
                "auth.cache.cf_namespace_id must match Cloudflare identifier naming rules.",
            ),
            (
                {
                    "backend": "cloudflare_kv",
                    "cf_account_id": "1234567890abcdef1234567890abcdef",
                    "cf_namespace_id": "fedcba0987654321fedcba0987654321",
                    "cf_kv_key": "invalid key",
                },
                "auth.cache.cf_kv_key must be a valid Cloudflare KV key.",
            ),
            (
                {
                    "backend": "cloudflare_kv",
                    "cf_account_id": "1234567890abcdef1234567890abcdef",
                    "cf_namespace_id": "fedcba0987654321fedcba0987654321",
                    "cf_kv_key": "mcp/security/oauth/cache",
                    "cf_api_token_env": "9INVALID",
                },
                "auth.cache.cf_api_token_env must be a valid environment variable name.",
            ),
            (
                {
                    "backend": "cloudflare_kv",
                    "cf_account_id": "1234567890abcdef1234567890abcdef",
                    "cf_namespace_id": "fedcba0987654321fedcba0987654321",
                    "cf_kv_key": "mcp/security/oauth/cache",
                    "cf_api_url": "http://api.cloudflare.com/client/v4",
                },
                "auth.cache.cf_api_url must be a valid https URL.",
            ),
            (
                {"backend": "local", "cf_account_id": "1234567890abcdef1234567890abcdef"},
                "only supported when auth.cache.backend='cloudflare_kv'",
            ),
            (
                {"backend": "etcd_kv"},
                "auth.cache.etcd_key is required",
            ),
            (
                {
                    "backend": "etcd_kv",
                    "etcd_key": "invalid key",
                },
                "auth.cache.etcd_key must be a valid etcd key path.",
            ),
            (
                {
                    "backend": "etcd_kv",
                    "etcd_key": "mcp/security/oauth/cache",
                    "etcd_token_env": "9INVALID",
                },
                "auth.cache.etcd_token_env must be a valid environment variable name.",
            ),
            (
                {
                    "backend": "etcd_kv",
                    "etcd_key": "mcp/security/oauth/cache",
                    "etcd_api_url": "ftp://etcd.example.com:2379",
                },
                "auth.cache.etcd_api_url must be a valid http/https URL.",
            ),
            (
                {"backend": "local", "etcd_key": "mcp/security/oauth/cache"},
                "only supported when auth.cache.backend='etcd_kv'",
            ),
            (
                {"backend": "postgres_kv"},
                "auth.cache.postgres_cache_key is required",
            ),
            (
                {
                    "backend": "postgres_kv",
                    "postgres_cache_key": "invalid key",
                },
                "auth.cache.postgres_cache_key must be a valid Postgres cache key path.",
            ),
            (
                {
                    "backend": "postgres_kv",
                    "postgres_cache_key": "mcp/security/oauth/cache",
                    "postgres_dsn_env": "9INVALID",
                },
                "auth.cache.postgres_dsn_env must be a valid environment variable name.",
            ),
            (
                {"backend": "local", "postgres_cache_key": "mcp/security/oauth/cache"},
                "only supported when auth.cache.backend='postgres_kv'",
            ),
            (
                {"backend": "mysql_kv"},
                "auth.cache.mysql_cache_key is required",
            ),
            (
                {
                    "backend": "mysql_kv",
                    "mysql_cache_key": "invalid key",
                },
                "auth.cache.mysql_cache_key must be a valid MySQL cache key path.",
            ),
            (
                {
                    "backend": "mysql_kv",
                    "mysql_cache_key": "mcp/security/oauth/cache",
                    "mysql_dsn_env": "9INVALID",
                },
                "auth.cache.mysql_dsn_env must be a valid environment variable name.",
            ),
            (
                {"backend": "local", "mysql_cache_key": "mcp/security/oauth/cache"},
                "only supported when auth.cache.backend='mysql_kv'",
            ),
            (
                {"backend": "mongo_kv"},
                "auth.cache.mongo_cache_key is required",
            ),
            (
                {
                    "backend": "mongo_kv",
                    "mongo_cache_key": "invalid key",
                },
                "auth.cache.mongo_cache_key must be a valid MongoDB cache key path.",
            ),
            (
                {
                    "backend": "mongo_kv",
                    "mongo_cache_key": "mcp/security/oauth/cache",
                    "mongo_dsn_env": "9INVALID",
                },
                "auth.cache.mongo_dsn_env must be a valid environment variable name.",
            ),
            (
                {"backend": "local", "mongo_cache_key": "mcp/security/oauth/cache"},
                "only supported when auth.cache.backend='mongo_kv'",
            ),
            (
                {"backend": "dynamodb_kv"},
                "auth.cache.dynamodb_cache_key is required",
            ),
            (
                {
                    "backend": "dynamodb_kv",
                    "dynamodb_cache_key": "invalid key",
                },
                "auth.cache.dynamodb_cache_key must be a valid DynamoDB cache key path.",
            ),
            (
                {
                    "backend": "dynamodb_kv",
                    "dynamodb_cache_key": "mcp/security/oauth/cache",
                    "aws_secret_id": "mcp-security/oauth-cache",
                },
                "auth.cache.aws_secret_id and auth.cache.aws_ssm_parameter_name are only supported when",
            ),
            (
                {"backend": "local", "dynamodb_cache_key": "mcp/security/oauth/cache"},
                "only supported when auth.cache.backend='dynamodb_kv'",
            ),
            (
                {"backend": "s3_object_kv"},
                "auth.cache.s3_bucket is required",
            ),
            (
                {
                    "backend": "s3_object_kv",
                    "s3_bucket": "Invalid Bucket",
                    "s3_object_key": "mcp/security/oauth/cache.json",
                },
                "auth.cache.s3_bucket must be a valid S3 bucket name.",
            ),
            (
                {
                    "backend": "s3_object_kv",
                    "s3_bucket": "mcp-security-cache",
                    "s3_object_key": "invalid\x07key",
                },
                "auth.cache.s3_object_key must be a valid S3 object key path.",
            ),
            (
                {
                    "backend": "s3_object_kv",
                    "s3_bucket": "mcp-security-cache",
                    "s3_object_key": "mcp/security/oauth/cache.json",
                    "aws_ssm_parameter_name": "/mcp/security/oauth/cache",
                },
                "auth.cache.aws_secret_id and auth.cache.aws_ssm_parameter_name are only supported when",
            ),
            (
                {"backend": "local", "s3_bucket": "mcp-security-cache"},
                "only supported when auth.cache.backend='s3_object_kv'",
            ),
        ],
    )
    def test_coerce_oauth_cache_settings_rejects_invalid_aws_shapes(
        self, cache_value: dict[str, object], expected_error: str
    ):
        """OAuth cache settings should validate backend-specific shapes deterministically."""
        settings, error = cli_module._coerce_oauth_cache_settings(
            auth_type="oauth_client_credentials",
            auth_value={"cache": cache_value},
        )
        assert settings is None
        assert error is not None
        assert expected_error in error

    def test_aws_persistent_cache_roundtrip_and_namespace_reuse(self, monkeypatch):
        """AWS Secrets Manager backend should persist and reload cache entries across runs."""
        cli_module._clear_oauth_token_cache()
        monkeypatch.setenv("MCP_OAUTH_CLIENT_ID", "client-aws")
        monkeypatch.setenv("MCP_OAUTH_CLIENT_SECRET", "secret-aws")

        class ResourceNotFoundError(Exception):
            def __init__(self) -> None:
                self.response = {"Error": {"Code": "ResourceNotFoundException"}}
                super().__init__("not found")

        class FakeSecretsManagerClient:
            secret_payload: ClassVar[str | None] = None
            client_kwargs: ClassVar[list[dict[str, str]]] = []

            def __init__(self, **kwargs: str) -> None:
                self.__class__.client_kwargs.append(dict(kwargs))

            def get_secret_value(self, **kwargs: str) -> dict[str, object]:
                assert kwargs["SecretId"] == "mcp-security/oauth-cache"
                if self.__class__.secret_payload is None:
                    raise ResourceNotFoundError()
                return {"SecretString": self.__class__.secret_payload}

            def update_secret(self, **kwargs: str) -> dict[str, object]:
                assert kwargs["SecretId"] == "mcp-security/oauth-cache"
                if self.__class__.secret_payload is None:
                    raise ResourceNotFoundError()
                self.__class__.secret_payload = kwargs["SecretString"]
                return {}

            def create_secret(self, **kwargs: str) -> dict[str, object]:
                assert kwargs["Name"] == "mcp-security/oauth-cache"
                self.__class__.secret_payload = kwargs["SecretString"]
                return {}

        class FakeBoto3Module:
            @staticmethod
            def client(service_name: str, **kwargs: str) -> FakeSecretsManagerClient:
                assert service_name == "secretsmanager"
                return FakeSecretsManagerClient(**kwargs)

        original_import_module = cli_module.importlib.import_module

        def fake_import_module(module_name: str):
            if module_name == "boto3":
                return FakeBoto3Module
            return original_import_module(module_name)

        monkeypatch.setattr(cli_module.importlib, "import_module", fake_import_module)

        call_count = {"value": 0}

        def fake_request(
            *,
            token_url: str,
            client_id: str,
            client_secret: str,
            scope: str | None,
            audience: str | None,
            token_endpoint_auth_method: str,
            timeout_seconds: int,
        ) -> tuple[str | None, float | None, str | None, int | None]:
            del token_url, client_id, client_secret, scope, audience, token_endpoint_auth_method, timeout_seconds
            call_count["value"] += 1
            return "oauth-aws-token", 3600.0, None, 200

        monkeypatch.setattr(cli_module, "_request_oauth_client_credentials_token", fake_request)

        raw_server_config = {
            "transport": "sse",
            "url": "https://example.com/sse",
            "auth": {
                "type": "oauth_client_credentials",
                "token_url": "https://auth.example.com/token",
                "client_id_env": "MCP_OAUTH_CLIENT_ID",
                "client_secret_env": "MCP_OAUTH_CLIENT_SECRET",
                "cache": {
                    "persistent": True,
                    "namespace": "aws-prod",
                    "backend": "aws_secrets_manager",
                    "aws_secret_id": "mcp-security/oauth-cache",
                    "aws_region": "eu-west-1",
                    "aws_endpoint_url": "https://secretsmanager.eu-west-1.amazonaws.com",
                },
            },
        }

        first_config, first_finding = _build_connector_config_from_config_entry(
            server_name="oauth_aws_server",
            raw_server_config=raw_server_config,
            timeout=10,
        )
        assert first_finding is None
        assert first_config is not None
        assert first_config["headers"]["Authorization"] == "Bearer oauth-aws-token"
        assert call_count["value"] == 1

        cli_module._clear_oauth_token_cache()
        second_config, second_finding = _build_connector_config_from_config_entry(
            server_name="oauth_aws_server",
            raw_server_config=raw_server_config,
            timeout=10,
        )
        assert second_finding is None
        assert second_config is not None
        assert second_config["headers"]["Authorization"] == "Bearer oauth-aws-token"
        assert call_count["value"] == 1

        assert FakeSecretsManagerClient.secret_payload is not None
        persisted_payload = json.loads(FakeSecretsManagerClient.secret_payload)
        assert persisted_payload["schema_version"] == cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2
        assert any(
            "region_name" in item and item["region_name"] == "eu-west-1"
            for item in FakeSecretsManagerClient.client_kwargs
        )
        assert any(
            "endpoint_url" in item and item["endpoint_url"] == "https://secretsmanager.eu-west-1.amazonaws.com"
            for item in FakeSecretsManagerClient.client_kwargs
        )

        cli_module._clear_oauth_token_cache()

    def test_aws_persistent_cache_bypasses_provider_errors(self, monkeypatch):
        """AWS backend cache load should bypass provider errors without raising."""

        class AccessDeniedError(Exception):
            def __init__(self) -> None:
                self.response = {"Error": {"Code": "AccessDeniedException"}}
                super().__init__("denied")

        class FakeSecretsManagerClient:
            def get_secret_value(self, **kwargs: str) -> dict[str, object]:
                del kwargs
                raise AccessDeniedError()

        class FakeBoto3Module:
            @staticmethod
            def client(service_name: str, **kwargs: str) -> FakeSecretsManagerClient:
                del kwargs
                assert service_name == "secretsmanager"
                return FakeSecretsManagerClient()

        original_import_module = cli_module.importlib.import_module

        def fake_import_module(module_name: str):
            if module_name == "boto3":
                return FakeBoto3Module
            return original_import_module(module_name)

        monkeypatch.setattr(cli_module.importlib, "import_module", fake_import_module)

        entries = cli_module._load_oauth_persistent_cache_entries(
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="aws-prod",
                backend="aws_secrets_manager",
                aws_secret_id="mcp-security/oauth-cache",
            )
        )
        assert entries == {}

    def test_aws_ssm_persistent_cache_roundtrip_and_namespace_reuse(self, monkeypatch):
        """AWS SSM backend should persist and reload cache entries across runs."""
        cli_module._clear_oauth_token_cache()
        monkeypatch.setenv("MCP_OAUTH_CLIENT_ID", "client-aws-ssm")
        monkeypatch.setenv("MCP_OAUTH_CLIENT_SECRET", "secret-aws-ssm")

        class FakeSSMClient:
            parameter_payload: ClassVar[str] = json.dumps(
                {"schema_version": cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2, "entries": {}},
                sort_keys=True,
            )
            client_kwargs: ClassVar[list[dict[str, str]]] = []

            def __init__(self, **kwargs: str) -> None:
                self.__class__.client_kwargs.append(dict(kwargs))

            def get_parameter(self, **kwargs: object) -> dict[str, object]:
                assert kwargs["Name"] == "/mcp-security/oauth-cache"
                assert kwargs["WithDecryption"] is True
                return {"Parameter": {"Value": self.__class__.parameter_payload}}

            def put_parameter(self, **kwargs: object) -> dict[str, object]:
                assert kwargs["Name"] == "/mcp-security/oauth-cache"
                assert kwargs["Type"] == "SecureString"
                assert kwargs["Overwrite"] is True
                value = kwargs["Value"]
                assert isinstance(value, str)
                self.__class__.parameter_payload = value
                return {}

        class FakeBoto3Module:
            @staticmethod
            def client(service_name: str, **kwargs: str) -> FakeSSMClient:
                assert service_name == "ssm"
                return FakeSSMClient(**kwargs)

        original_import_module = cli_module.importlib.import_module

        def fake_import_module(module_name: str):
            if module_name == "boto3":
                return FakeBoto3Module
            return original_import_module(module_name)

        monkeypatch.setattr(cli_module.importlib, "import_module", fake_import_module)

        call_count = {"value": 0}

        def fake_request(
            *,
            token_url: str,
            client_id: str,
            client_secret: str,
            scope: str | None,
            audience: str | None,
            token_endpoint_auth_method: str,
            timeout_seconds: int,
        ) -> tuple[str | None, float | None, str | None, int | None]:
            del token_url, client_id, client_secret, scope, audience, token_endpoint_auth_method, timeout_seconds
            call_count["value"] += 1
            return "oauth-aws-ssm-token", 3600.0, None, 200

        monkeypatch.setattr(cli_module, "_request_oauth_client_credentials_token", fake_request)

        raw_server_config = {
            "transport": "sse",
            "url": "https://example.com/sse",
            "auth": {
                "type": "oauth_client_credentials",
                "token_url": "https://auth.example.com/token",
                "client_id_env": "MCP_OAUTH_CLIENT_ID",
                "client_secret_env": "MCP_OAUTH_CLIENT_SECRET",
                "cache": {
                    "persistent": True,
                    "namespace": "aws-ssm-prod",
                    "backend": "aws_ssm_parameter_store",
                    "aws_ssm_parameter_name": "/mcp-security/oauth-cache",
                    "aws_region": "eu-west-1",
                    "aws_endpoint_url": "https://ssm.eu-west-1.amazonaws.com",
                },
            },
        }

        first_config, first_finding = _build_connector_config_from_config_entry(
            server_name="oauth_aws_ssm_server",
            raw_server_config=raw_server_config,
            timeout=10,
        )
        assert first_finding is None
        assert first_config is not None
        assert first_config["headers"]["Authorization"] == "Bearer oauth-aws-ssm-token"
        assert call_count["value"] == 1

        cli_module._clear_oauth_token_cache()
        second_config, second_finding = _build_connector_config_from_config_entry(
            server_name="oauth_aws_ssm_server",
            raw_server_config=raw_server_config,
            timeout=10,
        )
        assert second_finding is None
        assert second_config is not None
        assert second_config["headers"]["Authorization"] == "Bearer oauth-aws-ssm-token"
        assert call_count["value"] == 1

        persisted_payload = json.loads(FakeSSMClient.parameter_payload)
        assert persisted_payload["schema_version"] == cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2
        assert any("region_name" in item and item["region_name"] == "eu-west-1" for item in FakeSSMClient.client_kwargs)
        assert any(
            "endpoint_url" in item and item["endpoint_url"] == "https://ssm.eu-west-1.amazonaws.com"
            for item in FakeSSMClient.client_kwargs
        )

        cli_module._clear_oauth_token_cache()

    def test_aws_ssm_persistent_cache_bypasses_provider_errors(self, monkeypatch):
        """AWS SSM backend cache load should bypass provider errors without raising."""

        class AccessDeniedError(Exception):
            def __init__(self) -> None:
                self.response = {"Error": {"Code": "AccessDeniedException"}}
                super().__init__("denied")

        class FakeSSMClient:
            def get_parameter(self, **kwargs: object) -> dict[str, object]:
                del kwargs
                raise AccessDeniedError()

        class FakeBoto3Module:
            @staticmethod
            def client(service_name: str, **kwargs: str) -> FakeSSMClient:
                del kwargs
                assert service_name == "ssm"
                return FakeSSMClient()

        original_import_module = cli_module.importlib.import_module

        def fake_import_module(module_name: str):
            if module_name == "boto3":
                return FakeBoto3Module
            return original_import_module(module_name)

        monkeypatch.setattr(cli_module.importlib, "import_module", fake_import_module)

        entries = cli_module._load_oauth_persistent_cache_entries(
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="aws-ssm-prod",
                backend="aws_ssm_parameter_store",
                aws_ssm_parameter_name="/mcp-security/oauth-cache",
            )
        )
        assert entries == {}

    def test_gcp_persistent_cache_roundtrip_and_namespace_reuse(self, monkeypatch):
        """GCP Secret Manager backend should persist and reload cache entries across runs."""
        cli_module._clear_oauth_token_cache()
        monkeypatch.setenv("MCP_OAUTH_CLIENT_ID", "client-gcp")
        monkeypatch.setenv("MCP_OAUTH_CLIENT_SECRET", "secret-gcp")

        class NotFoundError(Exception):
            pass

        class _Payload:
            def __init__(self, data: bytes) -> None:
                self.data = data

        class _AccessResponse:
            def __init__(self, data: bytes) -> None:
                self.payload = _Payload(data)

        class FakeSecretManagerServiceClient:
            secret_payload: ClassVar[str | None] = None
            client_kwargs: ClassVar[list[dict[str, object]]] = []

            def __init__(self, **kwargs: object) -> None:
                self.__class__.client_kwargs.append(dict(kwargs))

            def access_secret_version(self, request: dict[str, object]) -> _AccessResponse:
                assert request["name"] == "projects/demo-project/secrets/mcp-oauth-cache/versions/latest"
                if self.__class__.secret_payload is None:
                    raise NotFoundError("missing")
                return _AccessResponse(self.__class__.secret_payload.encode("utf-8"))

            def add_secret_version(self, request: dict[str, object]) -> dict[str, object]:
                assert request["parent"] == "projects/demo-project/secrets/mcp-oauth-cache"
                payload = request["payload"]
                assert isinstance(payload, dict)
                data = payload["data"]
                assert isinstance(data, bytes)
                self.__class__.secret_payload = data.decode("utf-8")
                return {}

        class FakeGCPSecretManagerModule:
            SecretManagerServiceClient = FakeSecretManagerServiceClient

        original_import_module = cli_module.importlib.import_module

        def fake_import_module(module_name: str):
            if module_name == "google.cloud.secretmanager":
                return FakeGCPSecretManagerModule
            return original_import_module(module_name)

        monkeypatch.setattr(cli_module.importlib, "import_module", fake_import_module)

        call_count = {"value": 0}

        def fake_request(
            *,
            token_url: str,
            client_id: str,
            client_secret: str,
            scope: str | None,
            audience: str | None,
            token_endpoint_auth_method: str,
            timeout_seconds: int,
        ) -> tuple[str | None, float | None, str | None, int | None]:
            del token_url, client_id, client_secret, scope, audience, token_endpoint_auth_method, timeout_seconds
            call_count["value"] += 1
            return "oauth-gcp-token", 3600.0, None, 200

        monkeypatch.setattr(cli_module, "_request_oauth_client_credentials_token", fake_request)

        raw_server_config = {
            "transport": "sse",
            "url": "https://example.com/sse",
            "auth": {
                "type": "oauth_client_credentials",
                "token_url": "https://auth.example.com/token",
                "client_id_env": "MCP_OAUTH_CLIENT_ID",
                "client_secret_env": "MCP_OAUTH_CLIENT_SECRET",
                "cache": {
                    "persistent": True,
                    "namespace": "gcp-prod",
                    "backend": "gcp_secret_manager",
                    "gcp_secret_name": "projects/demo-project/secrets/mcp-oauth-cache",
                    "gcp_endpoint_url": "https://secretmanager.googleapis.com",
                },
            },
        }

        first_config, first_finding = _build_connector_config_from_config_entry(
            server_name="oauth_gcp_server",
            raw_server_config=raw_server_config,
            timeout=10,
        )
        assert first_finding is None
        assert first_config is not None
        assert first_config["headers"]["Authorization"] == "Bearer oauth-gcp-token"
        assert call_count["value"] == 1

        cli_module._clear_oauth_token_cache()
        second_config, second_finding = _build_connector_config_from_config_entry(
            server_name="oauth_gcp_server",
            raw_server_config=raw_server_config,
            timeout=10,
        )
        assert second_finding is None
        assert second_config is not None
        assert second_config["headers"]["Authorization"] == "Bearer oauth-gcp-token"
        assert call_count["value"] == 1

        assert FakeSecretManagerServiceClient.secret_payload is not None
        persisted_payload = json.loads(FakeSecretManagerServiceClient.secret_payload)
        assert persisted_payload["schema_version"] == cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2
        assert any(
            item.get("client_options", {}).get("api_endpoint") == "https://secretmanager.googleapis.com"
            for item in FakeSecretManagerServiceClient.client_kwargs
        )

        cli_module._clear_oauth_token_cache()

    def test_gcp_persistent_cache_bypasses_provider_errors(self, monkeypatch):
        """GCP backend cache load should bypass provider errors without raising."""

        class PermissionDeniedError(Exception):
            pass

        class FakeSecretManagerServiceClient:
            def access_secret_version(self, request: dict[str, object]) -> dict[str, object]:
                del request
                raise PermissionDeniedError("denied")

        class FakeGCPSecretManagerModule:
            SecretManagerServiceClient = FakeSecretManagerServiceClient

        original_import_module = cli_module.importlib.import_module

        def fake_import_module(module_name: str):
            if module_name == "google.cloud.secretmanager":
                return FakeGCPSecretManagerModule
            return original_import_module(module_name)

        monkeypatch.setattr(cli_module.importlib, "import_module", fake_import_module)

        entries = cli_module._load_oauth_persistent_cache_entries(
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="gcp-prod",
                backend="gcp_secret_manager",
                gcp_secret_name="projects/demo-project/secrets/mcp-oauth-cache",
            )
        )
        assert entries == {}

    def test_azure_persistent_cache_roundtrip_and_namespace_reuse(self, monkeypatch):
        """Azure Key Vault backend should persist and reload cache entries across runs."""
        cli_module._clear_oauth_token_cache()
        monkeypatch.setenv("MCP_OAUTH_CLIENT_ID", "client-azure")
        monkeypatch.setenv("MCP_OAUTH_CLIENT_SECRET", "secret-azure")

        class _SecretBundle:
            def __init__(self, value: str) -> None:
                self.value = value

        class FakeSecretClient:
            secret_payload: ClassVar[str] = json.dumps(
                {"schema_version": cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2, "entries": {}},
                sort_keys=True,
            )
            client_kwargs: ClassVar[list[dict[str, object]]] = []

            def __init__(self, **kwargs: object) -> None:
                self.__class__.client_kwargs.append(dict(kwargs))

            def get_secret(self, *, name: str, version: str | None = None) -> _SecretBundle:
                assert name == "mcp-security-oauth-cache"
                if version is not None:
                    assert version == "latest"
                return _SecretBundle(self.__class__.secret_payload)

            def set_secret(self, *, name: str, value: str) -> dict[str, object]:
                assert name == "mcp-security-oauth-cache"
                self.__class__.secret_payload = value
                return {}

        class FakeDefaultAzureCredential:
            def __init__(self) -> None:
                pass

        class FakeAzureIdentityModule:
            DefaultAzureCredential = FakeDefaultAzureCredential

        class FakeAzureKeyVaultSecretsModule:
            SecretClient = FakeSecretClient

        original_import_module = cli_module.importlib.import_module

        def fake_import_module(module_name: str):
            if module_name == "azure.identity":
                return FakeAzureIdentityModule
            if module_name == "azure.keyvault.secrets":
                return FakeAzureKeyVaultSecretsModule
            return original_import_module(module_name)

        monkeypatch.setattr(cli_module.importlib, "import_module", fake_import_module)

        call_count = {"value": 0}

        def fake_request(
            *,
            token_url: str,
            client_id: str,
            client_secret: str,
            scope: str | None,
            audience: str | None,
            token_endpoint_auth_method: str,
            timeout_seconds: int,
        ) -> tuple[str | None, float | None, str | None, int | None]:
            del token_url, client_id, client_secret, scope, audience, token_endpoint_auth_method, timeout_seconds
            call_count["value"] += 1
            return "oauth-azure-token", 3600.0, None, 200

        monkeypatch.setattr(cli_module, "_request_oauth_client_credentials_token", fake_request)

        raw_server_config = {
            "transport": "sse",
            "url": "https://example.com/sse",
            "auth": {
                "type": "oauth_client_credentials",
                "token_url": "https://auth.example.com/token",
                "client_id_env": "MCP_OAUTH_CLIENT_ID",
                "client_secret_env": "MCP_OAUTH_CLIENT_SECRET",
                "cache": {
                    "persistent": True,
                    "namespace": "azure-prod",
                    "backend": "azure_key_vault",
                    "azure_vault_url": "https://mcp-security.vault.azure.net",
                    "azure_secret_name": "mcp-security-oauth-cache",
                },
            },
        }

        first_config, first_finding = _build_connector_config_from_config_entry(
            server_name="oauth_azure_server",
            raw_server_config=raw_server_config,
            timeout=10,
        )
        assert first_finding is None
        assert first_config is not None
        assert first_config["headers"]["Authorization"] == "Bearer oauth-azure-token"
        assert call_count["value"] == 1

        cli_module._clear_oauth_token_cache()
        second_config, second_finding = _build_connector_config_from_config_entry(
            server_name="oauth_azure_server",
            raw_server_config=raw_server_config,
            timeout=10,
        )
        assert second_finding is None
        assert second_config is not None
        assert second_config["headers"]["Authorization"] == "Bearer oauth-azure-token"
        assert call_count["value"] == 1

        persisted_payload = json.loads(FakeSecretClient.secret_payload)
        assert persisted_payload["schema_version"] == cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2
        assert any(
            item.get("vault_url") == "https://mcp-security.vault.azure.net" for item in FakeSecretClient.client_kwargs
        )

        cli_module._clear_oauth_token_cache()

    def test_azure_persistent_cache_bypasses_provider_errors(self, monkeypatch):
        """Azure backend cache load should bypass provider errors without raising."""

        class UnauthorizedError(Exception):
            pass

        class FakeSecretClient:
            def get_secret(self, *, name: str, version: str | None = None) -> dict[str, object]:
                del name, version
                raise UnauthorizedError("denied")

        class FakeDefaultAzureCredential:
            def __init__(self) -> None:
                pass

        class FakeAzureIdentityModule:
            DefaultAzureCredential = FakeDefaultAzureCredential

        class FakeAzureKeyVaultSecretsModule:
            SecretClient = FakeSecretClient

        original_import_module = cli_module.importlib.import_module

        def fake_import_module(module_name: str):
            if module_name == "azure.identity":
                return FakeAzureIdentityModule
            if module_name == "azure.keyvault.secrets":
                return FakeAzureKeyVaultSecretsModule
            return original_import_module(module_name)

        monkeypatch.setattr(cli_module.importlib, "import_module", fake_import_module)

        entries = cli_module._load_oauth_persistent_cache_entries(
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="azure-prod",
                backend="azure_key_vault",
                azure_vault_url="https://mcp-security.vault.azure.net",
                azure_secret_name="mcp-security-oauth-cache",
            )
        )
        assert entries == {}

    def test_hashicorp_vault_persistent_cache_roundtrip_and_namespace_reuse(self, monkeypatch):
        """HashiCorp Vault backend should persist and reload cache entries across runs."""
        cli_module._clear_oauth_token_cache()
        monkeypatch.setenv("MCP_OAUTH_CLIENT_ID", "client-vault")
        monkeypatch.setenv("MCP_OAUTH_CLIENT_SECRET", "secret-vault")
        monkeypatch.setenv("VAULT_TOKEN_TEST", "vault-token-123")

        class FakeKVV2:
            secret_payload: ClassVar[str] = json.dumps(
                {"schema_version": cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2, "entries": {}},
                sort_keys=True,
            )

            def read_secret_version(self, *, path: str) -> dict[str, object]:
                assert path == "kv/mcp-security/oauth-cache"
                return {"data": {"data": {"oauth_cache_envelope": self.__class__.secret_payload}}}

            def create_or_update_secret(self, *, path: str, secret: dict[str, str]) -> dict[str, object]:
                assert path == "kv/mcp-security/oauth-cache"
                self.__class__.secret_payload = secret["oauth_cache_envelope"]
                return {}

        class FakeVaultClient:
            client_kwargs: ClassVar[list[dict[str, object]]] = []

            def __init__(self, **kwargs: object) -> None:
                self.__class__.client_kwargs.append(dict(kwargs))
                self.secrets = types.SimpleNamespace(kv=types.SimpleNamespace(v2=FakeKVV2()))

        class FakeHVACModule:
            Client = FakeVaultClient

        original_import_module = cli_module.importlib.import_module

        def fake_import_module(module_name: str):
            if module_name == "hvac":
                return FakeHVACModule
            return original_import_module(module_name)

        monkeypatch.setattr(cli_module.importlib, "import_module", fake_import_module)

        call_count = {"value": 0}

        def fake_request(
            *,
            token_url: str,
            client_id: str,
            client_secret: str,
            scope: str | None,
            audience: str | None,
            token_endpoint_auth_method: str,
            timeout_seconds: int,
        ) -> tuple[str | None, float | None, str | None, int | None]:
            del token_url, client_id, client_secret, scope, audience, token_endpoint_auth_method, timeout_seconds
            call_count["value"] += 1
            return "oauth-vault-token", 3600.0, None, 200

        monkeypatch.setattr(cli_module, "_request_oauth_client_credentials_token", fake_request)

        raw_server_config = {
            "transport": "sse",
            "url": "https://example.com/sse",
            "auth": {
                "type": "oauth_client_credentials",
                "token_url": "https://auth.example.com/token",
                "client_id_env": "MCP_OAUTH_CLIENT_ID",
                "client_secret_env": "MCP_OAUTH_CLIENT_SECRET",
                "cache": {
                    "persistent": True,
                    "namespace": "vault-prod",
                    "backend": "hashicorp_vault",
                    "vault_url": "https://vault.example.com",
                    "vault_secret_path": "kv/mcp-security/oauth-cache",
                    "vault_token_env": "VAULT_TOKEN_TEST",
                    "vault_namespace": "team-security",
                },
            },
        }

        first_config, first_finding = _build_connector_config_from_config_entry(
            server_name="oauth_vault_server",
            raw_server_config=raw_server_config,
            timeout=10,
        )
        assert first_finding is None
        assert first_config is not None
        assert first_config["headers"]["Authorization"] == "Bearer oauth-vault-token"
        assert call_count["value"] == 1

        cli_module._clear_oauth_token_cache()
        second_config, second_finding = _build_connector_config_from_config_entry(
            server_name="oauth_vault_server",
            raw_server_config=raw_server_config,
            timeout=10,
        )
        assert second_finding is None
        assert second_config is not None
        assert second_config["headers"]["Authorization"] == "Bearer oauth-vault-token"
        assert call_count["value"] == 1

        persisted_payload = json.loads(FakeKVV2.secret_payload)
        assert persisted_payload["schema_version"] == cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2
        assert any(item.get("url") == "https://vault.example.com" for item in FakeVaultClient.client_kwargs)
        assert any(item.get("token") == "vault-token-123" for item in FakeVaultClient.client_kwargs)
        assert any(item.get("namespace") == "team-security" for item in FakeVaultClient.client_kwargs)

        cli_module._clear_oauth_token_cache()

    def test_hashicorp_vault_persistent_cache_bypasses_provider_errors(self, monkeypatch):
        """HashiCorp Vault backend cache load should bypass provider errors without raising."""

        class FakeKVV2:
            def read_secret_version(self, *, path: str) -> dict[str, object]:
                del path
                raise RuntimeError("vault denied")

        class FakeVaultClient:
            def __init__(self, **kwargs: object) -> None:
                del kwargs
                self.secrets = types.SimpleNamespace(kv=types.SimpleNamespace(v2=FakeKVV2()))

        class FakeHVACModule:
            Client = FakeVaultClient

        original_import_module = cli_module.importlib.import_module

        def fake_import_module(module_name: str):
            if module_name == "hvac":
                return FakeHVACModule
            return original_import_module(module_name)

        monkeypatch.setattr(cli_module.importlib, "import_module", fake_import_module)

        entries = cli_module._load_oauth_persistent_cache_entries(
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="vault-prod",
                backend="hashicorp_vault",
                vault_url="https://vault.example.com",
                vault_secret_path="kv/mcp-security/oauth-cache",
                vault_token_env="VAULT_TOKEN_TEST",
            )
        )
        assert entries == {}

    def test_kubernetes_persistent_cache_roundtrip_and_namespace_reuse(self, monkeypatch):
        """Kubernetes Secrets backend should persist and reload cache entries across runs."""
        cli_module._clear_oauth_token_cache()
        monkeypatch.setenv("MCP_OAUTH_CLIENT_ID", "client-k8s")
        monkeypatch.setenv("MCP_OAUTH_CLIENT_SECRET", "secret-k8s")

        class FakeConfigError(Exception):
            pass

        class _Secret:
            def __init__(self, data: dict[str, str] | None = None) -> None:
                self.data = data or {}

        class FakeCoreV1Api:
            secret_data: ClassVar[dict[str, str]] = {
                "oauth_cache": base64.b64encode(
                    json.dumps(
                        {"schema_version": cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2, "entries": {}},
                        sort_keys=True,
                    ).encode("utf-8")
                ).decode("ascii")
            }
            patch_calls: ClassVar[int] = 0

            def read_namespaced_secret(self, *, name: str, namespace: str) -> _Secret:
                assert name == "oauth-cache"
                assert namespace == "mcp-security"
                return _Secret(dict(self.__class__.secret_data))

            def patch_namespaced_secret(
                self, *, name: str, namespace: str, body: dict[str, object]
            ) -> dict[str, object]:
                assert name == "oauth-cache"
                assert namespace == "mcp-security"
                data = body.get("data")
                assert isinstance(data, dict)
                assert "oauth_cache" in data
                self.__class__.secret_data = {str(key): str(value) for key, value in data.items()}
                self.__class__.patch_calls += 1
                return {}

        class FakeKubernetesClientModule:
            CoreV1Api = FakeCoreV1Api

        class FakeKubernetesConfigModule:
            incluster_calls: ClassVar[int] = 0
            kubeconfig_calls: ClassVar[int] = 0

            @classmethod
            def load_incluster_config(cls) -> None:
                cls.incluster_calls += 1
                raise FakeConfigError("incluster-unavailable")

            @classmethod
            def load_kube_config(cls) -> None:
                cls.kubeconfig_calls += 1
                return None

        original_import_module = cli_module.importlib.import_module

        def fake_import_module(module_name: str):
            if module_name == "kubernetes.client":
                return FakeKubernetesClientModule
            if module_name == "kubernetes.config":
                return FakeKubernetesConfigModule
            return original_import_module(module_name)

        monkeypatch.setattr(cli_module.importlib, "import_module", fake_import_module)

        call_count = {"value": 0}

        def fake_request(
            *,
            token_url: str,
            client_id: str,
            client_secret: str,
            scope: str | None,
            audience: str | None,
            token_endpoint_auth_method: str,
            timeout_seconds: int,
        ) -> tuple[str | None, float | None, str | None, int | None]:
            del token_url, client_id, client_secret, scope, audience, token_endpoint_auth_method, timeout_seconds
            call_count["value"] += 1
            return "oauth-k8s-token", 3600.0, None, 200

        monkeypatch.setattr(cli_module, "_request_oauth_client_credentials_token", fake_request)

        raw_server_config = {
            "transport": "sse",
            "url": "https://example.com/sse",
            "auth": {
                "type": "oauth_client_credentials",
                "token_url": "https://auth.example.com/token",
                "client_id_env": "MCP_OAUTH_CLIENT_ID",
                "client_secret_env": "MCP_OAUTH_CLIENT_SECRET",
                "cache": {
                    "persistent": True,
                    "namespace": "k8s-prod",
                    "backend": "kubernetes_secrets",
                    "k8s_secret_namespace": "mcp-security",
                    "k8s_secret_name": "oauth-cache",
                },
            },
        }

        first_config, first_finding = _build_connector_config_from_config_entry(
            server_name="oauth_k8s_server",
            raw_server_config=raw_server_config,
            timeout=10,
        )
        assert first_finding is None
        assert first_config is not None
        assert first_config["headers"]["Authorization"] == "Bearer oauth-k8s-token"
        assert call_count["value"] == 1

        cli_module._clear_oauth_token_cache()
        second_config, second_finding = _build_connector_config_from_config_entry(
            server_name="oauth_k8s_server",
            raw_server_config=raw_server_config,
            timeout=10,
        )
        assert second_finding is None
        assert second_config is not None
        assert second_config["headers"]["Authorization"] == "Bearer oauth-k8s-token"
        assert call_count["value"] == 1
        assert FakeCoreV1Api.patch_calls >= 1
        assert FakeKubernetesConfigModule.incluster_calls >= 1
        assert FakeKubernetesConfigModule.kubeconfig_calls >= 1

        payload_b64 = FakeCoreV1Api.secret_data["oauth_cache"]
        persisted_payload = json.loads(base64.b64decode(payload_b64.encode("ascii")).decode("utf-8"))
        assert persisted_payload["schema_version"] == cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2

        cli_module._clear_oauth_token_cache()

    def test_kubernetes_persistent_cache_bypasses_provider_errors(self, monkeypatch):
        """Kubernetes backend cache load should bypass provider errors without raising."""

        class FakeKubernetesClientModule:
            class CoreV1Api:
                def read_namespaced_secret(self, *, name: str, namespace: str) -> dict[str, object]:
                    del name, namespace
                    raise RuntimeError("forbidden")

        class FakeKubernetesConfigModule:
            @staticmethod
            def load_incluster_config() -> None:
                return None

            @staticmethod
            def load_kube_config() -> None:
                return None

        original_import_module = cli_module.importlib.import_module

        def fake_import_module(module_name: str):
            if module_name == "kubernetes.client":
                return FakeKubernetesClientModule
            if module_name == "kubernetes.config":
                return FakeKubernetesConfigModule
            return original_import_module(module_name)

        monkeypatch.setattr(cli_module.importlib, "import_module", fake_import_module)

        entries = cli_module._load_oauth_persistent_cache_entries(
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="k8s-prod",
                backend="kubernetes_secrets",
                k8s_secret_namespace="mcp-security",
                k8s_secret_name="oauth-cache",
            )
        )
        assert entries == {}

    def test_oci_vault_persistent_cache_roundtrip_and_namespace_reuse(self, monkeypatch):
        """OCI Vault backend should persist and reload cache entries across runs."""
        cli_module._clear_oauth_token_cache()
        monkeypatch.setenv("MCP_OAUTH_CLIENT_ID", "client-oci")
        monkeypatch.setenv("MCP_OAUTH_CLIENT_SECRET", "secret-oci")

        class _SecretState:
            payload: ClassVar[str] = base64.b64encode(
                json.dumps(
                    {"schema_version": cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2, "entries": {}},
                    sort_keys=True,
                ).encode("utf-8")
            ).decode("ascii")

        class FakeSecretsClient:
            client_kwargs: ClassVar[list[dict[str, object]]] = []

            def __init__(self, config: dict[str, object], **kwargs: object) -> None:
                self.__class__.client_kwargs.append({"config": dict(config), **kwargs})

            def get_secret_bundle(self, *, secret_id: str) -> types.SimpleNamespace:
                assert secret_id == "ocid1.secret.oc1.iad.exampleuniqueid1234567890"
                return types.SimpleNamespace(
                    data=types.SimpleNamespace(
                        secret_bundle_content=types.SimpleNamespace(content=_SecretState.payload)
                    )
                )

        class FakeBase64SecretContentDetails:
            def __init__(self, *, content_type: str, content: str) -> None:
                assert content_type == "BASE64"
                self.content = content

        class FakeUpdateSecretDetails:
            def __init__(self, *, secret_content: FakeBase64SecretContentDetails) -> None:
                self.secret_content = secret_content

        class FakeVaultsClient:
            client_kwargs: ClassVar[list[dict[str, object]]] = []

            def __init__(self, config: dict[str, object], **kwargs: object) -> None:
                self.__class__.client_kwargs.append({"config": dict(config), **kwargs})

            def get_secret(self, *, secret_id: str) -> dict[str, object]:
                assert secret_id == "ocid1.secret.oc1.iad.exampleuniqueid1234567890"
                return {}

            def update_secret(
                self, *, secret_id: str, update_secret_details: FakeUpdateSecretDetails
            ) -> dict[str, object]:
                assert secret_id == "ocid1.secret.oc1.iad.exampleuniqueid1234567890"
                _SecretState.payload = update_secret_details.secret_content.content
                return {}

        class FakeSignersModule:
            signer_calls: ClassVar[int] = 0

            @classmethod
            def get_resource_principals_signer(cls) -> object:
                cls.signer_calls += 1
                raise RuntimeError("resource-principal-unavailable")

        class FakeOCIConfigModule:
            from_file_calls: ClassVar[int] = 0

            @classmethod
            def from_file(cls, **kwargs: object) -> dict[str, str]:
                cls.from_file_calls += 1
                del kwargs
                return {"region": "us-ashburn-1"}

        class FakeOCIModule:
            config = FakeOCIConfigModule
            auth = types.SimpleNamespace(signers=FakeSignersModule)
            secrets = types.SimpleNamespace(SecretsClient=FakeSecretsClient)
            vault = types.SimpleNamespace(
                VaultsClient=FakeVaultsClient,
                models=types.SimpleNamespace(
                    Base64SecretContentDetails=FakeBase64SecretContentDetails,
                    UpdateSecretDetails=FakeUpdateSecretDetails,
                ),
            )

        original_import_module = cli_module.importlib.import_module

        def fake_import_module(module_name: str):
            if module_name == "oci":
                return FakeOCIModule
            return original_import_module(module_name)

        monkeypatch.setattr(cli_module.importlib, "import_module", fake_import_module)

        call_count = {"value": 0}

        def fake_request(
            *,
            token_url: str,
            client_id: str,
            client_secret: str,
            scope: str | None,
            audience: str | None,
            token_endpoint_auth_method: str,
            timeout_seconds: int,
        ) -> tuple[str | None, float | None, str | None, int | None]:
            del token_url, client_id, client_secret, scope, audience, token_endpoint_auth_method, timeout_seconds
            call_count["value"] += 1
            return "oauth-oci-token", 3600.0, None, 200

        monkeypatch.setattr(cli_module, "_request_oauth_client_credentials_token", fake_request)

        raw_server_config = {
            "transport": "sse",
            "url": "https://example.com/sse",
            "auth": {
                "type": "oauth_client_credentials",
                "token_url": "https://auth.example.com/token",
                "client_id_env": "MCP_OAUTH_CLIENT_ID",
                "client_secret_env": "MCP_OAUTH_CLIENT_SECRET",
                "cache": {
                    "persistent": True,
                    "namespace": "oci-prod",
                    "backend": "oci_vault",
                    "oci_secret_ocid": "ocid1.secret.oc1.iad.exampleuniqueid1234567890",
                    "oci_region": "eu-frankfurt-1",
                    "oci_endpoint_url": "https://vaults.eu-frankfurt-1.oci.oraclecloud.com",
                },
            },
        }

        first_config, first_finding = _build_connector_config_from_config_entry(
            server_name="oauth_oci_server",
            raw_server_config=raw_server_config,
            timeout=10,
        )
        assert first_finding is None
        assert first_config is not None
        assert first_config["headers"]["Authorization"] == "Bearer oauth-oci-token"
        assert call_count["value"] == 1

        cli_module._clear_oauth_token_cache()
        second_config, second_finding = _build_connector_config_from_config_entry(
            server_name="oauth_oci_server",
            raw_server_config=raw_server_config,
            timeout=10,
        )
        assert second_finding is None
        assert second_config is not None
        assert second_config["headers"]["Authorization"] == "Bearer oauth-oci-token"
        assert call_count["value"] == 1

        persisted_payload = json.loads(base64.b64decode(_SecretState.payload.encode("ascii")).decode("utf-8"))
        assert persisted_payload["schema_version"] == cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2
        assert FakeSignersModule.signer_calls >= 1
        assert FakeOCIConfigModule.from_file_calls >= 1
        assert any(
            item.get("service_endpoint") == "https://vaults.eu-frankfurt-1.oci.oraclecloud.com"
            for item in FakeSecretsClient.client_kwargs
        )
        assert any(item.get("config", {}).get("region") == "eu-frankfurt-1" for item in FakeSecretsClient.client_kwargs)

        cli_module._clear_oauth_token_cache()

    def test_build_oci_secrets_client_prefers_resource_principal(self, monkeypatch):
        """OCI client builder should prefer resource principal signer over config-file fallback."""

        class FakeSecretsClient:
            client_kwargs: ClassVar[list[dict[str, object]]] = []

            def __init__(self, config: dict[str, object], **kwargs: object) -> None:
                self.__class__.client_kwargs.append({"config": dict(config), **kwargs})

        class FakeSignersModule:
            signer_calls: ClassVar[int] = 0

            @classmethod
            def get_resource_principals_signer(cls) -> object:
                cls.signer_calls += 1
                return object()

        class FakeOCIConfigModule:
            from_file_calls: ClassVar[int] = 0

            @classmethod
            def from_file(cls, **kwargs: object) -> dict[str, str]:
                cls.from_file_calls += 1
                del kwargs
                return {"region": "us-ashburn-1"}

        class FakeOCIModule:
            config = FakeOCIConfigModule
            auth = types.SimpleNamespace(signers=FakeSignersModule)
            secrets = types.SimpleNamespace(SecretsClient=FakeSecretsClient)
            vault = types.SimpleNamespace(VaultsClient=FakeSecretsClient, models=types.SimpleNamespace())

        original_import_module = cli_module.importlib.import_module

        def fake_import_module(module_name: str):
            if module_name == "oci":
                return FakeOCIModule
            return original_import_module(module_name)

        monkeypatch.setattr(cli_module.importlib, "import_module", fake_import_module)

        client = cli_module._build_oci_secrets_client(
            cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="oci-prod",
                backend="oci_vault",
                oci_secret_ocid="ocid1.secret.oc1.iad.exampleuniqueid1234567890",
            )
        )
        assert client is not None
        assert FakeSignersModule.signer_calls == 1
        assert FakeOCIConfigModule.from_file_calls == 0

    def test_oci_vault_persistent_cache_bypasses_provider_errors(self, monkeypatch):
        """OCI backend cache load should bypass provider errors without raising."""

        class FakeSecretsClient:
            def __init__(self, config: dict[str, object], **kwargs: object) -> None:
                del config, kwargs

            def get_secret_bundle(self, *, secret_id: str) -> dict[str, object]:
                del secret_id
                raise RuntimeError("forbidden")

        class FakeSignersModule:
            @staticmethod
            def get_resource_principals_signer() -> object:
                return object()

        class FakeOCIModule:
            config = types.SimpleNamespace(from_file=lambda **kwargs: {"region": "us-ashburn-1"})
            auth = types.SimpleNamespace(signers=FakeSignersModule)
            secrets = types.SimpleNamespace(SecretsClient=FakeSecretsClient)
            vault = types.SimpleNamespace(VaultsClient=FakeSecretsClient, models=types.SimpleNamespace())

        original_import_module = cli_module.importlib.import_module

        def fake_import_module(module_name: str):
            if module_name == "oci":
                return FakeOCIModule
            return original_import_module(module_name)

        monkeypatch.setattr(cli_module.importlib, "import_module", fake_import_module)

        entries = cli_module._load_oauth_persistent_cache_entries(
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="oci-prod",
                backend="oci_vault",
                oci_secret_ocid="ocid1.secret.oc1.iad.exampleuniqueid1234567890",
            )
        )
        assert entries == {}

    def test_resolve_oci_auth_context_falls_back_to_config_chain(self, monkeypatch):
        """OCI auth resolver should use config-file chain when resource principal is unavailable."""

        class FakeSignersModule:
            @staticmethod
            def get_resource_principals_signer() -> object:
                raise RuntimeError("resource principal unavailable")

        class FakeOCIConfigModule:
            kwargs_calls: ClassVar[list[dict[str, object]]] = []

            @classmethod
            def from_file(cls, **kwargs: object) -> dict[str, str]:
                cls.kwargs_calls.append(dict(kwargs))
                return {"region": "us-ashburn-1", "tenancy": "ocid1.tenancy.oc1..example"}

        fake_oci_module = types.SimpleNamespace(
            auth=types.SimpleNamespace(signers=FakeSignersModule),
            config=FakeOCIConfigModule,
        )

        monkeypatch.setenv("OCI_CONFIG_FILE", "/tmp/oci-config")
        monkeypatch.setenv("OCI_CONFIG_PROFILE", "PROD")
        config, signer = cli_module._resolve_oci_auth_context(
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="oci-prod",
                backend="oci_vault",
                oci_secret_ocid="ocid1.secret.oc1.iad.exampleuniqueid1234567890",
                oci_region="eu-frankfurt-1",
            ),
            oci_module=fake_oci_module,
        )

        assert signer is None
        assert config is not None
        assert config["region"] == "eu-frankfurt-1"
        assert FakeOCIConfigModule.kwargs_calls == [
            {
                "file_location": "/tmp/oci-config",
                "profile_name": "PROD",
            }
        ]

    def test_resolve_oci_auth_context_returns_none_when_config_loader_missing(self):
        """OCI auth resolver should return no auth context when no auth loaders are available."""

        fake_oci_module = types.SimpleNamespace(
            auth=types.SimpleNamespace(signers=types.SimpleNamespace()),
            config=types.SimpleNamespace(),
        )

        config, signer = cli_module._resolve_oci_auth_context(
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="oci-prod",
                backend="oci_vault",
                oci_secret_ocid="ocid1.secret.oc1.iad.exampleuniqueid1234567890",
            ),
            oci_module=fake_oci_module,
        )

        assert config is None
        assert signer is None

    def test_read_oauth_cache_payload_from_oci_handles_empty_and_invalid_content(self, monkeypatch):
        """OCI payload reader should handle empty and malformed secret content safely."""

        def build_response(content: object) -> object:
            return types.SimpleNamespace(
                data=types.SimpleNamespace(
                    secret_bundle_content=types.SimpleNamespace(content=content),
                )
            )

        class FakeClient:
            def __init__(self, response: object) -> None:
                self._response = response

            def get_secret_bundle(self, *, secret_id: str) -> object:
                del secret_id
                return self._response

        cache_settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="oci-prod",
            backend="oci_vault",
            oci_secret_ocid="ocid1.secret.oc1.iad.exampleuniqueid1234567890",
        )

        monkeypatch.setattr(
            cli_module,
            "_build_oci_secrets_client",
            lambda cache_settings: FakeClient(build_response("")),
        )
        empty_payload = cli_module._read_oauth_cache_payload_from_oci(cache_settings=cache_settings)
        assert empty_payload == {
            "schema_version": cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2,
            "entries": {},
        }

        monkeypatch.setattr(
            cli_module,
            "_build_oci_secrets_client",
            lambda cache_settings: FakeClient(build_response("!!!")),
        )
        assert cli_module._read_oauth_cache_payload_from_oci(cache_settings=cache_settings) is None

        non_dict_payload = base64.b64encode(b"[]").decode("ascii")
        monkeypatch.setattr(
            cli_module,
            "_build_oci_secrets_client",
            lambda cache_settings: FakeClient(build_response(non_dict_payload)),
        )
        assert cli_module._read_oauth_cache_payload_from_oci(cache_settings=cache_settings) is None

    def test_write_oauth_cache_payload_to_oci_handles_missing_models_and_update_error(self, monkeypatch):
        """OCI payload writer should fail closed when SDK models are missing or update fails."""

        class FakeVaultClient:
            def __init__(self, should_fail_update: bool) -> None:
                self.should_fail_update = should_fail_update

            def get_secret(self, *, secret_id: str) -> dict[str, str]:
                del secret_id
                return {"id": "existing"}

            def update_secret(self, *, secret_id: str, update_secret_details: object) -> dict[str, str]:
                del secret_id, update_secret_details
                if self.should_fail_update:
                    raise RuntimeError("update denied")
                return {"status": "ok"}

        class FakeBase64SecretContentDetails:
            def __init__(self, *, content_type: str, content: str) -> None:
                self.content_type = content_type
                self.content = content

        class FakeUpdateSecretDetails:
            def __init__(self, *, secret_content: object) -> None:
                self.secret_content = secret_content

        cache_settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="oci-prod",
            backend="oci_vault",
            oci_secret_ocid="ocid1.secret.oc1.iad.exampleuniqueid1234567890",
        )

        monkeypatch.setattr(
            cli_module,
            "_build_oci_vault_client",
            lambda cache_settings: FakeVaultClient(should_fail_update=False),
        )
        original_import_module = cli_module.importlib.import_module
        monkeypatch.setattr(
            cli_module.importlib,
            "import_module",
            lambda module_name: (
                types.SimpleNamespace(vault=types.SimpleNamespace(models=types.SimpleNamespace()))
                if module_name == "oci"
                else original_import_module(module_name)
            ),
        )
        assert (
            cli_module._write_oauth_cache_payload_to_oci(
                cache_settings=cache_settings,
                entries={},
            )
            is False
        )

        monkeypatch.setattr(
            cli_module,
            "_build_oci_vault_client",
            lambda cache_settings: FakeVaultClient(should_fail_update=True),
        )
        original_import_module = cli_module.importlib.import_module
        monkeypatch.setattr(
            cli_module.importlib,
            "import_module",
            lambda module_name: (
                types.SimpleNamespace(
                    vault=types.SimpleNamespace(
                        models=types.SimpleNamespace(
                            Base64SecretContentDetails=FakeBase64SecretContentDetails,
                            UpdateSecretDetails=FakeUpdateSecretDetails,
                        )
                    )
                )
                if module_name == "oci"
                else original_import_module(module_name)
            ),
        )
        assert (
            cli_module._write_oauth_cache_payload_to_oci(
                cache_settings=cache_settings,
                entries={},
            )
            is False
        )

    def test_doppler_persistent_cache_roundtrip_and_namespace_reuse(self, monkeypatch):
        """Doppler backend should persist and reload cache entries across runs."""
        cli_module._clear_oauth_token_cache()
        monkeypatch.setenv("MCP_OAUTH_CLIENT_ID", "client-doppler")
        monkeypatch.setenv("MCP_OAUTH_CLIENT_SECRET", "secret-doppler")
        monkeypatch.setenv("DOPPLER_TOKEN", "dp.st.test-token")

        class FakeHTTPError(Exception):
            pass

        class FakeResponse:
            def __init__(self, *, status_code: int, json_data: object) -> None:
                self.status_code = status_code
                self._json_data = json_data

            def json(self) -> object:
                return self._json_data

            def raise_for_status(self) -> None:
                if self.status_code >= 400:
                    raise FakeHTTPError(f"status={self.status_code}")

        class FakeDopplerClient:
            client_kwargs: ClassVar[list[dict[str, object]]] = []
            post_payloads: ClassVar[list[dict[str, object]]] = []
            secrets_map: ClassVar[dict[str, str]] = {
                "MCP_OAUTH_CACHE": json.dumps(
                    {"schema_version": cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2, "entries": {}},
                    sort_keys=True,
                )
            }

            def __init__(self, **kwargs: object) -> None:
                self.__class__.client_kwargs.append(dict(kwargs))

            def get(self, path: str, params: dict[str, str]) -> FakeResponse:
                assert path == "/v3/configs/config/secrets/download"
                assert params["project"] == "security-platform"
                assert params["config"] == "prd"
                assert params["format"] == "json"
                return FakeResponse(status_code=200, json_data=dict(self.__class__.secrets_map))

            def post(self, path: str, json: dict[str, object]) -> FakeResponse:
                assert path == "/v3/configs/config/secrets"
                self.__class__.post_payloads.append(dict(json))
                secrets = json.get("secrets")
                assert isinstance(secrets, dict)
                for key, value in secrets.items():
                    if isinstance(key, str) and isinstance(value, str):
                        self.__class__.secrets_map[key] = value
                return FakeResponse(status_code=200, json_data={"ok": True})

            def close(self) -> None:
                return None

        monkeypatch.setattr(cli_module.httpx, "Client", FakeDopplerClient)

        call_count = {"value": 0}

        def fake_request(
            *,
            token_url: str,
            client_id: str,
            client_secret: str,
            scope: str | None,
            audience: str | None,
            token_endpoint_auth_method: str,
            timeout_seconds: int,
        ) -> tuple[str | None, float | None, str | None, int | None]:
            del token_url, client_id, client_secret, scope, audience, token_endpoint_auth_method, timeout_seconds
            call_count["value"] += 1
            return "oauth-doppler-token", 3600.0, None, 200

        monkeypatch.setattr(cli_module, "_request_oauth_client_credentials_token", fake_request)

        raw_server_config = {
            "transport": "sse",
            "url": "https://example.com/sse",
            "auth": {
                "type": "oauth_client_credentials",
                "token_url": "https://auth.example.com/token",
                "client_id_env": "MCP_OAUTH_CLIENT_ID",
                "client_secret_env": "MCP_OAUTH_CLIENT_SECRET",
                "cache": {
                    "persistent": True,
                    "namespace": "doppler-prod",
                    "backend": "doppler_secrets",
                    "doppler_project": "security-platform",
                    "doppler_config": "prd",
                    "doppler_secret_name": "MCP_OAUTH_CACHE",
                    "doppler_token_env": "DOPPLER_TOKEN",
                    "doppler_api_url": "https://api.doppler.com",
                },
            },
        }

        first_config, first_finding = _build_connector_config_from_config_entry(
            server_name="oauth_doppler_server",
            raw_server_config=raw_server_config,
            timeout=10,
        )
        assert first_finding is None
        assert first_config is not None
        assert first_config["headers"]["Authorization"] == "Bearer oauth-doppler-token"
        assert call_count["value"] == 1

        cli_module._clear_oauth_token_cache()
        second_config, second_finding = _build_connector_config_from_config_entry(
            server_name="oauth_doppler_server",
            raw_server_config=raw_server_config,
            timeout=10,
        )
        assert second_finding is None
        assert second_config is not None
        assert second_config["headers"]["Authorization"] == "Bearer oauth-doppler-token"
        assert call_count["value"] == 1

        persisted_payload = json.loads(FakeDopplerClient.secrets_map["MCP_OAUTH_CACHE"])
        assert persisted_payload["schema_version"] == cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2
        assert FakeDopplerClient.post_payloads
        assert any(item.get("base_url") == "https://api.doppler.com" for item in FakeDopplerClient.client_kwargs)

        cli_module._clear_oauth_token_cache()

    def test_doppler_persistent_cache_bypasses_provider_errors(self, monkeypatch):
        """Doppler backend cache load should bypass provider errors without raising."""
        monkeypatch.setenv("DOPPLER_TOKEN", "dp.st.test-token")

        class FakeDopplerClient:
            def __init__(self, **kwargs: object) -> None:
                del kwargs

            def get(self, path: str, params: dict[str, str]) -> dict[str, object]:
                del path, params
                raise RuntimeError("denied")

            def close(self) -> None:
                return None

        monkeypatch.setattr(cli_module.httpx, "Client", FakeDopplerClient)

        entries = cli_module._load_oauth_persistent_cache_entries(
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="doppler-prod",
                backend="doppler_secrets",
                doppler_project="security-platform",
                doppler_config="prd",
                doppler_secret_name="MCP_OAUTH_CACHE",
            )
        )
        assert entries == {}

    def test_onepassword_connect_persistent_cache_roundtrip_and_namespace_reuse(self, monkeypatch):
        """1Password Connect backend should persist and reload cache entries across runs."""
        cli_module._clear_oauth_token_cache()
        monkeypatch.setenv("MCP_OAUTH_CLIENT_ID", "client-op")
        monkeypatch.setenv("MCP_OAUTH_CLIENT_SECRET", "secret-op")
        monkeypatch.setenv("OP_CONNECT_TOKEN", "op-token-test")

        class FakeHTTPError(Exception):
            pass

        class FakeResponse:
            def __init__(self, *, status_code: int, json_data: object) -> None:
                self.status_code = status_code
                self._json_data = json_data

            def json(self) -> object:
                return self._json_data

            def raise_for_status(self) -> None:
                if self.status_code >= 400:
                    raise FakeHTTPError(f"status={self.status_code}")

        class FakeOnePasswordConnectClient:
            client_kwargs: ClassVar[list[dict[str, object]]] = []
            put_payloads: ClassVar[list[dict[str, object]]] = []
            item_payload: ClassVar[dict[str, object]] = {
                "id": "item-456",
                "vault": {"id": "vault-123"},
                "fields": [
                    {
                        "id": "oauth_cache",
                        "label": "oauth_cache",
                        "value": json.dumps(
                            {"schema_version": cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2, "entries": {}},
                            sort_keys=True,
                        ),
                    }
                ],
            }

            def __init__(self, **kwargs: object) -> None:
                self.__class__.client_kwargs.append(dict(kwargs))

            def get(self, path: str) -> FakeResponse:
                assert path == "/v1/vaults/vault-123/items/item-456"
                return FakeResponse(status_code=200, json_data=json.loads(json.dumps(self.__class__.item_payload)))

            def put(self, path: str, **kwargs: object) -> FakeResponse:
                assert path == "/v1/vaults/vault-123/items/item-456"
                raw_payload = kwargs.get("json")
                assert isinstance(raw_payload, dict)
                self.__class__.put_payloads.append(dict(raw_payload))
                self.__class__.item_payload = json.loads(json.dumps(raw_payload))
                return FakeResponse(status_code=200, json_data={"ok": True})

            def close(self) -> None:
                return None

        monkeypatch.setattr(cli_module.httpx, "Client", FakeOnePasswordConnectClient)

        call_count = {"value": 0}

        def fake_request(
            *,
            token_url: str,
            client_id: str,
            client_secret: str,
            scope: str | None,
            audience: str | None,
            token_endpoint_auth_method: str,
            timeout_seconds: int,
        ) -> tuple[str | None, float | None, str | None, int | None]:
            del token_url, client_id, client_secret, scope, audience, token_endpoint_auth_method, timeout_seconds
            call_count["value"] += 1
            return "oauth-op-token", 3600.0, None, 200

        monkeypatch.setattr(cli_module, "_request_oauth_client_credentials_token", fake_request)

        raw_server_config = {
            "transport": "sse",
            "url": "https://example.com/sse",
            "auth": {
                "type": "oauth_client_credentials",
                "token_url": "https://auth.example.com/token",
                "client_id_env": "MCP_OAUTH_CLIENT_ID",
                "client_secret_env": "MCP_OAUTH_CLIENT_SECRET",
                "cache": {
                    "persistent": True,
                    "namespace": "op-prod",
                    "backend": "onepassword_connect",
                    "op_connect_host": "https://op-connect.example.com",
                    "op_vault_id": "vault-123",
                    "op_item_id": "item-456",
                    "op_field_label": "oauth_cache",
                    "op_connect_token_env": "OP_CONNECT_TOKEN",
                },
            },
        }

        first_config, first_finding = _build_connector_config_from_config_entry(
            server_name="oauth_op_server",
            raw_server_config=raw_server_config,
            timeout=10,
        )
        assert first_finding is None
        assert first_config is not None
        assert first_config["headers"]["Authorization"] == "Bearer oauth-op-token"
        assert call_count["value"] == 1

        cli_module._clear_oauth_token_cache()
        second_config, second_finding = _build_connector_config_from_config_entry(
            server_name="oauth_op_server",
            raw_server_config=raw_server_config,
            timeout=10,
        )
        assert second_finding is None
        assert second_config is not None
        assert second_config["headers"]["Authorization"] == "Bearer oauth-op-token"
        assert call_count["value"] == 1

        item_fields = FakeOnePasswordConnectClient.item_payload.get("fields")
        assert isinstance(item_fields, list)
        assert item_fields
        cached_value = item_fields[0].get("value")
        assert isinstance(cached_value, str)
        persisted_payload = json.loads(cached_value)
        assert persisted_payload["schema_version"] == cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2
        assert FakeOnePasswordConnectClient.put_payloads
        assert any(
            item.get("base_url") == "https://op-connect.example.com"
            for item in FakeOnePasswordConnectClient.client_kwargs
        )

        cli_module._clear_oauth_token_cache()

    def test_onepassword_connect_persistent_cache_bypasses_provider_errors(self, monkeypatch):
        """1Password Connect backend cache load should bypass provider errors without raising."""
        monkeypatch.setenv("OP_CONNECT_TOKEN", "op-token-test")

        class FakeOnePasswordConnectClient:
            def __init__(self, **kwargs: object) -> None:
                del kwargs

            def get(self, path: str) -> dict[str, object]:
                del path
                raise RuntimeError("denied")

            def close(self) -> None:
                return None

        monkeypatch.setattr(cli_module.httpx, "Client", FakeOnePasswordConnectClient)

        entries = cli_module._load_oauth_persistent_cache_entries(
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="op-prod",
                backend="onepassword_connect",
                op_connect_host="https://op-connect.example.com",
                op_vault_id="vault-123",
                op_item_id="item-456",
                op_field_label="oauth_cache",
                op_connect_token_env="OP_CONNECT_TOKEN",
            )
        )
        assert entries == {}

    def test_onepassword_connect_write_bypasses_missing_field(self, monkeypatch):
        """1Password Connect backend write should fail closed when target field is missing."""
        monkeypatch.setenv("OP_CONNECT_TOKEN", "op-token-test")

        class FakeResponse:
            def __init__(self, *, status_code: int, json_data: object) -> None:
                self.status_code = status_code
                self._json_data = json_data

            def json(self) -> object:
                return self._json_data

            def raise_for_status(self) -> None:
                if self.status_code >= 400:
                    raise RuntimeError(f"status={self.status_code}")

        class FakeOnePasswordConnectClient:
            def __init__(self, **kwargs: object) -> None:
                del kwargs

            def get(self, path: str) -> FakeResponse:
                assert path == "/v1/vaults/vault-123/items/item-456"
                return FakeResponse(
                    status_code=200,
                    json_data={
                        "id": "item-456",
                        "fields": [{"id": "other", "label": "other", "value": "{}"}],
                    },
                )

            def put(self, path: str, **kwargs: object) -> FakeResponse:
                del path, kwargs
                raise AssertionError("put should not be called when target field is missing")

            def close(self) -> None:
                return None

        monkeypatch.setattr(cli_module.httpx, "Client", FakeOnePasswordConnectClient)

        success = cli_module._write_oauth_cache_payload_to_onepassword_connect(
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="op-prod",
                backend="onepassword_connect",
                op_connect_host="https://op-connect.example.com",
                op_vault_id="vault-123",
                op_item_id="item-456",
                op_field_label="oauth_cache",
                op_connect_token_env="OP_CONNECT_TOKEN",
            ),
            entries={},
        )
        assert success is False

    def test_onepassword_connect_write_bypasses_http_errors(self, monkeypatch):
        """1Password Connect backend write should fail closed on update HTTP failures."""
        monkeypatch.setenv("OP_CONNECT_TOKEN", "op-token-test")

        class FakeResponse:
            def __init__(self, *, status_code: int, json_data: object) -> None:
                self.status_code = status_code
                self._json_data = json_data

            def json(self) -> object:
                return self._json_data

            def raise_for_status(self) -> None:
                if self.status_code >= 400:
                    raise RuntimeError(f"status={self.status_code}")

        class FakeOnePasswordConnectClient:
            def __init__(self, **kwargs: object) -> None:
                del kwargs
                self._put_calls = 0

            def get(self, path: str) -> FakeResponse:
                assert path == "/v1/vaults/vault-123/items/item-456"
                return FakeResponse(
                    status_code=200,
                    json_data={
                        "id": "item-456",
                        "fields": [{"id": "oauth_cache", "label": "oauth_cache", "value": "{}"}],
                    },
                )

            def put(self, path: str, **kwargs: object) -> FakeResponse:
                assert path == "/v1/vaults/vault-123/items/item-456"
                del kwargs
                self._put_calls += 1
                if self._put_calls == 1:
                    return FakeResponse(status_code=404, json_data={})
                return FakeResponse(status_code=500, json_data={})

            def close(self) -> None:
                return None

        monkeypatch.setattr(cli_module.httpx, "Client", FakeOnePasswordConnectClient)

        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="op-prod",
            backend="onepassword_connect",
            op_connect_host="https://op-connect.example.com",
            op_vault_id="vault-123",
            op_item_id="item-456",
            op_field_label="oauth_cache",
            op_connect_token_env="OP_CONNECT_TOKEN",
        )

        assert (
            cli_module._write_oauth_cache_payload_to_onepassword_connect(cache_settings=settings, entries={}) is False
        )
        assert (
            cli_module._write_oauth_cache_payload_to_onepassword_connect(cache_settings=settings, entries={}) is False
        )

    def test_bitwarden_persistent_cache_roundtrip_and_namespace_reuse(self, monkeypatch):
        """Bitwarden backend should persist and reload cache entries across runs."""
        cli_module._clear_oauth_token_cache()
        monkeypatch.setenv("MCP_OAUTH_CLIENT_ID", "client-bw")
        monkeypatch.setenv("MCP_OAUTH_CLIENT_SECRET", "secret-bw")
        monkeypatch.setenv("BWS_ACCESS_TOKEN", "bw-token-test")

        class FakeHTTPError(Exception):
            pass

        class FakeResponse:
            def __init__(self, *, status_code: int, json_data: object) -> None:
                self.status_code = status_code
                self._json_data = json_data

            def json(self) -> object:
                return self._json_data

            def raise_for_status(self) -> None:
                if self.status_code >= 400:
                    raise FakeHTTPError(f"status={self.status_code}")

        class FakeBitwardenClient:
            client_kwargs: ClassVar[list[dict[str, object]]] = []
            put_payloads: ClassVar[list[dict[str, object]]] = []
            secret_value: ClassVar[str] = json.dumps(
                {"schema_version": cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2, "entries": {}},
                sort_keys=True,
            )

            def __init__(self, **kwargs: object) -> None:
                self.__class__.client_kwargs.append(dict(kwargs))

            def get(self, path: str) -> FakeResponse:
                assert path == "/public/secrets/11111111-2222-3333-4444-555555555555"
                return FakeResponse(
                    status_code=200,
                    json_data={
                        "id": "11111111-2222-3333-4444-555555555555",
                        "value": self.__class__.secret_value,
                    },
                )

            def put(self, path: str, **kwargs: object) -> FakeResponse:
                assert path == "/public/secrets/11111111-2222-3333-4444-555555555555"
                raw_payload = kwargs.get("json")
                assert isinstance(raw_payload, dict)
                self.__class__.put_payloads.append(dict(raw_payload))
                value = raw_payload.get("value")
                assert isinstance(value, str)
                self.__class__.secret_value = value
                return FakeResponse(status_code=200, json_data={"success": True})

            def close(self) -> None:
                return None

        monkeypatch.setattr(cli_module.httpx, "Client", FakeBitwardenClient)

        call_count = {"value": 0}

        def fake_request(
            *,
            token_url: str,
            client_id: str,
            client_secret: str,
            scope: str | None,
            audience: str | None,
            token_endpoint_auth_method: str,
            timeout_seconds: int,
        ) -> tuple[str | None, float | None, str | None, int | None]:
            del token_url, client_id, client_secret, scope, audience, token_endpoint_auth_method, timeout_seconds
            call_count["value"] += 1
            return "oauth-bw-token", 3600.0, None, 200

        monkeypatch.setattr(cli_module, "_request_oauth_client_credentials_token", fake_request)

        raw_server_config = {
            "transport": "sse",
            "url": "https://example.com/sse",
            "auth": {
                "type": "oauth_client_credentials",
                "token_url": "https://auth.example.com/oauth/token",
                "client_id_env": "MCP_OAUTH_CLIENT_ID",
                "client_secret_env": "MCP_OAUTH_CLIENT_SECRET",
                "cache": {
                    "persistent": True,
                    "namespace": "bw-prod",
                    "backend": "bitwarden_secrets",
                    "bw_secret_id": "11111111-2222-3333-4444-555555555555",
                    "bw_access_token_env": "BWS_ACCESS_TOKEN",
                    "bw_api_url": "https://api.bitwarden.com",
                },
            },
        }

        first_config, first_finding = _build_connector_config_from_config_entry(
            server_name="oauth_bw_server",
            raw_server_config=raw_server_config,
            timeout=10,
        )
        assert first_finding is None
        assert first_config is not None
        assert first_config["headers"]["Authorization"] == "Bearer oauth-bw-token"
        assert call_count["value"] == 1

        cli_module._clear_oauth_token_cache()
        second_config, second_finding = _build_connector_config_from_config_entry(
            server_name="oauth_bw_server",
            raw_server_config=raw_server_config,
            timeout=10,
        )
        assert second_finding is None
        assert second_config is not None
        assert second_config["headers"]["Authorization"] == "Bearer oauth-bw-token"
        assert call_count["value"] == 1

        persisted_payload = json.loads(FakeBitwardenClient.secret_value)
        assert persisted_payload["schema_version"] == cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2
        assert FakeBitwardenClient.put_payloads
        assert any(item.get("base_url") == "https://api.bitwarden.com" for item in FakeBitwardenClient.client_kwargs)

        cli_module._clear_oauth_token_cache()

    def test_bitwarden_persistent_cache_bypasses_provider_errors(self, monkeypatch):
        """Bitwarden backend cache load should bypass provider errors without raising."""
        monkeypatch.setenv("BWS_ACCESS_TOKEN", "bw-token-test")

        class FakeBitwardenClient:
            def __init__(self, **kwargs: object) -> None:
                del kwargs

            def get(self, path: str) -> dict[str, object]:
                del path
                raise RuntimeError("denied")

            def close(self) -> None:
                return None

        monkeypatch.setattr(cli_module.httpx, "Client", FakeBitwardenClient)

        entries = cli_module._load_oauth_persistent_cache_entries(
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="bw-prod",
                backend="bitwarden_secrets",
                bw_secret_id="11111111-2222-3333-4444-555555555555",
                bw_access_token_env="BWS_ACCESS_TOKEN",
            )
        )
        assert entries == {}

    def test_bitwarden_write_bypasses_missing_secret(self, monkeypatch):
        """Bitwarden backend write should fail closed when target secret does not exist."""
        monkeypatch.setenv("BWS_ACCESS_TOKEN", "bw-token-test")

        class FakeResponse:
            def __init__(self, *, status_code: int, json_data: object) -> None:
                self.status_code = status_code
                self._json_data = json_data

            def json(self) -> object:
                return self._json_data

            def raise_for_status(self) -> None:
                if self.status_code >= 400:
                    raise RuntimeError(f"status={self.status_code}")

        class FakeBitwardenClient:
            def __init__(self, **kwargs: object) -> None:
                del kwargs

            def get(self, path: str) -> FakeResponse:
                assert path == "/public/secrets/11111111-2222-3333-4444-555555555555"
                return FakeResponse(status_code=404, json_data={})

            def put(self, path: str, **kwargs: object) -> FakeResponse:
                del path, kwargs
                raise AssertionError("put should not be called when secret does not exist")

            def close(self) -> None:
                return None

        monkeypatch.setattr(cli_module.httpx, "Client", FakeBitwardenClient)

        success = cli_module._write_oauth_cache_payload_to_bitwarden(
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="bw-prod",
                backend="bitwarden_secrets",
                bw_secret_id="11111111-2222-3333-4444-555555555555",
                bw_access_token_env="BWS_ACCESS_TOKEN",
            ),
            entries={},
        )
        assert success is False

    def test_bitwarden_write_bypasses_http_errors(self, monkeypatch):
        """Bitwarden backend write should fail closed on update HTTP failures."""
        monkeypatch.setenv("BWS_ACCESS_TOKEN", "bw-token-test")

        class FakeResponse:
            def __init__(self, *, status_code: int, json_data: object) -> None:
                self.status_code = status_code
                self._json_data = json_data

            def json(self) -> object:
                return self._json_data

            def raise_for_status(self) -> None:
                if self.status_code >= 400:
                    raise RuntimeError(f"status={self.status_code}")

        class FakeBitwardenClient:
            def __init__(self, **kwargs: object) -> None:
                del kwargs
                self._put_calls = 0

            def get(self, path: str) -> FakeResponse:
                assert path == "/public/secrets/11111111-2222-3333-4444-555555555555"
                return FakeResponse(status_code=200, json_data={"value": "{}"})

            def put(self, path: str, **kwargs: object) -> FakeResponse:
                assert path == "/public/secrets/11111111-2222-3333-4444-555555555555"
                del kwargs
                self._put_calls += 1
                if self._put_calls == 1:
                    return FakeResponse(status_code=404, json_data={})
                return FakeResponse(status_code=500, json_data={})

            def close(self) -> None:
                return None

        monkeypatch.setattr(cli_module.httpx, "Client", FakeBitwardenClient)

        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="bw-prod",
            backend="bitwarden_secrets",
            bw_secret_id="11111111-2222-3333-4444-555555555555",
            bw_access_token_env="BWS_ACCESS_TOKEN",
        )

        assert cli_module._write_oauth_cache_payload_to_bitwarden(cache_settings=settings, entries={}) is False
        assert cli_module._write_oauth_cache_payload_to_bitwarden(cache_settings=settings, entries={}) is False

    def test_read_bitwarden_payload_supports_data_value_fallback(self, monkeypatch):
        """Bitwarden reader should accept envelope from nested data.value payloads."""
        monkeypatch.setenv("BWS_ACCESS_TOKEN", "bw-token-test")

        class FakeResponse:
            def __init__(self, *, status_code: int, json_data: object) -> None:
                self.status_code = status_code
                self._json_data = json_data

            def json(self) -> object:
                return self._json_data

            def raise_for_status(self) -> None:
                if self.status_code >= 400:
                    raise RuntimeError(f"status={self.status_code}")

        class FakeBitwardenClient:
            def __init__(self, **kwargs: object) -> None:
                del kwargs

            def get(self, path: str) -> FakeResponse:
                assert path == "/public/secrets/11111111-2222-3333-4444-555555555555"
                return FakeResponse(
                    status_code=200,
                    json_data={
                        "data": {
                            "value": json.dumps(
                                {"schema_version": cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2, "entries": {}}
                            )
                        }
                    },
                )

            def close(self) -> None:
                return None

        monkeypatch.setattr(cli_module.httpx, "Client", FakeBitwardenClient)

        payload = cli_module._read_oauth_cache_payload_from_bitwarden(
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="bw-prod",
                backend="bitwarden_secrets",
                bw_secret_id="11111111-2222-3333-4444-555555555555",
                bw_access_token_env="BWS_ACCESS_TOKEN",
            )
        )
        assert isinstance(payload, dict)
        assert payload.get("schema_version") == cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2

    def test_read_bitwarden_payload_returns_empty_entries_on_missing_secret(self, monkeypatch):
        """Bitwarden reader should return an empty envelope when secret is not found."""
        monkeypatch.setenv("BWS_ACCESS_TOKEN", "bw-token-test")

        class FakeResponse:
            def __init__(self, *, status_code: int, json_data: object) -> None:
                self.status_code = status_code
                self._json_data = json_data

            def json(self) -> object:
                return self._json_data

            def raise_for_status(self) -> None:
                if self.status_code >= 400:
                    raise RuntimeError(f"status={self.status_code}")

        class FakeBitwardenClient:
            def __init__(self, **kwargs: object) -> None:
                del kwargs

            def get(self, path: str) -> FakeResponse:
                assert path == "/public/secrets/11111111-2222-3333-4444-555555555555"
                return FakeResponse(status_code=404, json_data={})

            def close(self) -> None:
                return None

        monkeypatch.setattr(cli_module.httpx, "Client", FakeBitwardenClient)

        payload = cli_module._read_oauth_cache_payload_from_bitwarden(
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="bw-prod",
                backend="bitwarden_secrets",
                bw_secret_id="11111111-2222-3333-4444-555555555555",
                bw_access_token_env="BWS_ACCESS_TOKEN",
            )
        )
        assert isinstance(payload, dict)
        assert payload.get("entries") == {}

    def test_read_bitwarden_payload_requires_secret_id(self):
        """Bitwarden reader should bypass when secret id is missing."""
        payload = cli_module._read_oauth_cache_payload_from_bitwarden(
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="bw-prod",
                backend="bitwarden_secrets",
                bw_secret_id=None,
                bw_access_token_env="BWS_ACCESS_TOKEN",
            )
        )
        assert payload is None

    def test_build_bitwarden_http_client_handles_invalid_url_and_client_errors(self, monkeypatch):
        """Bitwarden client builder should fail closed on invalid URL and constructor errors."""
        monkeypatch.setenv("BWS_ACCESS_TOKEN", "bw-token-test")

        assert (
            cli_module._build_bitwarden_http_client(
                cache_settings=cli_module.OAuthCacheSettings(
                    persistent=True,
                    namespace="bw-prod",
                    backend="bitwarden_secrets",
                    bw_secret_id="11111111-2222-3333-4444-555555555555",
                    bw_access_token_env="BWS_ACCESS_TOKEN",
                    bw_api_url="   ",
                )
            )
            is None
        )

        monkeypatch.setattr(cli_module.httpx, "Client", lambda **kwargs: (_ for _ in ()).throw(RuntimeError("boom")))
        assert (
            cli_module._build_bitwarden_http_client(
                cache_settings=cli_module.OAuthCacheSettings(
                    persistent=True,
                    namespace="bw-prod",
                    backend="bitwarden_secrets",
                    bw_secret_id="11111111-2222-3333-4444-555555555555",
                    bw_access_token_env="BWS_ACCESS_TOKEN",
                    bw_api_url="https://api.bitwarden.com",
                )
            )
            is None
        )

    def test_bitwarden_write_requires_secret_id_and_token(self, monkeypatch):
        """Bitwarden writer should fail closed when required ID/token inputs are missing."""
        monkeypatch.delenv("BWS_ACCESS_TOKEN", raising=False)

        settings_without_id = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="bw-prod",
            backend="bitwarden_secrets",
            bw_secret_id=None,
            bw_access_token_env="BWS_ACCESS_TOKEN",
        )
        assert (
            cli_module._write_oauth_cache_payload_to_bitwarden(cache_settings=settings_without_id, entries={}) is False
        )

        settings_without_token = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="bw-prod",
            backend="bitwarden_secrets",
            bw_secret_id="11111111-2222-3333-4444-555555555555",
            bw_access_token_env="BWS_ACCESS_TOKEN",
        )
        assert (
            cli_module._write_oauth_cache_payload_to_bitwarden(cache_settings=settings_without_token, entries={})
            is False
        )

    def test_persist_bitwarden_removes_deleted_in_memory_entry(self, monkeypatch):
        """Bitwarden persister should remove cache key when in-memory entry is missing."""
        cli_module._clear_oauth_token_cache()
        seen_entries: dict[str, dict[str, object]] = {}

        monkeypatch.setattr(
            cli_module,
            "_load_oauth_persistent_cache_entries_from_bitwarden",
            lambda *, cache_settings: {"stale-key": {"access_token": "old-token"}},
        )

        def fake_write(*, cache_settings: cli_module.OAuthCacheSettings, entries: dict[str, dict[str, object]]) -> bool:
            del cache_settings
            seen_entries.update(entries)
            return True

        monkeypatch.setattr(cli_module, "_write_oauth_cache_payload_to_bitwarden", fake_write)

        cli_module._persist_oauth_cache_entry_bitwarden(
            cache_key="stale-key",
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="bw-prod",
                backend="bitwarden_secrets",
                bw_secret_id="11111111-2222-3333-4444-555555555555",
                bw_access_token_env="BWS_ACCESS_TOKEN",
            ),
        )

        assert seen_entries == {}

    def test_infisical_persistent_cache_roundtrip_and_namespace_reuse(self, monkeypatch):
        """Infisical backend should persist and reload cache entries across runs."""
        cli_module._clear_oauth_token_cache()
        monkeypatch.setenv("MCP_OAUTH_CLIENT_ID", "client-infisical")
        monkeypatch.setenv("MCP_OAUTH_CLIENT_SECRET", "secret-infisical")
        monkeypatch.setenv("INFISICAL_TOKEN", "infisical-token-test")

        class FakeHTTPError(Exception):
            pass

        class FakeResponse:
            def __init__(self, *, status_code: int, json_data: object) -> None:
                self.status_code = status_code
                self._json_data = json_data

            def json(self) -> object:
                return self._json_data

            def raise_for_status(self) -> None:
                if self.status_code >= 400:
                    raise FakeHTTPError(f"status={self.status_code}")

        class FakeInfisicalClient:
            client_kwargs: ClassVar[list[dict[str, object]]] = []
            post_payloads: ClassVar[list[dict[str, object]]] = []
            secret_value: ClassVar[str] = json.dumps(
                {"schema_version": cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2, "entries": {}},
                sort_keys=True,
            )

            def __init__(self, **kwargs: object) -> None:
                self.__class__.client_kwargs.append(dict(kwargs))

            def get(self, path: str, params: dict[str, str]) -> FakeResponse:
                assert path == "/v3/secrets/raw/MCP_OAUTH_CACHE"
                assert params["workspaceId"] == "workspace-123"
                assert params["environment"] == "prod"
                return FakeResponse(status_code=200, json_data={"secretValue": self.__class__.secret_value})

            def post(self, path: str, **kwargs: object) -> FakeResponse:
                assert path == "/v3/secrets/MCP_OAUTH_CACHE"
                raw_payload = kwargs.get("json")
                assert isinstance(raw_payload, dict)
                self.__class__.post_payloads.append(dict(raw_payload))
                value = raw_payload.get("secretValue")
                assert isinstance(value, str)
                self.__class__.secret_value = value
                return FakeResponse(status_code=200, json_data={"success": True})

            def close(self) -> None:
                return None

        monkeypatch.setattr(cli_module.httpx, "Client", FakeInfisicalClient)

        call_count = {"value": 0}

        def fake_request(
            *,
            token_url: str,
            client_id: str,
            client_secret: str,
            scope: str | None,
            audience: str | None,
            token_endpoint_auth_method: str,
            timeout_seconds: int,
        ) -> tuple[str | None, float | None, str | None, int | None]:
            del token_url, client_id, client_secret, scope, audience, token_endpoint_auth_method, timeout_seconds
            call_count["value"] += 1
            return "oauth-infisical-token", 3600.0, None, 200

        monkeypatch.setattr(cli_module, "_request_oauth_client_credentials_token", fake_request)

        raw_server_config = {
            "transport": "sse",
            "url": "https://example.com/sse",
            "auth": {
                "type": "oauth_client_credentials",
                "token_url": "https://auth.example.com/oauth/token",
                "client_id_env": "MCP_OAUTH_CLIENT_ID",
                "client_secret_env": "MCP_OAUTH_CLIENT_SECRET",
                "cache": {
                    "persistent": True,
                    "namespace": "infisical-prod",
                    "backend": "infisical_secrets",
                    "infisical_project_id": "workspace-123",
                    "infisical_environment": "prod",
                    "infisical_secret_name": "MCP_OAUTH_CACHE",
                    "infisical_token_env": "INFISICAL_TOKEN",
                    "infisical_api_url": "https://app.infisical.com/api",
                },
            },
        }

        first_config, first_finding = _build_connector_config_from_config_entry(
            server_name="oauth_infisical_server",
            raw_server_config=raw_server_config,
            timeout=10,
        )
        assert first_finding is None
        assert first_config is not None
        assert first_config["headers"]["Authorization"] == "Bearer oauth-infisical-token"
        assert call_count["value"] == 1

        cli_module._clear_oauth_token_cache()
        second_config, second_finding = _build_connector_config_from_config_entry(
            server_name="oauth_infisical_server",
            raw_server_config=raw_server_config,
            timeout=10,
        )
        assert second_finding is None
        assert second_config is not None
        assert second_config["headers"]["Authorization"] == "Bearer oauth-infisical-token"
        assert call_count["value"] == 1

        persisted_payload = json.loads(FakeInfisicalClient.secret_value)
        assert persisted_payload["schema_version"] == cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2
        assert FakeInfisicalClient.post_payloads
        assert any(
            item.get("base_url") == "https://app.infisical.com/api" for item in FakeInfisicalClient.client_kwargs
        )

        cli_module._clear_oauth_token_cache()

    def test_infisical_persistent_cache_bypasses_provider_errors(self, monkeypatch):
        """Infisical backend cache load should bypass provider errors without raising."""
        monkeypatch.setenv("INFISICAL_TOKEN", "infisical-token-test")

        class FakeInfisicalClient:
            def __init__(self, **kwargs: object) -> None:
                del kwargs

            def get(self, path: str, params: dict[str, str]) -> dict[str, object]:
                del path, params
                raise RuntimeError("denied")

            def close(self) -> None:
                return None

        monkeypatch.setattr(cli_module.httpx, "Client", FakeInfisicalClient)

        entries = cli_module._load_oauth_persistent_cache_entries(
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="infisical-prod",
                backend="infisical_secrets",
                infisical_project_id="workspace-123",
                infisical_environment="prod",
                infisical_secret_name="MCP_OAUTH_CACHE",
                infisical_token_env="INFISICAL_TOKEN",
            )
        )
        assert entries == {}

    def test_infisical_write_bypasses_missing_secret(self, monkeypatch):
        """Infisical backend write should fail closed when target secret does not exist."""
        monkeypatch.setenv("INFISICAL_TOKEN", "infisical-token-test")

        class FakeResponse:
            def __init__(self, *, status_code: int, json_data: object) -> None:
                self.status_code = status_code
                self._json_data = json_data

            def json(self) -> object:
                return self._json_data

            def raise_for_status(self) -> None:
                if self.status_code >= 400:
                    raise RuntimeError(f"status={self.status_code}")

        class FakeInfisicalClient:
            def __init__(self, **kwargs: object) -> None:
                del kwargs

            def get(self, path: str, params: dict[str, str]) -> FakeResponse:
                assert path == "/v3/secrets/raw/MCP_OAUTH_CACHE"
                assert params["workspaceId"] == "workspace-123"
                assert params["environment"] == "prod"
                return FakeResponse(status_code=404, json_data={})

            def post(self, path: str, **kwargs: object) -> FakeResponse:
                del path, kwargs
                raise AssertionError("post should not be called when secret does not exist")

            def close(self) -> None:
                return None

        monkeypatch.setattr(cli_module.httpx, "Client", FakeInfisicalClient)

        success = cli_module._write_oauth_cache_payload_to_infisical(
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="infisical-prod",
                backend="infisical_secrets",
                infisical_project_id="workspace-123",
                infisical_environment="prod",
                infisical_secret_name="MCP_OAUTH_CACHE",
                infisical_token_env="INFISICAL_TOKEN",
            ),
            entries={},
        )
        assert success is False

    def test_infisical_write_bypasses_http_errors(self, monkeypatch):
        """Infisical backend write should fail closed on update HTTP failures."""
        monkeypatch.setenv("INFISICAL_TOKEN", "infisical-token-test")

        class FakeResponse:
            def __init__(self, *, status_code: int, json_data: object) -> None:
                self.status_code = status_code
                self._json_data = json_data

            def json(self) -> object:
                return self._json_data

            def raise_for_status(self) -> None:
                if self.status_code >= 400:
                    raise RuntimeError(f"status={self.status_code}")

        class FakeInfisicalClient:
            def __init__(self, **kwargs: object) -> None:
                del kwargs
                self._post_calls = 0

            def get(self, path: str, params: dict[str, str]) -> FakeResponse:
                assert path == "/v3/secrets/raw/MCP_OAUTH_CACHE"
                assert params["workspaceId"] == "workspace-123"
                assert params["environment"] == "prod"
                return FakeResponse(status_code=200, json_data={"secretValue": "{}"})

            def post(self, path: str, **kwargs: object) -> FakeResponse:
                assert path == "/v3/secrets/MCP_OAUTH_CACHE"
                del kwargs
                self._post_calls += 1
                if self._post_calls == 1:
                    return FakeResponse(status_code=404, json_data={})
                return FakeResponse(status_code=500, json_data={})

            def close(self) -> None:
                return None

        monkeypatch.setattr(cli_module.httpx, "Client", FakeInfisicalClient)

        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="infisical-prod",
            backend="infisical_secrets",
            infisical_project_id="workspace-123",
            infisical_environment="prod",
            infisical_secret_name="MCP_OAUTH_CACHE",
            infisical_token_env="INFISICAL_TOKEN",
        )

        assert cli_module._write_oauth_cache_payload_to_infisical(cache_settings=settings, entries={}) is False
        assert cli_module._write_oauth_cache_payload_to_infisical(cache_settings=settings, entries={}) is False

    def test_read_infisical_payload_supports_nested_secret_value_fallback(self, monkeypatch):
        """Infisical reader should accept envelope from nested secret.secretValue payloads."""
        monkeypatch.setenv("INFISICAL_TOKEN", "infisical-token-test")

        class FakeResponse:
            def __init__(self, *, status_code: int, json_data: object) -> None:
                self.status_code = status_code
                self._json_data = json_data

            def json(self) -> object:
                return self._json_data

            def raise_for_status(self) -> None:
                if self.status_code >= 400:
                    raise RuntimeError(f"status={self.status_code}")

        class FakeInfisicalClient:
            def __init__(self, **kwargs: object) -> None:
                del kwargs

            def get(self, path: str, params: dict[str, str]) -> FakeResponse:
                assert path == "/v3/secrets/raw/MCP_OAUTH_CACHE"
                assert params["workspaceId"] == "workspace-123"
                assert params["environment"] == "prod"
                return FakeResponse(
                    status_code=200,
                    json_data={
                        "secret": {
                            "secretValue": json.dumps(
                                {"schema_version": cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2, "entries": {}}
                            )
                        }
                    },
                )

            def close(self) -> None:
                return None

        monkeypatch.setattr(cli_module.httpx, "Client", FakeInfisicalClient)

        payload = cli_module._read_oauth_cache_payload_from_infisical(
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="infisical-prod",
                backend="infisical_secrets",
                infisical_project_id="workspace-123",
                infisical_environment="prod",
                infisical_secret_name="MCP_OAUTH_CACHE",
                infisical_token_env="INFISICAL_TOKEN",
            )
        )
        assert isinstance(payload, dict)
        assert payload.get("schema_version") == cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2

    def test_read_infisical_payload_returns_empty_entries_on_missing_secret(self, monkeypatch):
        """Infisical reader should return an empty envelope when secret is not found."""
        monkeypatch.setenv("INFISICAL_TOKEN", "infisical-token-test")

        class FakeResponse:
            def __init__(self, *, status_code: int, json_data: object) -> None:
                self.status_code = status_code
                self._json_data = json_data

            def json(self) -> object:
                return self._json_data

            def raise_for_status(self) -> None:
                if self.status_code >= 400:
                    raise RuntimeError(f"status={self.status_code}")

        class FakeInfisicalClient:
            def __init__(self, **kwargs: object) -> None:
                del kwargs

            def get(self, path: str, params: dict[str, str]) -> FakeResponse:
                assert path == "/v3/secrets/raw/MCP_OAUTH_CACHE"
                assert params["workspaceId"] == "workspace-123"
                assert params["environment"] == "prod"
                return FakeResponse(status_code=404, json_data={})

            def close(self) -> None:
                return None

        monkeypatch.setattr(cli_module.httpx, "Client", FakeInfisicalClient)

        payload = cli_module._read_oauth_cache_payload_from_infisical(
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="infisical-prod",
                backend="infisical_secrets",
                infisical_project_id="workspace-123",
                infisical_environment="prod",
                infisical_secret_name="MCP_OAUTH_CACHE",
                infisical_token_env="INFISICAL_TOKEN",
            )
        )
        assert isinstance(payload, dict)
        assert payload.get("entries") == {}

    def test_read_infisical_payload_requires_required_fields(self):
        """Infisical reader should bypass when required fields are missing."""
        payload = cli_module._read_oauth_cache_payload_from_infisical(
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="infisical-prod",
                backend="infisical_secrets",
                infisical_project_id=None,
                infisical_environment="prod",
                infisical_secret_name="MCP_OAUTH_CACHE",
                infisical_token_env="INFISICAL_TOKEN",
            )
        )
        assert payload is None

    def test_build_infisical_http_client_handles_invalid_url_and_client_errors(self, monkeypatch):
        """Infisical client builder should fail closed on invalid URL and constructor errors."""
        monkeypatch.setenv("INFISICAL_TOKEN", "infisical-token-test")

        assert (
            cli_module._build_infisical_http_client(
                cache_settings=cli_module.OAuthCacheSettings(
                    persistent=True,
                    namespace="infisical-prod",
                    backend="infisical_secrets",
                    infisical_project_id="workspace-123",
                    infisical_environment="prod",
                    infisical_secret_name="MCP_OAUTH_CACHE",
                    infisical_token_env="INFISICAL_TOKEN",
                    infisical_api_url="   ",
                )
            )
            is None
        )

        monkeypatch.setattr(cli_module.httpx, "Client", lambda **kwargs: (_ for _ in ()).throw(RuntimeError("boom")))
        assert (
            cli_module._build_infisical_http_client(
                cache_settings=cli_module.OAuthCacheSettings(
                    persistent=True,
                    namespace="infisical-prod",
                    backend="infisical_secrets",
                    infisical_project_id="workspace-123",
                    infisical_environment="prod",
                    infisical_secret_name="MCP_OAUTH_CACHE",
                    infisical_token_env="INFISICAL_TOKEN",
                    infisical_api_url="https://app.infisical.com/api",
                )
            )
            is None
        )

    def test_infisical_write_requires_secret_identity_and_token(self, monkeypatch):
        """Infisical writer should fail closed when required identity/token inputs are missing."""
        monkeypatch.delenv("INFISICAL_TOKEN", raising=False)

        settings_without_project = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="infisical-prod",
            backend="infisical_secrets",
            infisical_project_id=None,
            infisical_environment="prod",
            infisical_secret_name="MCP_OAUTH_CACHE",
            infisical_token_env="INFISICAL_TOKEN",
        )
        assert (
            cli_module._write_oauth_cache_payload_to_infisical(cache_settings=settings_without_project, entries={})
            is False
        )

        settings_without_token = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="infisical-prod",
            backend="infisical_secrets",
            infisical_project_id="workspace-123",
            infisical_environment="prod",
            infisical_secret_name="MCP_OAUTH_CACHE",
            infisical_token_env="INFISICAL_TOKEN",
        )
        assert (
            cli_module._write_oauth_cache_payload_to_infisical(cache_settings=settings_without_token, entries={})
            is False
        )

    def test_read_infisical_payload_bypasses_status_and_json_shape_errors(self, monkeypatch):
        """Infisical reader should fail closed on status, JSON parse, and JSON shape errors."""
        monkeypatch.setenv("INFISICAL_TOKEN", "infisical-token-test")

        class FakeResponse:
            def __init__(
                self,
                *,
                status_code: int,
                json_data: object,
                json_error: bool = False,
            ) -> None:
                self.status_code = status_code
                self._json_data = json_data
                self._json_error = json_error

            def json(self) -> object:
                if self._json_error:
                    raise ValueError("bad-json")
                return self._json_data

            def raise_for_status(self) -> None:
                if self.status_code >= 400:
                    raise RuntimeError(f"status={self.status_code}")

        class FakeInfisicalClient:
            call_count = 0

            def __init__(self, **kwargs: object) -> None:
                del kwargs

            def get(self, path: str, params: dict[str, str]) -> FakeResponse:
                assert path == "/v3/secrets/raw/MCP_OAUTH_CACHE"
                assert params["workspaceId"] == "workspace-123"
                assert params["environment"] == "prod"
                FakeInfisicalClient.call_count += 1
                if FakeInfisicalClient.call_count == 1:
                    return FakeResponse(status_code=500, json_data={})
                if FakeInfisicalClient.call_count == 2:
                    return FakeResponse(status_code=200, json_data={}, json_error=True)
                return FakeResponse(status_code=200, json_data=[])

            def close(self) -> None:
                return None

        monkeypatch.setattr(cli_module.httpx, "Client", FakeInfisicalClient)

        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="infisical-prod",
            backend="infisical_secrets",
            infisical_project_id="workspace-123",
            infisical_environment="prod",
            infisical_secret_name="MCP_OAUTH_CACHE",
            infisical_token_env="INFISICAL_TOKEN",
        )
        assert cli_module._read_oauth_cache_payload_from_infisical(cache_settings=settings) is None
        assert cli_module._read_oauth_cache_payload_from_infisical(cache_settings=settings) is None
        assert cli_module._read_oauth_cache_payload_from_infisical(cache_settings=settings) is None

    def test_read_infisical_payload_supports_data_value_and_envelope_guards(self, monkeypatch):
        """Infisical reader should use data.value fallback and guard malformed envelopes."""
        monkeypatch.setenv("INFISICAL_TOKEN", "infisical-token-test")

        class FakeResponse:
            def __init__(self, *, status_code: int, json_data: object) -> None:
                self.status_code = status_code
                self._json_data = json_data

            def json(self) -> object:
                return self._json_data

            def raise_for_status(self) -> None:
                if self.status_code >= 400:
                    raise RuntimeError(f"status={self.status_code}")

        class FakeInfisicalClient:
            call_count = 0

            def __init__(self, **kwargs: object) -> None:
                del kwargs

            def get(self, path: str, params: dict[str, str]) -> FakeResponse:
                assert path == "/v3/secrets/raw/MCP_OAUTH_CACHE"
                assert params["workspaceId"] == "workspace-123"
                assert params["environment"] == "prod"
                FakeInfisicalClient.call_count += 1
                if FakeInfisicalClient.call_count == 1:
                    return FakeResponse(
                        status_code=200,
                        json_data={
                            "data": {
                                "value": json.dumps(
                                    {"schema_version": cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2, "entries": {}}
                                )
                            }
                        },
                    )
                if FakeInfisicalClient.call_count == 2:
                    return FakeResponse(status_code=200, json_data={"data": {"value": "{invalid-json"}})
                return FakeResponse(status_code=200, json_data={"data": {"value": "[]"}})

            def close(self) -> None:
                return None

        monkeypatch.setattr(cli_module.httpx, "Client", FakeInfisicalClient)

        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="infisical-prod",
            backend="infisical_secrets",
            infisical_project_id="workspace-123",
            infisical_environment="prod",
            infisical_secret_name="MCP_OAUTH_CACHE",
            infisical_token_env="INFISICAL_TOKEN",
        )

        payload = cli_module._read_oauth_cache_payload_from_infisical(cache_settings=settings)
        assert isinstance(payload, dict)
        assert payload.get("schema_version") == cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2
        assert cli_module._read_oauth_cache_payload_from_infisical(cache_settings=settings) is None
        assert cli_module._read_oauth_cache_payload_from_infisical(cache_settings=settings) is None

    def test_infisical_write_bypasses_preflight_and_post_exceptions(self, monkeypatch):
        """Infisical writer should fail closed on preflight and update exception paths."""
        monkeypatch.setenv("INFISICAL_TOKEN", "infisical-token-test")

        class FakeResponse:
            def __init__(self, *, status_code: int, json_data: object) -> None:
                self.status_code = status_code
                self._json_data = json_data

            def json(self) -> object:
                return self._json_data

            def raise_for_status(self) -> None:
                if self.status_code >= 400:
                    raise RuntimeError(f"status={self.status_code}")

        class FakeInfisicalClient:
            init_count = 0

            def __init__(self, **kwargs: object) -> None:
                del kwargs
                FakeInfisicalClient.init_count += 1
                self._scenario = FakeInfisicalClient.init_count

            def get(self, path: str, params: dict[str, str]) -> FakeResponse:
                assert path == "/v3/secrets/raw/MCP_OAUTH_CACHE"
                assert params["workspaceId"] == "workspace-123"
                assert params["environment"] == "prod"
                if self._scenario == 1:
                    raise RuntimeError("preflight-get-failed")
                if self._scenario == 2:
                    return FakeResponse(status_code=500, json_data={})
                return FakeResponse(status_code=200, json_data={"secretValue": "{}"})

            def post(self, path: str, **kwargs: object) -> FakeResponse:
                assert path == "/v3/secrets/MCP_OAUTH_CACHE"
                del kwargs
                if self._scenario == 3:
                    raise RuntimeError("post-failed")
                if self._scenario == 4:
                    return FakeResponse(status_code=500, json_data={})
                raise AssertionError("unexpected scenario")

            def close(self) -> None:
                return None

        monkeypatch.setattr(cli_module.httpx, "Client", FakeInfisicalClient)

        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="infisical-prod",
            backend="infisical_secrets",
            infisical_project_id="workspace-123",
            infisical_environment="prod",
            infisical_secret_name="MCP_OAUTH_CACHE",
            infisical_token_env="INFISICAL_TOKEN",
        )
        assert cli_module._write_oauth_cache_payload_to_infisical(cache_settings=settings, entries={}) is False
        assert cli_module._write_oauth_cache_payload_to_infisical(cache_settings=settings, entries={}) is False
        assert cli_module._write_oauth_cache_payload_to_infisical(cache_settings=settings, entries={}) is False
        assert cli_module._write_oauth_cache_payload_to_infisical(cache_settings=settings, entries={}) is False

    def test_persist_infisical_removes_deleted_in_memory_entry(self, monkeypatch):
        """Infisical persister should remove cache key when in-memory entry is missing."""
        cli_module._clear_oauth_token_cache()
        seen_entries: dict[str, dict[str, object]] = {}

        monkeypatch.setattr(
            cli_module,
            "_load_oauth_persistent_cache_entries_from_infisical",
            lambda *, cache_settings: {"stale-key": {"access_token": "old-token"}},
        )

        def fake_write(*, cache_settings: cli_module.OAuthCacheSettings, entries: dict[str, dict[str, object]]) -> bool:
            del cache_settings
            seen_entries.update(entries)
            return True

        monkeypatch.setattr(cli_module, "_write_oauth_cache_payload_to_infisical", fake_write)

        cli_module._persist_oauth_cache_entry_infisical(
            cache_key="stale-key",
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="infisical-prod",
                backend="infisical_secrets",
                infisical_project_id="workspace-123",
                infisical_environment="prod",
                infisical_secret_name="MCP_OAUTH_CACHE",
                infisical_token_env="INFISICAL_TOKEN",
            ),
        )

        assert seen_entries == {}

    def test_read_akeyless_payload_supports_value_and_data_fallback(self, monkeypatch):
        """Akeyless reader should parse envelope from value and data.value payloads."""
        monkeypatch.setenv("AKEYLESS_TOKEN", "akeyless-token-test")

        class FakeResponse:
            def __init__(self, *, status_code: int, json_data: object) -> None:
                self.status_code = status_code
                self._json_data = json_data

            def json(self) -> object:
                return self._json_data

            def raise_for_status(self) -> None:
                if self.status_code >= 400:
                    raise RuntimeError(f"status={self.status_code}")

        class FakeAkeylessClient:
            call_count = 0

            def __init__(self, **kwargs: object) -> None:
                del kwargs

            def post(self, path: str, **kwargs: object) -> FakeResponse:
                assert path == "/api/v2/get-secret-value"
                assert kwargs["json"]["name"] == "/prod/mcp/oauth_cache"
                FakeAkeylessClient.call_count += 1
                if FakeAkeylessClient.call_count == 1:
                    return FakeResponse(
                        status_code=200,
                        json_data={
                            "value": json.dumps(
                                {"schema_version": cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2, "entries": {}}
                            )
                        },
                    )
                return FakeResponse(
                    status_code=200,
                    json_data={
                        "data": {
                            "value": json.dumps(
                                {"schema_version": cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2, "entries": {}}
                            )
                        }
                    },
                )

            def close(self) -> None:
                return None

        monkeypatch.setattr(cli_module.httpx, "Client", FakeAkeylessClient)
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="akeyless-prod",
            backend="akeyless_secrets",
            akeyless_secret_name="/prod/mcp/oauth_cache",
            akeyless_token_env="AKEYLESS_TOKEN",
            akeyless_api_url="https://api.akeyless.io",
        )

        first = cli_module._read_oauth_cache_payload_from_akeyless(cache_settings=settings)
        second = cli_module._read_oauth_cache_payload_from_akeyless(cache_settings=settings)
        assert isinstance(first, dict)
        assert isinstance(second, dict)
        assert first.get("schema_version") == cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2
        assert second.get("schema_version") == cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2

    def test_read_akeyless_payload_bypasses_errors_and_missing_secret(self, monkeypatch):
        """Akeyless reader should fail closed for errors and map 404 to empty envelope."""
        monkeypatch.setenv("AKEYLESS_TOKEN", "akeyless-token-test")

        class FakeResponse:
            def __init__(self, *, status_code: int, json_data: object, json_error: bool = False) -> None:
                self.status_code = status_code
                self._json_data = json_data
                self._json_error = json_error

            def json(self) -> object:
                if self._json_error:
                    raise ValueError("bad-json")
                return self._json_data

            def raise_for_status(self) -> None:
                if self.status_code >= 400:
                    raise RuntimeError(f"status={self.status_code}")

        class FakeAkeylessClient:
            call_count = 0

            def __init__(self, **kwargs: object) -> None:
                del kwargs

            def post(self, path: str, **kwargs: object) -> FakeResponse:
                assert path == "/api/v2/get-secret-value"
                del kwargs
                FakeAkeylessClient.call_count += 1
                if FakeAkeylessClient.call_count == 1:
                    return FakeResponse(status_code=404, json_data={})
                if FakeAkeylessClient.call_count == 2:
                    return FakeResponse(status_code=500, json_data={})
                if FakeAkeylessClient.call_count == 3:
                    return FakeResponse(status_code=200, json_data={}, json_error=True)
                return FakeResponse(status_code=200, json_data={"value": "{invalid-json"})

            def close(self) -> None:
                return None

        monkeypatch.setattr(cli_module.httpx, "Client", FakeAkeylessClient)
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="akeyless-prod",
            backend="akeyless_secrets",
            akeyless_secret_name="/prod/mcp/oauth_cache",
            akeyless_token_env="AKEYLESS_TOKEN",
        )

        first = cli_module._read_oauth_cache_payload_from_akeyless(cache_settings=settings)
        second = cli_module._read_oauth_cache_payload_from_akeyless(cache_settings=settings)
        third = cli_module._read_oauth_cache_payload_from_akeyless(cache_settings=settings)
        fourth = cli_module._read_oauth_cache_payload_from_akeyless(cache_settings=settings)
        assert isinstance(first, dict)
        assert first.get("entries") == {}
        assert second is None
        assert third is None
        assert fourth is None

    def test_akeyless_write_success_and_bypass_paths(self, monkeypatch):
        """Akeyless writer should support success flow and fail-closed preflight/post paths."""
        monkeypatch.setenv("AKEYLESS_TOKEN", "akeyless-token-test")

        class FakeResponse:
            def __init__(self, *, status_code: int, json_data: object) -> None:
                self.status_code = status_code
                self._json_data = json_data

            def json(self) -> object:
                return self._json_data

            def raise_for_status(self) -> None:
                if self.status_code >= 400:
                    raise RuntimeError(f"status={self.status_code}")

        class FakeAkeylessClient:
            init_count = 0

            def __init__(self, **kwargs: object) -> None:
                del kwargs
                FakeAkeylessClient.init_count += 1
                self._scenario = FakeAkeylessClient.init_count
                self._post_calls = 0

            def post(self, path: str, **kwargs: object) -> FakeResponse:
                self._post_calls += 1
                if self._scenario == 1:
                    if self._post_calls == 1:
                        assert path == "/api/v2/get-secret-value"
                        return FakeResponse(status_code=200, json_data={"value": "{}"})
                    assert path == "/api/v2/set-secret-value"
                    return FakeResponse(status_code=200, json_data={})
                if self._scenario == 2:
                    assert path == "/api/v2/get-secret-value"
                    return FakeResponse(status_code=404, json_data={})
                if self._scenario == 3:
                    assert path == "/api/v2/get-secret-value"
                    return FakeResponse(status_code=500, json_data={})
                if self._scenario == 4:
                    if self._post_calls == 1:
                        assert path == "/api/v2/get-secret-value"
                        return FakeResponse(status_code=200, json_data={"value": "{}"})
                    raise RuntimeError("post-write-failed")
                raise AssertionError("unexpected scenario")

            def close(self) -> None:
                return None

        monkeypatch.setattr(cli_module.httpx, "Client", FakeAkeylessClient)
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="akeyless-prod",
            backend="akeyless_secrets",
            akeyless_secret_name="/prod/mcp/oauth_cache",
            akeyless_token_env="AKEYLESS_TOKEN",
        )

        assert cli_module._write_oauth_cache_payload_to_akeyless(cache_settings=settings, entries={}) is True
        assert cli_module._write_oauth_cache_payload_to_akeyless(cache_settings=settings, entries={}) is False
        assert cli_module._write_oauth_cache_payload_to_akeyless(cache_settings=settings, entries={}) is False
        assert cli_module._write_oauth_cache_payload_to_akeyless(cache_settings=settings, entries={}) is False

    def test_akeyless_build_client_and_required_guards(self, monkeypatch):
        """Akeyless client/writer should fail closed when token/url/secret identity are missing."""
        monkeypatch.delenv("AKEYLESS_TOKEN", raising=False)

        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="akeyless-prod",
            backend="akeyless_secrets",
            akeyless_secret_name="/prod/mcp/oauth_cache",
            akeyless_token_env="AKEYLESS_TOKEN",
        )
        assert cli_module._build_akeyless_http_client(cache_settings=settings) is None
        assert cli_module._read_oauth_cache_payload_from_akeyless(cache_settings=settings) is None
        assert cli_module._write_oauth_cache_payload_to_akeyless(cache_settings=settings, entries={}) is False

        monkeypatch.setenv("AKEYLESS_TOKEN", "token")
        assert (
            cli_module._build_akeyless_http_client(
                cache_settings=cli_module.OAuthCacheSettings(
                    persistent=True,
                    namespace="akeyless-prod",
                    backend="akeyless_secrets",
                    akeyless_secret_name="/prod/mcp/oauth_cache",
                    akeyless_token_env="AKEYLESS_TOKEN",
                    akeyless_api_url="   ",
                )
            )
            is None
        )

    def test_persist_akeyless_removes_deleted_in_memory_entry(self, monkeypatch):
        """Akeyless persister should remove cache key when in-memory entry is missing."""
        cli_module._clear_oauth_token_cache()
        seen_entries: dict[str, dict[str, object]] = {}

        monkeypatch.setattr(
            cli_module,
            "_load_oauth_persistent_cache_entries_from_akeyless",
            lambda *, cache_settings: {"stale-key": {"access_token": "old-token"}},
        )

        def fake_write(*, cache_settings: cli_module.OAuthCacheSettings, entries: dict[str, dict[str, object]]) -> bool:
            del cache_settings
            seen_entries.update(entries)
            return True

        monkeypatch.setattr(cli_module, "_write_oauth_cache_payload_to_akeyless", fake_write)

        cli_module._persist_oauth_cache_entry_akeyless(
            cache_key="stale-key",
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="akeyless-prod",
                backend="akeyless_secrets",
                akeyless_secret_name="/prod/mcp/oauth_cache",
                akeyless_token_env="AKEYLESS_TOKEN",
            ),
        )

        assert seen_entries == {}

    def test_read_gitlab_payload_supports_value_and_variable_fallback(self, monkeypatch):
        """GitLab reader should parse envelope from value and variable.value payloads."""
        monkeypatch.setenv("GITLAB_TOKEN", "gitlab-token-test")

        class FakeResponse:
            def __init__(self, *, status_code: int, json_data: object) -> None:
                self.status_code = status_code
                self._json_data = json_data

            def json(self) -> object:
                return self._json_data

            def raise_for_status(self) -> None:
                if self.status_code >= 400:
                    raise RuntimeError(f"status={self.status_code}")

        class FakeGitLabClient:
            call_count = 0

            def __init__(self, **kwargs: object) -> None:
                del kwargs

            def get(self, path: str, **kwargs: object) -> FakeResponse:
                assert path == "/projects/12345/variables/MCP_OAUTH_CACHE"
                assert kwargs.get("params") == {"filter[environment_scope]": "*"}
                FakeGitLabClient.call_count += 1
                if FakeGitLabClient.call_count == 1:
                    return FakeResponse(
                        status_code=200,
                        json_data={
                            "value": json.dumps(
                                {"schema_version": cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2, "entries": {}}
                            )
                        },
                    )
                return FakeResponse(
                    status_code=200,
                    json_data={
                        "variable": {
                            "value": json.dumps(
                                {"schema_version": cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2, "entries": {}}
                            )
                        }
                    },
                )

            def close(self) -> None:
                return None

        monkeypatch.setattr(cli_module.httpx, "Client", FakeGitLabClient)
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="gitlab-prod",
            backend="gitlab_variables",
            gitlab_project_id="12345",
            gitlab_variable_key="MCP_OAUTH_CACHE",
            gitlab_token_env="GITLAB_TOKEN",
            gitlab_api_url="https://gitlab.example.com/api/v4",
        )

        first = cli_module._read_oauth_cache_payload_from_gitlab(cache_settings=settings)
        second = cli_module._read_oauth_cache_payload_from_gitlab(cache_settings=settings)
        assert isinstance(first, dict)
        assert isinstance(second, dict)
        assert first.get("schema_version") == cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2
        assert second.get("schema_version") == cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2

    def test_read_gitlab_payload_bypasses_errors_and_missing_variable(self, monkeypatch):
        """GitLab reader should fail closed for errors and map 404 to empty envelope."""
        monkeypatch.setenv("GITLAB_TOKEN", "gitlab-token-test")

        class FakeResponse:
            def __init__(self, *, status_code: int, json_data: object, json_error: bool = False) -> None:
                self.status_code = status_code
                self._json_data = json_data
                self._json_error = json_error

            def json(self) -> object:
                if self._json_error:
                    raise ValueError("bad-json")
                return self._json_data

            def raise_for_status(self) -> None:
                if self.status_code >= 400:
                    raise RuntimeError(f"status={self.status_code}")

        class FakeGitLabClient:
            call_count = 0

            def __init__(self, **kwargs: object) -> None:
                del kwargs

            def get(self, path: str, **kwargs: object) -> FakeResponse:
                assert path == "/projects/12345/variables/MCP_OAUTH_CACHE"
                assert kwargs.get("params") == {"filter[environment_scope]": "*"}
                FakeGitLabClient.call_count += 1
                if FakeGitLabClient.call_count == 1:
                    return FakeResponse(status_code=404, json_data={})
                if FakeGitLabClient.call_count == 2:
                    return FakeResponse(status_code=500, json_data={})
                if FakeGitLabClient.call_count == 3:
                    return FakeResponse(status_code=200, json_data={}, json_error=True)
                return FakeResponse(status_code=200, json_data={"value": "{invalid-json"})

            def close(self) -> None:
                return None

        monkeypatch.setattr(cli_module.httpx, "Client", FakeGitLabClient)
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="gitlab-prod",
            backend="gitlab_variables",
            gitlab_project_id="12345",
            gitlab_variable_key="MCP_OAUTH_CACHE",
            gitlab_token_env="GITLAB_TOKEN",
        )

        first = cli_module._read_oauth_cache_payload_from_gitlab(cache_settings=settings)
        second = cli_module._read_oauth_cache_payload_from_gitlab(cache_settings=settings)
        third = cli_module._read_oauth_cache_payload_from_gitlab(cache_settings=settings)
        fourth = cli_module._read_oauth_cache_payload_from_gitlab(cache_settings=settings)
        assert isinstance(first, dict)
        assert first.get("entries") == {}
        assert second is None
        assert third is None
        assert fourth is None

    def test_gitlab_write_success_and_bypass_paths(self, monkeypatch):
        """GitLab writer should support success flow and fail-closed preflight/post paths."""
        monkeypatch.setenv("GITLAB_TOKEN", "gitlab-token-test")

        class FakeResponse:
            def __init__(self, *, status_code: int, json_data: object) -> None:
                self.status_code = status_code
                self._json_data = json_data

            def json(self) -> object:
                return self._json_data

            def raise_for_status(self) -> None:
                if self.status_code >= 400:
                    raise RuntimeError(f"status={self.status_code}")

        class FakeGitLabClient:
            init_count = 0

            def __init__(self, **kwargs: object) -> None:
                del kwargs
                FakeGitLabClient.init_count += 1
                self._scenario = FakeGitLabClient.init_count
                self._get_calls = 0

            def get(self, path: str, **kwargs: object) -> FakeResponse:
                assert path == "/projects/12345/variables/MCP_OAUTH_CACHE"
                assert kwargs.get("params") == {"filter[environment_scope]": "*"}
                self._get_calls += 1
                if self._scenario == 1:
                    return FakeResponse(status_code=200, json_data={"value": "{}"})
                if self._scenario == 2:
                    return FakeResponse(status_code=404, json_data={})
                if self._scenario == 3:
                    return FakeResponse(status_code=500, json_data={})
                return FakeResponse(status_code=200, json_data={"value": "{}"})

            def put(self, path: str, **kwargs: object) -> FakeResponse:
                assert path == "/projects/12345/variables/MCP_OAUTH_CACHE"
                assert kwargs.get("params") == {"filter[environment_scope]": "*"}
                if self._scenario == 1:
                    payload = kwargs.get("data")
                    assert isinstance(payload, dict)
                    assert isinstance(payload.get("value"), str)
                    assert payload.get("environment_scope") == "*"
                    return FakeResponse(status_code=200, json_data={})
                raise RuntimeError("post-write-failed")

            def close(self) -> None:
                return None

        monkeypatch.setattr(cli_module.httpx, "Client", FakeGitLabClient)
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="gitlab-prod",
            backend="gitlab_variables",
            gitlab_project_id="12345",
            gitlab_variable_key="MCP_OAUTH_CACHE",
            gitlab_token_env="GITLAB_TOKEN",
        )

        assert cli_module._write_oauth_cache_payload_to_gitlab(cache_settings=settings, entries={}) is True
        assert cli_module._write_oauth_cache_payload_to_gitlab(cache_settings=settings, entries={}) is False
        assert cli_module._write_oauth_cache_payload_to_gitlab(cache_settings=settings, entries={}) is False
        assert cli_module._write_oauth_cache_payload_to_gitlab(cache_settings=settings, entries={}) is False

    def test_gitlab_build_client_and_required_guards(self, monkeypatch):
        """GitLab client/reader/writer should fail closed when token/url/identity is missing."""
        monkeypatch.delenv("GITLAB_TOKEN", raising=False)

        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="gitlab-prod",
            backend="gitlab_variables",
            gitlab_project_id="12345",
            gitlab_variable_key="MCP_OAUTH_CACHE",
            gitlab_token_env="GITLAB_TOKEN",
        )
        assert cli_module._build_gitlab_http_client(cache_settings=settings) is None
        assert cli_module._read_oauth_cache_payload_from_gitlab(cache_settings=settings) is None
        assert cli_module._write_oauth_cache_payload_to_gitlab(cache_settings=settings, entries={}) is False

        monkeypatch.setenv("GITLAB_TOKEN", "token")
        assert (
            cli_module._build_gitlab_http_client(
                cache_settings=cli_module.OAuthCacheSettings(
                    persistent=True,
                    namespace="gitlab-prod",
                    backend="gitlab_variables",
                    gitlab_project_id="12345",
                    gitlab_variable_key="MCP_OAUTH_CACHE",
                    gitlab_token_env="GITLAB_TOKEN",
                    gitlab_api_url="   ",
                )
            )
            is None
        )

        missing_settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="gitlab-prod",
            backend="gitlab_variables",
            gitlab_project_id=None,
            gitlab_variable_key="MCP_OAUTH_CACHE",
            gitlab_token_env="GITLAB_TOKEN",
        )
        assert cli_module._read_oauth_cache_payload_from_gitlab(cache_settings=missing_settings) is None
        assert cli_module._write_oauth_cache_payload_to_gitlab(cache_settings=missing_settings, entries={}) is False

    def test_gitlab_variable_path_supports_project_group_and_instance_backends(self):
        """GitLab variable path/query builder should support project, group, and instance backends."""
        capabilities = cli_module._GITLAB_OAUTH_CACHE_BACKEND_CAPABILITIES

        assert set(capabilities) == {
            "gitlab_variables",
            "gitlab_group_variables",
            "gitlab_instance_variables",
        }
        assert capabilities["gitlab_variables"].identifier_field == "gitlab_project_id"
        assert capabilities["gitlab_variables"].supports_environment_scope is True
        assert capabilities["gitlab_group_variables"].identifier_field == "gitlab_group_id"
        assert capabilities["gitlab_group_variables"].supports_environment_scope is True
        assert capabilities["gitlab_instance_variables"].identifier_field is None
        assert capabilities["gitlab_instance_variables"].supports_environment_scope is False

        project_settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="gitlab-prod",
            backend="gitlab_variables",
            gitlab_project_id="12345",
            gitlab_variable_key="MCP_OAUTH_CACHE",
        )
        group_settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="gitlab-prod",
            backend="gitlab_group_variables",
            gitlab_group_id="67890",
            gitlab_variable_key="MCP_OAUTH_CACHE",
        )
        instance_settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="gitlab-prod",
            backend="gitlab_instance_variables",
            gitlab_variable_key="MCP_OAUTH_CACHE",
        )

        assert cli_module._build_gitlab_variable_path(cache_settings=project_settings) == (
            "/projects/12345/variables/MCP_OAUTH_CACHE"
        )
        assert cli_module._build_gitlab_variable_path(cache_settings=group_settings) == (
            "/groups/67890/variables/MCP_OAUTH_CACHE"
        )
        assert cli_module._build_gitlab_variable_path(cache_settings=instance_settings) == (
            "/admin/ci/variables/MCP_OAUTH_CACHE"
        )
        assert cli_module._build_gitlab_variable_query_params(cache_settings=project_settings) == {
            "filter[environment_scope]": "*"
        }
        assert cli_module._build_gitlab_variable_query_params(cache_settings=group_settings) == {
            "filter[environment_scope]": "*"
        }
        assert cli_module._build_gitlab_variable_query_params(cache_settings=instance_settings) == {}

    def test_gitlab_group_read_and_write_use_group_variable_path(self, monkeypatch):
        """GitLab group backend should read/write through /groups/<id>/variables/<key> path."""
        monkeypatch.setenv("GITLAB_TOKEN", "gitlab-token-test")

        class FakeResponse:
            def __init__(self, *, status_code: int, json_data: object) -> None:
                self.status_code = status_code
                self._json_data = json_data

            def json(self) -> object:
                return self._json_data

            def raise_for_status(self) -> None:
                if self.status_code >= 400:
                    raise RuntimeError(f"status={self.status_code}")

        saw_get_requests: list[tuple[str, object]] = []
        saw_put_requests: list[tuple[str, object, object]] = []
        scenario = {"value": 0}

        class FakeGitLabClient:

            def __init__(self, **kwargs: object) -> None:
                del kwargs

            def get(self, path: str, **kwargs: object) -> FakeResponse:
                saw_get_requests.append((path, kwargs.get("params")))
                if scenario["value"] == 0:
                    scenario["value"] = 1
                    return FakeResponse(
                        status_code=200,
                        json_data={
                            "value": json.dumps(
                                {"schema_version": cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2, "entries": {}}
                            )
                        },
                    )
                return FakeResponse(status_code=200, json_data={"value": "{}"})

            def put(self, path: str, **kwargs: object) -> FakeResponse:
                saw_put_requests.append((path, kwargs.get("params"), kwargs.get("data")))
                payload = kwargs.get("data")
                assert isinstance(payload, dict)
                assert isinstance(payload.get("value"), str)
                assert payload.get("environment_scope") == "production"
                return FakeResponse(status_code=200, json_data={})

            def close(self) -> None:
                return None

        monkeypatch.setattr(cli_module.httpx, "Client", FakeGitLabClient)

        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="gitlab-group",
            backend="gitlab_group_variables",
            gitlab_group_id="67890",
            gitlab_variable_key="MCP_OAUTH_CACHE",
            gitlab_environment_scope="production",
            gitlab_token_env="GITLAB_TOKEN",
            gitlab_api_url="https://gitlab.example.com/api/v4",
        )

        payload = cli_module._read_oauth_cache_payload_from_gitlab(cache_settings=settings)
        wrote = cli_module._write_oauth_cache_payload_to_gitlab(cache_settings=settings, entries={})

        assert isinstance(payload, dict)
        assert wrote is True
        assert saw_get_requests[0] == (
            "/groups/67890/variables/MCP_OAUTH_CACHE",
            {"filter[environment_scope]": "production"},
        )
        assert saw_put_requests[0][0] == "/groups/67890/variables/MCP_OAUTH_CACHE"
        assert saw_put_requests[0][1] == {"filter[environment_scope]": "production"}

    def test_gitlab_instance_read_and_write_use_instance_variable_path(self, monkeypatch):
        """GitLab instance backend should read/write through /admin/ci/variables/<key> path."""
        monkeypatch.setenv("GITLAB_TOKEN", "gitlab-token-test")

        class FakeResponse:
            def __init__(self, *, status_code: int, json_data: object) -> None:
                self.status_code = status_code
                self._json_data = json_data

            def json(self) -> object:
                return self._json_data

            def raise_for_status(self) -> None:
                if self.status_code >= 400:
                    raise RuntimeError(f"status={self.status_code}")

        saw_get_requests: list[tuple[str, object]] = []
        saw_put_requests: list[tuple[str, object, object]] = []
        scenario = {"value": 0}

        class FakeGitLabClient:

            def __init__(self, **kwargs: object) -> None:
                del kwargs

            def get(self, path: str, **kwargs: object) -> FakeResponse:
                saw_get_requests.append((path, kwargs.get("params")))
                if scenario["value"] == 0:
                    scenario["value"] = 1
                    return FakeResponse(
                        status_code=200,
                        json_data={
                            "value": json.dumps(
                                {"schema_version": cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2, "entries": {}}
                            )
                        },
                    )
                return FakeResponse(status_code=200, json_data={"value": "{}"})

            def put(self, path: str, **kwargs: object) -> FakeResponse:
                saw_put_requests.append((path, kwargs.get("params"), kwargs.get("data")))
                payload = kwargs.get("data")
                assert isinstance(payload, dict)
                assert isinstance(payload.get("value"), str)
                assert "environment_scope" not in payload
                return FakeResponse(status_code=200, json_data={})

            def close(self) -> None:
                return None

        monkeypatch.setattr(cli_module.httpx, "Client", FakeGitLabClient)

        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="gitlab-instance",
            backend="gitlab_instance_variables",
            gitlab_variable_key="MCP_OAUTH_CACHE",
            gitlab_token_env="GITLAB_TOKEN",
            gitlab_api_url="https://gitlab.example.com/api/v4",
        )

        payload = cli_module._read_oauth_cache_payload_from_gitlab(cache_settings=settings)
        wrote = cli_module._write_oauth_cache_payload_to_gitlab(cache_settings=settings, entries={})

        assert isinstance(payload, dict)
        assert wrote is True
        assert saw_get_requests[0] == ("/admin/ci/variables/MCP_OAUTH_CACHE", {})
        assert saw_put_requests[0][0] == "/admin/ci/variables/MCP_OAUTH_CACHE"
        assert saw_put_requests[0][1] == {}

    def test_persist_gitlab_removes_deleted_in_memory_entry(self, monkeypatch):
        """GitLab persister should remove cache key when in-memory entry is missing."""
        cli_module._clear_oauth_token_cache()
        seen_entries: dict[str, dict[str, object]] = {}

        monkeypatch.setattr(
            cli_module,
            "_load_oauth_persistent_cache_entries_from_gitlab",
            lambda *, cache_settings: {"stale-key": {"access_token": "old-token"}},
        )

        def fake_write(*, cache_settings: cli_module.OAuthCacheSettings, entries: dict[str, dict[str, object]]) -> bool:
            del cache_settings
            seen_entries.update(entries)
            return True

        monkeypatch.setattr(cli_module, "_write_oauth_cache_payload_to_gitlab", fake_write)

        cli_module._persist_oauth_cache_entry_gitlab(
            cache_key="stale-key",
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="gitlab-prod",
                backend="gitlab_variables",
                gitlab_project_id="12345",
                gitlab_variable_key="MCP_OAUTH_CACHE",
                gitlab_token_env="GITLAB_TOKEN",
            ),
        )

        assert seen_entries == {}

    def test_read_github_payload_supports_value_and_variable_fallback(self, monkeypatch):
        """GitHub reader should parse envelope from value and variable.value payloads."""
        monkeypatch.setenv("GITHUB_TOKEN", "github-token-test")

        class FakeResponse:
            def __init__(self, *, status_code: int, json_data: object) -> None:
                self.status_code = status_code
                self._json_data = json_data

            def json(self) -> object:
                return self._json_data

            def raise_for_status(self) -> None:
                if self.status_code >= 400:
                    raise RuntimeError(f"status={self.status_code}")

        class FakeGitHubClient:
            call_count = 0

            def __init__(self, **kwargs: object) -> None:
                del kwargs

            def get(self, path: str, **kwargs: object) -> FakeResponse:
                del kwargs
                assert path == "/repos/ogulcanaydogan/mcp-security-scanner/actions/variables/MCP_OAUTH_CACHE"
                FakeGitHubClient.call_count += 1
                if FakeGitHubClient.call_count == 1:
                    return FakeResponse(
                        status_code=200,
                        json_data={
                            "value": json.dumps(
                                {"schema_version": cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2, "entries": {}}
                            )
                        },
                    )
                return FakeResponse(
                    status_code=200,
                    json_data={
                        "variable": {
                            "value": json.dumps(
                                {"schema_version": cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2, "entries": {}}
                            )
                        }
                    },
                )

            def close(self) -> None:
                return None

        monkeypatch.setattr(cli_module.httpx, "Client", FakeGitHubClient)
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="github-prod",
            backend="github_actions_variables",
            github_repository="ogulcanaydogan/mcp-security-scanner",
            github_variable_name="MCP_OAUTH_CACHE",
            github_token_env="GITHUB_TOKEN",
            github_api_url="https://api.github.com",
        )

        first = cli_module._read_oauth_cache_payload_from_github(cache_settings=settings)
        second = cli_module._read_oauth_cache_payload_from_github(cache_settings=settings)
        assert isinstance(first, dict)
        assert isinstance(second, dict)
        assert first.get("schema_version") == cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2
        assert second.get("schema_version") == cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2

    def test_read_github_payload_bypasses_errors_and_missing_variable(self, monkeypatch):
        """GitHub reader should fail closed for errors and map 404 to empty envelope."""
        monkeypatch.setenv("GITHUB_TOKEN", "github-token-test")

        class FakeResponse:
            def __init__(self, *, status_code: int, json_data: object, json_error: bool = False) -> None:
                self.status_code = status_code
                self._json_data = json_data
                self._json_error = json_error

            def json(self) -> object:
                if self._json_error:
                    raise ValueError("bad-json")
                return self._json_data

            def raise_for_status(self) -> None:
                if self.status_code >= 400:
                    raise RuntimeError(f"status={self.status_code}")

        class FakeGitHubClient:
            call_count = 0

            def __init__(self, **kwargs: object) -> None:
                del kwargs

            def get(self, path: str, **kwargs: object) -> FakeResponse:
                del path, kwargs
                FakeGitHubClient.call_count += 1
                if FakeGitHubClient.call_count == 1:
                    return FakeResponse(status_code=404, json_data={})
                if FakeGitHubClient.call_count == 2:
                    return FakeResponse(status_code=500, json_data={})
                if FakeGitHubClient.call_count == 3:
                    return FakeResponse(status_code=200, json_data={}, json_error=True)
                return FakeResponse(status_code=200, json_data={"value": "{invalid-json"})

            def close(self) -> None:
                return None

        monkeypatch.setattr(cli_module.httpx, "Client", FakeGitHubClient)
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="github-prod",
            backend="github_actions_variables",
            github_repository="ogulcanaydogan/mcp-security-scanner",
            github_variable_name="MCP_OAUTH_CACHE",
            github_token_env="GITHUB_TOKEN",
        )

        first = cli_module._read_oauth_cache_payload_from_github(cache_settings=settings)
        second = cli_module._read_oauth_cache_payload_from_github(cache_settings=settings)
        third = cli_module._read_oauth_cache_payload_from_github(cache_settings=settings)
        fourth = cli_module._read_oauth_cache_payload_from_github(cache_settings=settings)
        assert isinstance(first, dict)
        assert first.get("entries") == {}
        assert second is None
        assert third is None
        assert fourth is None

    def test_github_write_success_and_bypass_paths(self, monkeypatch):
        """GitHub writer should support success flow and fail-closed preflight/post paths."""
        monkeypatch.setenv("GITHUB_TOKEN", "github-token-test")

        class FakeResponse:
            def __init__(self, *, status_code: int, json_data: object) -> None:
                self.status_code = status_code
                self._json_data = json_data

            def json(self) -> object:
                return self._json_data

            def raise_for_status(self) -> None:
                if self.status_code >= 400:
                    raise RuntimeError(f"status={self.status_code}")

        class FakeGitHubClient:
            init_count = 0

            def __init__(self, **kwargs: object) -> None:
                del kwargs
                FakeGitHubClient.init_count += 1
                self._scenario = FakeGitHubClient.init_count

            def get(self, path: str, **kwargs: object) -> FakeResponse:
                del kwargs
                assert path == "/repos/ogulcanaydogan/mcp-security-scanner/actions/variables/MCP_OAUTH_CACHE"
                if self._scenario == 1:
                    return FakeResponse(status_code=200, json_data={"value": "{}"})
                if self._scenario == 2:
                    return FakeResponse(status_code=404, json_data={})
                if self._scenario == 3:
                    return FakeResponse(status_code=500, json_data={})
                return FakeResponse(status_code=200, json_data={"value": "{}"})

            def patch(self, path: str, **kwargs: object) -> FakeResponse:
                assert path == "/repos/ogulcanaydogan/mcp-security-scanner/actions/variables/MCP_OAUTH_CACHE"
                if self._scenario == 1:
                    payload = kwargs.get("json")
                    assert isinstance(payload, dict)
                    assert payload.get("name") == "MCP_OAUTH_CACHE"
                    assert isinstance(payload.get("value"), str)
                    return FakeResponse(status_code=204, json_data={})
                raise RuntimeError("post-write-failed")

            def close(self) -> None:
                return None

        monkeypatch.setattr(cli_module.httpx, "Client", FakeGitHubClient)
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="github-prod",
            backend="github_actions_variables",
            github_repository="ogulcanaydogan/mcp-security-scanner",
            github_variable_name="MCP_OAUTH_CACHE",
            github_token_env="GITHUB_TOKEN",
        )

        assert cli_module._write_oauth_cache_payload_to_github(cache_settings=settings, entries={}) is True
        assert cli_module._write_oauth_cache_payload_to_github(cache_settings=settings, entries={}) is False
        assert cli_module._write_oauth_cache_payload_to_github(cache_settings=settings, entries={}) is False
        assert cli_module._write_oauth_cache_payload_to_github(cache_settings=settings, entries={}) is False

    def test_github_build_client_and_required_guards(self, monkeypatch):
        """GitHub client/reader/writer should fail closed when token/url/identity is missing."""
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)

        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="github-prod",
            backend="github_actions_variables",
            github_repository="ogulcanaydogan/mcp-security-scanner",
            github_variable_name="MCP_OAUTH_CACHE",
            github_token_env="GITHUB_TOKEN",
        )
        assert cli_module._build_github_http_client(cache_settings=settings) is None
        assert cli_module._read_oauth_cache_payload_from_github(cache_settings=settings) is None
        assert cli_module._write_oauth_cache_payload_to_github(cache_settings=settings, entries={}) is False

        monkeypatch.setenv("GITHUB_TOKEN", "token")
        assert (
            cli_module._build_github_http_client(
                cache_settings=cli_module.OAuthCacheSettings(
                    persistent=True,
                    namespace="github-prod",
                    backend="github_actions_variables",
                    github_repository="ogulcanaydogan/mcp-security-scanner",
                    github_variable_name="MCP_OAUTH_CACHE",
                    github_token_env="GITHUB_TOKEN",
                    github_api_url="   ",
                )
            )
            is None
        )

        missing_settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="github-prod",
            backend="github_actions_variables",
            github_repository=None,
            github_variable_name="MCP_OAUTH_CACHE",
            github_token_env="GITHUB_TOKEN",
        )
        assert cli_module._read_oauth_cache_payload_from_github(cache_settings=missing_settings) is None
        assert cli_module._write_oauth_cache_payload_to_github(cache_settings=missing_settings, entries={}) is False

    def test_persist_github_removes_deleted_in_memory_entry(self, monkeypatch):
        """GitHub persister should remove cache key when in-memory entry is missing."""
        cli_module._clear_oauth_token_cache()
        seen_entries: dict[str, dict[str, object]] = {}

        monkeypatch.setattr(
            cli_module,
            "_load_oauth_persistent_cache_entries_from_github",
            lambda *, cache_settings: {"stale-key": {"access_token": "old-token"}},
        )

        def fake_write(*, cache_settings: cli_module.OAuthCacheSettings, entries: dict[str, dict[str, object]]) -> bool:
            del cache_settings
            seen_entries.update(entries)
            return True

        monkeypatch.setattr(cli_module, "_write_oauth_cache_payload_to_github", fake_write)

        cli_module._persist_oauth_cache_entry_github(
            cache_key="stale-key",
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="github-prod",
                backend="github_actions_variables",
                github_repository="ogulcanaydogan/mcp-security-scanner",
                github_variable_name="MCP_OAUTH_CACHE",
                github_token_env="GITHUB_TOKEN",
            ),
        )

        assert seen_entries == {}

    def test_build_github_environment_variable_path_encodes_environment_name(self):
        """GitHub environment variable path should URL-encode environment name segment."""
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="github-prod",
            backend="github_environment_variables",
            github_repository="ogulcanaydogan/mcp-security-scanner",
            github_environment_name="Prod Blue/Primary",
            github_variable_name="MCP_OAUTH_CACHE",
        )

        path = cli_module._build_github_environment_variable_path(cache_settings=settings)

        assert (
            path
            == "/repos/ogulcanaydogan/mcp-security-scanner/environments/Prod%20Blue%2FPrimary/variables/MCP_OAUTH_CACHE"
        )

    def test_read_github_environment_payload_supports_value_and_variable_fallback(self, monkeypatch):
        """GitHub environment reader should parse envelope from value and variable.value payloads."""
        monkeypatch.setenv("GITHUB_TOKEN", "github-token-test")

        class FakeResponse:
            def __init__(self, *, status_code: int, json_data: object) -> None:
                self.status_code = status_code
                self._json_data = json_data

            def json(self) -> object:
                return self._json_data

            def raise_for_status(self) -> None:
                if self.status_code >= 400:
                    raise RuntimeError(f"status={self.status_code}")

        class FakeGitHubClient:
            call_count = 0

            def __init__(self, **kwargs: object) -> None:
                del kwargs

            def get(self, path: str, **kwargs: object) -> FakeResponse:
                del kwargs
                assert (
                    path
                    == "/repos/ogulcanaydogan/mcp-security-scanner/environments/production/variables/MCP_OAUTH_CACHE"
                )
                FakeGitHubClient.call_count += 1
                if FakeGitHubClient.call_count == 1:
                    return FakeResponse(
                        status_code=200,
                        json_data={
                            "value": json.dumps(
                                {"schema_version": cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2, "entries": {}}
                            )
                        },
                    )
                return FakeResponse(
                    status_code=200,
                    json_data={
                        "variable": {
                            "value": json.dumps(
                                {"schema_version": cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2, "entries": {}}
                            )
                        }
                    },
                )

            def close(self) -> None:
                return None

        monkeypatch.setattr(cli_module.httpx, "Client", FakeGitHubClient)
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="github-prod",
            backend="github_environment_variables",
            github_repository="ogulcanaydogan/mcp-security-scanner",
            github_environment_name="production",
            github_variable_name="MCP_OAUTH_CACHE",
            github_token_env="GITHUB_TOKEN",
            github_api_url="https://api.github.com",
        )

        first = cli_module._read_oauth_cache_payload_from_github_environment(cache_settings=settings)
        second = cli_module._read_oauth_cache_payload_from_github_environment(cache_settings=settings)
        assert isinstance(first, dict)
        assert isinstance(second, dict)
        assert first.get("schema_version") == cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2
        assert second.get("schema_version") == cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2

    def test_read_github_environment_payload_bypasses_errors_and_missing_variable(self, monkeypatch):
        """GitHub environment reader should fail closed for errors and map 404 to empty envelope."""
        monkeypatch.setenv("GITHUB_TOKEN", "github-token-test")

        class FakeResponse:
            def __init__(self, *, status_code: int, json_data: object, json_error: bool = False) -> None:
                self.status_code = status_code
                self._json_data = json_data
                self._json_error = json_error

            def json(self) -> object:
                if self._json_error:
                    raise ValueError("bad-json")
                return self._json_data

            def raise_for_status(self) -> None:
                if self.status_code >= 400:
                    raise RuntimeError(f"status={self.status_code}")

        class FakeGitHubClient:
            call_count = 0

            def __init__(self, **kwargs: object) -> None:
                del kwargs

            def get(self, path: str, **kwargs: object) -> FakeResponse:
                del path, kwargs
                FakeGitHubClient.call_count += 1
                if FakeGitHubClient.call_count == 1:
                    return FakeResponse(status_code=404, json_data={})
                if FakeGitHubClient.call_count == 2:
                    return FakeResponse(status_code=500, json_data={})
                if FakeGitHubClient.call_count == 3:
                    return FakeResponse(status_code=200, json_data={}, json_error=True)
                return FakeResponse(status_code=200, json_data={"value": "{invalid-json"})

            def close(self) -> None:
                return None

        monkeypatch.setattr(cli_module.httpx, "Client", FakeGitHubClient)
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="github-prod",
            backend="github_environment_variables",
            github_repository="ogulcanaydogan/mcp-security-scanner",
            github_environment_name="production",
            github_variable_name="MCP_OAUTH_CACHE",
            github_token_env="GITHUB_TOKEN",
        )

        first = cli_module._read_oauth_cache_payload_from_github_environment(cache_settings=settings)
        second = cli_module._read_oauth_cache_payload_from_github_environment(cache_settings=settings)
        third = cli_module._read_oauth_cache_payload_from_github_environment(cache_settings=settings)
        fourth = cli_module._read_oauth_cache_payload_from_github_environment(cache_settings=settings)
        assert isinstance(first, dict)
        assert first.get("entries") == {}
        assert second is None
        assert third is None
        assert fourth is None

    def test_github_environment_write_success_and_bypass_paths(self, monkeypatch):
        """GitHub environment writer should support success flow and fail-closed preflight/post paths."""
        monkeypatch.setenv("GITHUB_TOKEN", "github-token-test")

        class FakeResponse:
            def __init__(self, *, status_code: int, json_data: object) -> None:
                self.status_code = status_code
                self._json_data = json_data

            def json(self) -> object:
                return self._json_data

            def raise_for_status(self) -> None:
                if self.status_code >= 400:
                    raise RuntimeError(f"status={self.status_code}")

        class FakeGitHubClient:
            init_count = 0

            def __init__(self, **kwargs: object) -> None:
                del kwargs
                FakeGitHubClient.init_count += 1
                self._scenario = FakeGitHubClient.init_count

            def get(self, path: str, **kwargs: object) -> FakeResponse:
                del kwargs
                assert (
                    path
                    == "/repos/ogulcanaydogan/mcp-security-scanner/environments/production/variables/MCP_OAUTH_CACHE"
                )
                if self._scenario == 1:
                    return FakeResponse(status_code=200, json_data={"value": "{}"})
                if self._scenario == 2:
                    return FakeResponse(status_code=404, json_data={})
                if self._scenario == 3:
                    return FakeResponse(status_code=500, json_data={})
                return FakeResponse(status_code=200, json_data={"value": "{}"})

            def patch(self, path: str, **kwargs: object) -> FakeResponse:
                assert (
                    path
                    == "/repos/ogulcanaydogan/mcp-security-scanner/environments/production/variables/MCP_OAUTH_CACHE"
                )
                if self._scenario == 1:
                    payload = kwargs.get("json")
                    assert isinstance(payload, dict)
                    assert payload.get("name") == "MCP_OAUTH_CACHE"
                    assert isinstance(payload.get("value"), str)
                    return FakeResponse(status_code=204, json_data={})
                raise RuntimeError("post-write-failed")

            def close(self) -> None:
                return None

        monkeypatch.setattr(cli_module.httpx, "Client", FakeGitHubClient)
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="github-prod",
            backend="github_environment_variables",
            github_repository="ogulcanaydogan/mcp-security-scanner",
            github_environment_name="production",
            github_variable_name="MCP_OAUTH_CACHE",
            github_token_env="GITHUB_TOKEN",
        )

        assert cli_module._write_oauth_cache_payload_to_github_environment(cache_settings=settings, entries={}) is True
        assert cli_module._write_oauth_cache_payload_to_github_environment(cache_settings=settings, entries={}) is False
        assert cli_module._write_oauth_cache_payload_to_github_environment(cache_settings=settings, entries={}) is False
        assert cli_module._write_oauth_cache_payload_to_github_environment(cache_settings=settings, entries={}) is False

    def test_github_environment_build_client_and_required_guards(self, monkeypatch):
        """GitHub environment helpers should fail closed when token/url/identity is missing."""
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)

        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="github-prod",
            backend="github_environment_variables",
            github_repository="ogulcanaydogan/mcp-security-scanner",
            github_environment_name="production",
            github_variable_name="MCP_OAUTH_CACHE",
            github_token_env="GITHUB_TOKEN",
        )
        assert cli_module._build_github_http_client(cache_settings=settings) is None
        assert cli_module._read_oauth_cache_payload_from_github_environment(cache_settings=settings) is None
        assert cli_module._write_oauth_cache_payload_to_github_environment(cache_settings=settings, entries={}) is False

        monkeypatch.setenv("GITHUB_TOKEN", "token")
        assert (
            cli_module._build_github_http_client(
                cache_settings=cli_module.OAuthCacheSettings(
                    persistent=True,
                    namespace="github-prod",
                    backend="github_environment_variables",
                    github_repository="ogulcanaydogan/mcp-security-scanner",
                    github_environment_name="production",
                    github_variable_name="MCP_OAUTH_CACHE",
                    github_token_env="GITHUB_TOKEN",
                    github_api_url="   ",
                )
            )
            is None
        )

        missing_settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="github-prod",
            backend="github_environment_variables",
            github_repository="ogulcanaydogan/mcp-security-scanner",
            github_environment_name=None,
            github_variable_name="MCP_OAUTH_CACHE",
            github_token_env="GITHUB_TOKEN",
        )
        assert cli_module._read_oauth_cache_payload_from_github_environment(cache_settings=missing_settings) is None
        assert (
            cli_module._write_oauth_cache_payload_to_github_environment(cache_settings=missing_settings, entries={})
            is False
        )

    def test_persist_github_environment_removes_deleted_in_memory_entry(self, monkeypatch):
        """GitHub environment persister should remove cache key when in-memory entry is missing."""
        cli_module._clear_oauth_token_cache()
        seen_entries: dict[str, dict[str, object]] = {}

        monkeypatch.setattr(
            cli_module,
            "_load_oauth_persistent_cache_entries_from_github_environment",
            lambda *, cache_settings: {"stale-key": {"access_token": "old-token"}},
        )

        def fake_write(*, cache_settings: cli_module.OAuthCacheSettings, entries: dict[str, dict[str, object]]) -> bool:
            del cache_settings
            seen_entries.update(entries)
            return True

        monkeypatch.setattr(cli_module, "_write_oauth_cache_payload_to_github_environment", fake_write)

        cli_module._persist_oauth_cache_entry_github_environment(
            cache_key="stale-key",
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="github-prod",
                backend="github_environment_variables",
                github_repository="ogulcanaydogan/mcp-security-scanner",
                github_environment_name="production",
                github_variable_name="MCP_OAUTH_CACHE",
                github_token_env="GITHUB_TOKEN",
            ),
        )

        assert seen_entries == {}

    def test_build_github_organization_variable_path_encodes_organization_name(self):
        """GitHub organization variable path should URL-encode organization segment."""
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="github-prod",
            backend="github_organization_variables",
            github_organization="acme security",
            github_variable_name="MCP_OAUTH_CACHE",
        )

        path = cli_module._build_github_organization_variable_path(cache_settings=settings)

        assert path == "/orgs/acme%20security/actions/variables/MCP_OAUTH_CACHE"

    def test_read_github_organization_payload_supports_value_and_variable_fallback(self, monkeypatch):
        """GitHub organization reader should parse envelope from value and variable.value payloads."""
        monkeypatch.setenv("GITHUB_TOKEN", "github-token-test")

        class FakeResponse:
            def __init__(self, *, status_code: int, json_data: object) -> None:
                self.status_code = status_code
                self._json_data = json_data

            def json(self) -> object:
                return self._json_data

            def raise_for_status(self) -> None:
                if self.status_code >= 400:
                    raise RuntimeError(f"status={self.status_code}")

        class FakeGitHubClient:
            call_count = 0

            def __init__(self, **kwargs: object) -> None:
                del kwargs

            def get(self, path: str, **kwargs: object) -> FakeResponse:
                del kwargs
                assert path == "/orgs/ogulcanaydogan/actions/variables/MCP_OAUTH_CACHE"
                FakeGitHubClient.call_count += 1
                if FakeGitHubClient.call_count == 1:
                    return FakeResponse(
                        status_code=200,
                        json_data={
                            "value": json.dumps(
                                {"schema_version": cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2, "entries": {}}
                            )
                        },
                    )
                return FakeResponse(
                    status_code=200,
                    json_data={
                        "variable": {
                            "value": json.dumps(
                                {"schema_version": cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2, "entries": {}}
                            )
                        }
                    },
                )

            def close(self) -> None:
                return None

        monkeypatch.setattr(cli_module.httpx, "Client", FakeGitHubClient)
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="github-prod",
            backend="github_organization_variables",
            github_organization="ogulcanaydogan",
            github_variable_name="MCP_OAUTH_CACHE",
            github_token_env="GITHUB_TOKEN",
            github_api_url="https://api.github.com",
        )

        first = cli_module._read_oauth_cache_payload_from_github_organization(cache_settings=settings)
        second = cli_module._read_oauth_cache_payload_from_github_organization(cache_settings=settings)
        assert isinstance(first, dict)
        assert isinstance(second, dict)
        assert first.get("schema_version") == cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2
        assert second.get("schema_version") == cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2

    def test_read_github_organization_payload_bypasses_errors_and_missing_variable(self, monkeypatch):
        """GitHub organization reader should fail closed for errors and map 404 to empty envelope."""
        monkeypatch.setenv("GITHUB_TOKEN", "github-token-test")

        class FakeResponse:
            def __init__(self, *, status_code: int, json_data: object, json_error: bool = False) -> None:
                self.status_code = status_code
                self._json_data = json_data
                self._json_error = json_error

            def json(self) -> object:
                if self._json_error:
                    raise ValueError("bad-json")
                return self._json_data

            def raise_for_status(self) -> None:
                if self.status_code >= 400:
                    raise RuntimeError(f"status={self.status_code}")

        class FakeGitHubClient:
            call_count = 0

            def __init__(self, **kwargs: object) -> None:
                del kwargs

            def get(self, path: str, **kwargs: object) -> FakeResponse:
                del path, kwargs
                FakeGitHubClient.call_count += 1
                if FakeGitHubClient.call_count == 1:
                    return FakeResponse(status_code=404, json_data={})
                if FakeGitHubClient.call_count == 2:
                    return FakeResponse(status_code=500, json_data={})
                if FakeGitHubClient.call_count == 3:
                    return FakeResponse(status_code=200, json_data={}, json_error=True)
                return FakeResponse(status_code=200, json_data={"value": "{invalid-json"})

            def close(self) -> None:
                return None

        monkeypatch.setattr(cli_module.httpx, "Client", FakeGitHubClient)
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="github-prod",
            backend="github_organization_variables",
            github_organization="ogulcanaydogan",
            github_variable_name="MCP_OAUTH_CACHE",
            github_token_env="GITHUB_TOKEN",
        )

        first = cli_module._read_oauth_cache_payload_from_github_organization(cache_settings=settings)
        second = cli_module._read_oauth_cache_payload_from_github_organization(cache_settings=settings)
        third = cli_module._read_oauth_cache_payload_from_github_organization(cache_settings=settings)
        fourth = cli_module._read_oauth_cache_payload_from_github_organization(cache_settings=settings)
        assert isinstance(first, dict)
        assert first.get("entries") == {}
        assert second is None
        assert third is None
        assert fourth is None

    def test_github_organization_write_success_and_bypass_paths(self, monkeypatch):
        """GitHub organization writer should support success flow and fail-closed preflight/post paths."""
        monkeypatch.setenv("GITHUB_TOKEN", "github-token-test")

        class FakeResponse:
            def __init__(self, *, status_code: int, json_data: object) -> None:
                self.status_code = status_code
                self._json_data = json_data

            def json(self) -> object:
                return self._json_data

            def raise_for_status(self) -> None:
                if self.status_code >= 400:
                    raise RuntimeError(f"status={self.status_code}")

        class FakeGitHubClient:
            init_count = 0

            def __init__(self, **kwargs: object) -> None:
                del kwargs
                FakeGitHubClient.init_count += 1
                self._scenario = FakeGitHubClient.init_count

            def get(self, path: str, **kwargs: object) -> FakeResponse:
                del kwargs
                selected_url = (
                    "https://api.github.com/orgs/ogulcanaydogan/actions/variables/MCP_OAUTH_CACHE/repositories"
                )
                if path == "/orgs/ogulcanaydogan/actions/variables/MCP_OAUTH_CACHE":
                    if self._scenario == 1:
                        return FakeResponse(status_code=200, json_data={"visibility": "all", "value": "{}"})
                    if self._scenario == 2:
                        return FakeResponse(status_code=200, json_data={"visibility": "private", "value": "{}"})
                    if self._scenario == 3:
                        return FakeResponse(
                            status_code=200,
                            json_data={
                                "visibility": "selected",
                                "selected_repositories_url": selected_url,
                                "value": "{}",
                            },
                        )
                    if self._scenario == 4:
                        return FakeResponse(status_code=200, json_data={"value": "{}"})
                    if self._scenario == 5:
                        return FakeResponse(status_code=200, json_data={"visibility": "selected", "value": "{}"})
                    if self._scenario == 6:
                        return FakeResponse(
                            status_code=200,
                            json_data={
                                "visibility": "selected",
                                "selected_repositories_url": selected_url,
                                "value": "{}",
                            },
                        )
                    if self._scenario == 7:
                        return FakeResponse(status_code=404, json_data={})
                    if self._scenario == 8:
                        return FakeResponse(status_code=500, json_data={})
                    return FakeResponse(status_code=200, json_data={"visibility": "all", "value": "{}"})
                if self._scenario == 3 and path == selected_url:
                    return FakeResponse(status_code=200, json_data={"repositories": [{"id": 101}, {"id": 202}]})
                if self._scenario == 6 and path == selected_url:
                    return FakeResponse(status_code=200, json_data={"repositories": [{"id": "bad"}]})
                return FakeResponse(status_code=500, json_data={})

            def patch(self, path: str, **kwargs: object) -> FakeResponse:
                assert path == "/orgs/ogulcanaydogan/actions/variables/MCP_OAUTH_CACHE"
                payload = kwargs.get("json")
                assert isinstance(payload, dict)
                assert payload.get("name") == "MCP_OAUTH_CACHE"
                assert isinstance(payload.get("value"), str)
                if self._scenario == 1:
                    assert payload.get("visibility") == "all"
                    assert "selected_repository_ids" not in payload
                    return FakeResponse(status_code=204, json_data={})
                if self._scenario == 2:
                    assert payload.get("visibility") == "private"
                    assert "selected_repository_ids" not in payload
                    return FakeResponse(status_code=204, json_data={})
                if self._scenario == 3:
                    assert payload.get("visibility") == "selected"
                    assert payload.get("selected_repository_ids") == [101, 202]
                    return FakeResponse(status_code=204, json_data={})
                if self._scenario == 9:
                    assert payload.get("visibility") == "all"
                raise RuntimeError("post-write-failed")

            def close(self) -> None:
                return None

        monkeypatch.setattr(cli_module.httpx, "Client", FakeGitHubClient)
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="github-prod",
            backend="github_organization_variables",
            github_organization="ogulcanaydogan",
            github_variable_name="MCP_OAUTH_CACHE",
            github_token_env="GITHUB_TOKEN",
        )

        assert cli_module._write_oauth_cache_payload_to_github_organization(cache_settings=settings, entries={}) is True
        assert cli_module._write_oauth_cache_payload_to_github_organization(cache_settings=settings, entries={}) is True
        assert cli_module._write_oauth_cache_payload_to_github_organization(cache_settings=settings, entries={}) is True
        assert (
            cli_module._write_oauth_cache_payload_to_github_organization(cache_settings=settings, entries={}) is False
        )
        assert (
            cli_module._write_oauth_cache_payload_to_github_organization(cache_settings=settings, entries={}) is False
        )
        assert (
            cli_module._write_oauth_cache_payload_to_github_organization(cache_settings=settings, entries={}) is False
        )
        assert (
            cli_module._write_oauth_cache_payload_to_github_organization(cache_settings=settings, entries={}) is False
        )
        assert (
            cli_module._write_oauth_cache_payload_to_github_organization(cache_settings=settings, entries={}) is False
        )
        assert (
            cli_module._write_oauth_cache_payload_to_github_organization(cache_settings=settings, entries={}) is False
        )

    def test_github_organization_build_client_and_required_guards(self, monkeypatch):
        """GitHub organization helpers should fail closed when token/url/identity is missing."""
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)

        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="github-prod",
            backend="github_organization_variables",
            github_organization="ogulcanaydogan",
            github_variable_name="MCP_OAUTH_CACHE",
            github_token_env="GITHUB_TOKEN",
        )
        assert cli_module._build_github_http_client(cache_settings=settings) is None
        assert cli_module._read_oauth_cache_payload_from_github_organization(cache_settings=settings) is None
        assert (
            cli_module._write_oauth_cache_payload_to_github_organization(cache_settings=settings, entries={}) is False
        )

        monkeypatch.setenv("GITHUB_TOKEN", "token")
        assert (
            cli_module._build_github_http_client(
                cache_settings=cli_module.OAuthCacheSettings(
                    persistent=True,
                    namespace="github-prod",
                    backend="github_organization_variables",
                    github_organization="ogulcanaydogan",
                    github_variable_name="MCP_OAUTH_CACHE",
                    github_token_env="GITHUB_TOKEN",
                    github_api_url="   ",
                )
            )
            is None
        )

        missing_settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="github-prod",
            backend="github_organization_variables",
            github_organization=None,
            github_variable_name="MCP_OAUTH_CACHE",
            github_token_env="GITHUB_TOKEN",
        )
        assert cli_module._read_oauth_cache_payload_from_github_organization(cache_settings=missing_settings) is None
        assert (
            cli_module._write_oauth_cache_payload_to_github_organization(
                cache_settings=missing_settings,
                entries={},
            )
            is False
        )

    def test_persist_github_organization_removes_deleted_in_memory_entry(self, monkeypatch):
        """GitHub organization persister should remove cache key when in-memory entry is missing."""
        cli_module._clear_oauth_token_cache()
        seen_entries: dict[str, dict[str, object]] = {}

        monkeypatch.setattr(
            cli_module,
            "_load_oauth_persistent_cache_entries_from_github_organization",
            lambda *, cache_settings: {"stale-key": {"access_token": "old-token"}},
        )

        def fake_write(*, cache_settings: cli_module.OAuthCacheSettings, entries: dict[str, dict[str, object]]) -> bool:
            del cache_settings
            seen_entries.update(entries)
            return True

        monkeypatch.setattr(cli_module, "_write_oauth_cache_payload_to_github_organization", fake_write)

        cli_module._persist_oauth_cache_entry_github_organization(
            cache_key="stale-key",
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="github-prod",
                backend="github_organization_variables",
                github_organization="ogulcanaydogan",
                github_variable_name="MCP_OAUTH_CACHE",
                github_token_env="GITHUB_TOKEN",
            ),
        )

        assert seen_entries == {}

    def test_build_consul_kv_path_encodes_key_path(self):
        """Consul KV path builder should URL-encode key segments while preserving slashes."""
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="consul-prod",
            backend="consul_kv",
            consul_key_path="mcp security/oauth cache",
        )

        path = cli_module._build_consul_kv_path(cache_settings=settings)

        assert path == "/v1/kv/mcp%20security/oauth%20cache"

    def test_read_consul_payload_parses_raw_value(self, monkeypatch):
        """Consul reader should parse envelope from raw KV response body."""
        monkeypatch.setenv("CONSUL_HTTP_TOKEN", "consul-token-test")

        class FakeResponse:
            def __init__(self, *, status_code: int, text: str) -> None:
                self.status_code = status_code
                self.text = text

            def raise_for_status(self) -> None:
                if self.status_code >= 400:
                    raise RuntimeError(f"status={self.status_code}")

        class FakeConsulClient:
            call_count = 0

            def __init__(self, **kwargs: object) -> None:
                del kwargs

            def get(self, path: str, **kwargs: object) -> FakeResponse:
                assert path == "/v1/kv/mcp/security/oauth/cache"
                assert kwargs.get("params") == {"raw": "true"}
                FakeConsulClient.call_count += 1
                if FakeConsulClient.call_count == 1:
                    return FakeResponse(
                        status_code=200,
                        text=json.dumps({"schema_version": cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2, "entries": {}}),
                    )
                return FakeResponse(status_code=200, text="")

            def close(self) -> None:
                return None

        monkeypatch.setattr(cli_module.httpx, "Client", FakeConsulClient)
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="consul-prod",
            backend="consul_kv",
            consul_key_path="mcp/security/oauth/cache",
            consul_token_env="CONSUL_HTTP_TOKEN",
            consul_api_url="https://consul.example.com",
        )

        first = cli_module._read_oauth_cache_payload_from_consul(cache_settings=settings)
        second = cli_module._read_oauth_cache_payload_from_consul(cache_settings=settings)
        assert isinstance(first, dict)
        assert first.get("schema_version") == cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2
        assert isinstance(second, dict)
        assert second.get("entries") == {}

    def test_read_consul_payload_bypasses_errors_and_missing_key(self, monkeypatch):
        """Consul reader should fail closed for errors and map missing key to empty envelope."""
        monkeypatch.setenv("CONSUL_HTTP_TOKEN", "consul-token-test")

        class FakeResponse:
            def __init__(self, *, status_code: int, text: str) -> None:
                self.status_code = status_code
                self.text = text

            def raise_for_status(self) -> None:
                if self.status_code >= 400:
                    raise RuntimeError(f"status={self.status_code}")

        class FakeConsulClient:
            call_count = 0

            def __init__(self, **kwargs: object) -> None:
                del kwargs

            def get(self, path: str, **kwargs: object) -> FakeResponse:
                del path, kwargs
                FakeConsulClient.call_count += 1
                if FakeConsulClient.call_count == 1:
                    return FakeResponse(status_code=404, text="")
                if FakeConsulClient.call_count == 2:
                    return FakeResponse(status_code=500, text="")
                return FakeResponse(status_code=200, text="{invalid-json")

            def close(self) -> None:
                return None

        monkeypatch.setattr(cli_module.httpx, "Client", FakeConsulClient)
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="consul-prod",
            backend="consul_kv",
            consul_key_path="mcp/security/oauth/cache",
            consul_token_env="CONSUL_HTTP_TOKEN",
        )

        first = cli_module._read_oauth_cache_payload_from_consul(cache_settings=settings)
        second = cli_module._read_oauth_cache_payload_from_consul(cache_settings=settings)
        third = cli_module._read_oauth_cache_payload_from_consul(cache_settings=settings)
        assert isinstance(first, dict)
        assert first.get("entries") == {}
        assert second is None
        assert third is None

    def test_consul_write_success_and_bypass_paths(self, monkeypatch):
        """Consul writer should support success flow and fail-closed preflight/post paths."""
        monkeypatch.setenv("CONSUL_HTTP_TOKEN", "consul-token-test")

        class FakeResponse:
            def __init__(self, *, status_code: int, text: str = "") -> None:
                self.status_code = status_code
                self.text = text

            def raise_for_status(self) -> None:
                if self.status_code >= 400:
                    raise RuntimeError(f"status={self.status_code}")

        class FakeConsulClient:
            init_count = 0

            def __init__(self, **kwargs: object) -> None:
                del kwargs
                FakeConsulClient.init_count += 1
                self._scenario = FakeConsulClient.init_count

            def get(self, path: str, **kwargs: object) -> FakeResponse:
                assert path == "/v1/kv/mcp/security/oauth/cache"
                assert kwargs.get("params") == {"raw": "true"}
                if self._scenario == 1:
                    return FakeResponse(status_code=200, text="{}")
                if self._scenario == 2:
                    return FakeResponse(status_code=404)
                if self._scenario == 3:
                    return FakeResponse(status_code=500)
                return FakeResponse(status_code=200, text="{}")

            def put(self, path: str, **kwargs: object) -> FakeResponse:
                assert path == "/v1/kv/mcp/security/oauth/cache"
                if self._scenario == 1:
                    payload = kwargs.get("content")
                    assert isinstance(payload, str)
                    return FakeResponse(status_code=200)
                raise RuntimeError("post-write-failed")

            def close(self) -> None:
                return None

        monkeypatch.setattr(cli_module.httpx, "Client", FakeConsulClient)
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="consul-prod",
            backend="consul_kv",
            consul_key_path="mcp/security/oauth/cache",
            consul_token_env="CONSUL_HTTP_TOKEN",
        )

        assert cli_module._write_oauth_cache_payload_to_consul(cache_settings=settings, entries={}) is True
        assert cli_module._write_oauth_cache_payload_to_consul(cache_settings=settings, entries={}) is False
        assert cli_module._write_oauth_cache_payload_to_consul(cache_settings=settings, entries={}) is False
        assert cli_module._write_oauth_cache_payload_to_consul(cache_settings=settings, entries={}) is False

    def test_consul_build_client_and_required_guards(self, monkeypatch):
        """Consul helpers should fail closed when token/url/key identity is missing."""
        monkeypatch.delenv("CONSUL_HTTP_TOKEN", raising=False)

        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="consul-prod",
            backend="consul_kv",
            consul_key_path="mcp/security/oauth/cache",
            consul_token_env="CONSUL_HTTP_TOKEN",
        )
        assert cli_module._build_consul_http_client(cache_settings=settings) is None
        assert cli_module._read_oauth_cache_payload_from_consul(cache_settings=settings) is None
        assert cli_module._write_oauth_cache_payload_to_consul(cache_settings=settings, entries={}) is False

        monkeypatch.setenv("CONSUL_HTTP_TOKEN", "token")
        assert (
            cli_module._build_consul_http_client(
                cache_settings=cli_module.OAuthCacheSettings(
                    persistent=True,
                    namespace="consul-prod",
                    backend="consul_kv",
                    consul_key_path="mcp/security/oauth/cache",
                    consul_token_env="CONSUL_HTTP_TOKEN",
                    consul_api_url="   ",
                )
            )
            is None
        )

        missing_settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="consul-prod",
            backend="consul_kv",
            consul_key_path=None,
            consul_token_env="CONSUL_HTTP_TOKEN",
        )
        assert cli_module._read_oauth_cache_payload_from_consul(cache_settings=missing_settings) is None
        assert cli_module._write_oauth_cache_payload_to_consul(cache_settings=missing_settings, entries={}) is False

    def test_persist_consul_removes_deleted_in_memory_entry(self, monkeypatch):
        """Consul persister should remove cache key when in-memory entry is missing."""
        cli_module._clear_oauth_token_cache()
        seen_entries: dict[str, dict[str, object]] = {}

        monkeypatch.setattr(
            cli_module,
            "_load_oauth_persistent_cache_entries_from_consul",
            lambda *, cache_settings: {"stale-key": {"access_token": "old-token"}},
        )

        def fake_write(*, cache_settings: cli_module.OAuthCacheSettings, entries: dict[str, dict[str, object]]) -> bool:
            del cache_settings
            seen_entries.update(entries)
            return True

        monkeypatch.setattr(cli_module, "_write_oauth_cache_payload_to_consul", fake_write)

        cli_module._persist_oauth_cache_entry_consul(
            cache_key="stale-key",
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="consul-prod",
                backend="consul_kv",
                consul_key_path="mcp/security/oauth/cache",
                consul_token_env="CONSUL_HTTP_TOKEN",
            ),
        )

        assert seen_entries == {}

    def test_build_redis_key_normalizes_path(self):
        """Redis key builder should normalize leading/trailing slashes."""
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="redis-prod",
            backend="redis_kv",
            redis_key="/mcp/security/oauth/cache/",
        )

        key_name = cli_module._build_redis_key(cache_settings=settings)

        assert key_name == "mcp/security/oauth/cache"

    def test_read_redis_payload_parses_raw_value(self, monkeypatch):
        """Redis reader should parse envelope from raw GET response value."""
        monkeypatch.setenv("REDIS_PASSWORD", "redis-password-test")

        class FakeRedisClient:
            call_count = 0

            def __init__(self, **kwargs: object) -> None:
                del kwargs

            @classmethod
            def from_url(cls, url: str, **kwargs: object) -> "FakeRedisClient":
                assert url == "rediss://redis.example.com:6380/0"
                assert kwargs.get("password") == "redis-password-test"
                return cls()

            def get(self, key: str) -> bytes:
                assert key == "mcp/security/oauth/cache"
                FakeRedisClient.call_count += 1
                if FakeRedisClient.call_count == 1:
                    return json.dumps(
                        {"schema_version": cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2, "entries": {}}
                    ).encode("utf-8")
                return b""

            def close(self) -> None:
                return None

        monkeypatch.setattr(
            cli_module.importlib, "import_module", lambda name: types.SimpleNamespace(Redis=FakeRedisClient)
        )
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="redis-prod",
            backend="redis_kv",
            redis_key="mcp/security/oauth/cache",
            redis_url="rediss://redis.example.com:6380/0",
            redis_password_env="REDIS_PASSWORD",
        )

        first = cli_module._read_oauth_cache_payload_from_redis(cache_settings=settings)
        second = cli_module._read_oauth_cache_payload_from_redis(cache_settings=settings)
        assert isinstance(first, dict)
        assert first.get("schema_version") == cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2
        assert isinstance(second, dict)
        assert second.get("entries") == {}

    def test_read_redis_payload_bypasses_errors_and_missing_key(self, monkeypatch):
        """Redis reader should fail closed for errors and map missing key to empty envelope."""
        monkeypatch.setenv("REDIS_PASSWORD", "redis-password-test")

        class FakeRedisClient:
            call_count = 0

            def __init__(self, **kwargs: object) -> None:
                del kwargs

            @classmethod
            def from_url(cls, url: str, **kwargs: object) -> "FakeRedisClient":
                del url, kwargs
                return cls()

            def get(self, key: str) -> object:
                del key
                FakeRedisClient.call_count += 1
                if FakeRedisClient.call_count == 1:
                    return None
                if FakeRedisClient.call_count == 2:
                    raise RuntimeError("redis read failed")
                return b"{invalid-json"

            def close(self) -> None:
                return None

        monkeypatch.setattr(
            cli_module.importlib, "import_module", lambda name: types.SimpleNamespace(Redis=FakeRedisClient)
        )
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="redis-prod",
            backend="redis_kv",
            redis_key="mcp/security/oauth/cache",
            redis_url="redis://127.0.0.1:6379/0",
            redis_password_env="REDIS_PASSWORD",
        )

        first = cli_module._read_oauth_cache_payload_from_redis(cache_settings=settings)
        second = cli_module._read_oauth_cache_payload_from_redis(cache_settings=settings)
        third = cli_module._read_oauth_cache_payload_from_redis(cache_settings=settings)
        assert isinstance(first, dict)
        assert first.get("entries") == {}
        assert second is None
        assert third is None

    def test_redis_write_success_and_bypass_paths(self, monkeypatch):
        """Redis writer should support success flow and fail-closed preflight/post paths."""
        monkeypatch.setenv("REDIS_PASSWORD", "redis-password-test")

        class FakeRedisClient:
            init_count = 0

            def __init__(self, **kwargs: object) -> None:
                del kwargs
                FakeRedisClient.init_count += 1
                self._scenario = FakeRedisClient.init_count

            @classmethod
            def from_url(cls, url: str, **kwargs: object) -> "FakeRedisClient":
                del url, kwargs
                return cls()

            def get(self, key: str) -> object:
                assert key == "mcp/security/oauth/cache"
                if self._scenario == 1:
                    return b"{}"
                if self._scenario == 2:
                    return None
                if self._scenario == 3:
                    raise RuntimeError("preflight failed")
                return b"{}"

            def set(self, key: str, value: str) -> object:
                assert key == "mcp/security/oauth/cache"
                if self._scenario == 1:
                    assert isinstance(value, str)
                    return True
                if self._scenario == 4:
                    raise RuntimeError("write failed")
                return False

            def close(self) -> None:
                return None

        monkeypatch.setattr(
            cli_module.importlib, "import_module", lambda name: types.SimpleNamespace(Redis=FakeRedisClient)
        )
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="redis-prod",
            backend="redis_kv",
            redis_key="mcp/security/oauth/cache",
            redis_url="redis://127.0.0.1:6379/0",
            redis_password_env="REDIS_PASSWORD",
        )

        assert cli_module._write_oauth_cache_payload_to_redis(cache_settings=settings, entries={}) is True
        assert cli_module._write_oauth_cache_payload_to_redis(cache_settings=settings, entries={}) is False
        assert cli_module._write_oauth_cache_payload_to_redis(cache_settings=settings, entries={}) is False
        assert cli_module._write_oauth_cache_payload_to_redis(cache_settings=settings, entries={}) is False

    def test_redis_build_client_and_required_guards(self, monkeypatch):
        """Redis helpers should fail closed when dependency/url/key identity is missing."""
        monkeypatch.delenv("REDIS_PASSWORD", raising=False)

        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="redis-prod",
            backend="redis_kv",
            redis_key="mcp/security/oauth/cache",
            redis_url="redis://127.0.0.1:6379/0",
            redis_password_env="REDIS_PASSWORD",
        )

        monkeypatch.setattr(
            cli_module.importlib, "import_module", lambda name: (_ for _ in ()).throw(ImportError(name))
        )
        assert cli_module._build_redis_client(cache_settings=settings) is None
        assert cli_module._read_oauth_cache_payload_from_redis(cache_settings=settings) is None
        assert cli_module._write_oauth_cache_payload_to_redis(cache_settings=settings, entries={}) is False

        monkeypatch.setenv("REDIS_PASSWORD", "redis-password-test")
        monkeypatch.setattr(
            cli_module.importlib,
            "import_module",
            lambda name: types.SimpleNamespace(Redis=types.SimpleNamespace()),
        )
        assert cli_module._build_redis_client(cache_settings=settings) is None

        missing_settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="redis-prod",
            backend="redis_kv",
            redis_key=None,
            redis_url="redis://127.0.0.1:6379/0",
            redis_password_env="REDIS_PASSWORD",
        )
        assert cli_module._read_oauth_cache_payload_from_redis(cache_settings=missing_settings) is None
        assert cli_module._write_oauth_cache_payload_to_redis(cache_settings=missing_settings, entries={}) is False

    def test_persist_redis_removes_deleted_in_memory_entry(self, monkeypatch):
        """Redis persister should remove cache key when in-memory entry is missing."""
        cli_module._clear_oauth_token_cache()
        seen_entries: dict[str, dict[str, object]] = {}

        monkeypatch.setattr(
            cli_module,
            "_load_oauth_persistent_cache_entries_from_redis",
            lambda *, cache_settings: {"stale-key": {"access_token": "old-token"}},
        )

        def fake_write(*, cache_settings: cli_module.OAuthCacheSettings, entries: dict[str, dict[str, object]]) -> bool:
            del cache_settings
            seen_entries.update(entries)
            return True

        monkeypatch.setattr(cli_module, "_write_oauth_cache_payload_to_redis", fake_write)

        cli_module._persist_oauth_cache_entry_redis(
            cache_key="stale-key",
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="redis-prod",
                backend="redis_kv",
                redis_key="mcp/security/oauth/cache",
                redis_url="redis://127.0.0.1:6379/0",
                redis_password_env="REDIS_PASSWORD",
            ),
        )

        assert seen_entries == {}

    def test_build_cloudflare_kv_path_encodes_segments(self):
        """Cloudflare KV path builder should URL-encode account, namespace, and key segments."""
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="cloudflare-prod",
            backend="cloudflare_kv",
            cf_account_id="account-123",
            cf_namespace_id="namespace_456",
            cf_kv_key="mcp/security/oauth/cache",
        )

        path = cli_module._build_cloudflare_kv_path(cache_settings=settings)

        assert path == "/accounts/account-123/storage/kv/namespaces/namespace_456/values/mcp%2Fsecurity%2Foauth%2Fcache"

    def test_read_cloudflare_payload_parses_raw_value(self, monkeypatch):
        """Cloudflare reader should parse envelope from raw KV value response body."""
        monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "cf-token-test")

        class FakeResponse:
            def __init__(self, *, status_code: int, text: str) -> None:
                self.status_code = status_code
                self.text = text

            def raise_for_status(self) -> None:
                if self.status_code >= 400:
                    raise RuntimeError(f"status={self.status_code}")

        class FakeCloudflareClient:
            call_count = 0

            def __init__(self, **kwargs: object) -> None:
                del kwargs

            def get(self, path: str, **kwargs: object) -> FakeResponse:
                del kwargs
                assert (
                    path
                    == "/accounts/account-123/storage/kv/namespaces/namespace-456/values/mcp%2Fsecurity%2Foauth%2Fcache"
                )
                FakeCloudflareClient.call_count += 1
                if FakeCloudflareClient.call_count == 1:
                    return FakeResponse(
                        status_code=200,
                        text=json.dumps({"schema_version": cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2, "entries": {}}),
                    )
                return FakeResponse(status_code=200, text="")

            def close(self) -> None:
                return None

        monkeypatch.setattr(cli_module.httpx, "Client", FakeCloudflareClient)
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="cloudflare-prod",
            backend="cloudflare_kv",
            cf_account_id="account-123",
            cf_namespace_id="namespace-456",
            cf_kv_key="mcp/security/oauth/cache",
            cf_api_token_env="CLOUDFLARE_API_TOKEN",
            cf_api_url="https://api.cloudflare.com/client/v4",
        )

        first = cli_module._read_oauth_cache_payload_from_cloudflare(cache_settings=settings)
        second = cli_module._read_oauth_cache_payload_from_cloudflare(cache_settings=settings)
        assert isinstance(first, dict)
        assert first.get("schema_version") == cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2
        assert isinstance(second, dict)
        assert second.get("entries") == {}

    def test_read_cloudflare_payload_bypasses_errors_and_missing_key(self, monkeypatch):
        """Cloudflare reader should fail closed for errors and map missing key to empty envelope."""
        monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "cf-token-test")

        class FakeResponse:
            def __init__(self, *, status_code: int, text: str) -> None:
                self.status_code = status_code
                self.text = text

            def raise_for_status(self) -> None:
                if self.status_code >= 400:
                    raise RuntimeError(f"status={self.status_code}")

        class FakeCloudflareClient:
            call_count = 0

            def __init__(self, **kwargs: object) -> None:
                del kwargs

            def get(self, path: str, **kwargs: object) -> FakeResponse:
                del path, kwargs
                FakeCloudflareClient.call_count += 1
                if FakeCloudflareClient.call_count == 1:
                    return FakeResponse(status_code=404, text="")
                if FakeCloudflareClient.call_count == 2:
                    return FakeResponse(status_code=500, text="")
                return FakeResponse(status_code=200, text="{invalid-json")

            def close(self) -> None:
                return None

        monkeypatch.setattr(cli_module.httpx, "Client", FakeCloudflareClient)
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="cloudflare-prod",
            backend="cloudflare_kv",
            cf_account_id="account-123",
            cf_namespace_id="namespace-456",
            cf_kv_key="mcp/security/oauth/cache",
            cf_api_token_env="CLOUDFLARE_API_TOKEN",
        )

        first = cli_module._read_oauth_cache_payload_from_cloudflare(cache_settings=settings)
        second = cli_module._read_oauth_cache_payload_from_cloudflare(cache_settings=settings)
        third = cli_module._read_oauth_cache_payload_from_cloudflare(cache_settings=settings)
        assert isinstance(first, dict)
        assert first.get("entries") == {}
        assert second is None
        assert third is None

    def test_cloudflare_write_success_and_bypass_paths(self, monkeypatch):
        """Cloudflare writer should support success flow and fail-closed preflight/post paths."""
        monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "cf-token-test")

        class FakeResponse:
            def __init__(self, *, status_code: int, text: str = "") -> None:
                self.status_code = status_code
                self.text = text

            def raise_for_status(self) -> None:
                if self.status_code >= 400:
                    raise RuntimeError(f"status={self.status_code}")

        class FakeCloudflareClient:
            init_count = 0

            def __init__(self, **kwargs: object) -> None:
                del kwargs
                FakeCloudflareClient.init_count += 1
                self._scenario = FakeCloudflareClient.init_count

            def get(self, path: str, **kwargs: object) -> FakeResponse:
                del kwargs
                assert (
                    path
                    == "/accounts/account-123/storage/kv/namespaces/namespace-456/values/mcp%2Fsecurity%2Foauth%2Fcache"
                )
                if self._scenario == 1:
                    return FakeResponse(status_code=200, text="{}")
                if self._scenario == 2:
                    return FakeResponse(status_code=404)
                if self._scenario == 3:
                    return FakeResponse(status_code=500)
                return FakeResponse(status_code=200, text="{}")

            def put(self, path: str, **kwargs: object) -> FakeResponse:
                assert (
                    path
                    == "/accounts/account-123/storage/kv/namespaces/namespace-456/values/mcp%2Fsecurity%2Foauth%2Fcache"
                )
                if self._scenario == 1:
                    payload = kwargs.get("content")
                    assert isinstance(payload, str)
                    return FakeResponse(status_code=200)
                raise RuntimeError("post-write-failed")

            def close(self) -> None:
                return None

        monkeypatch.setattr(cli_module.httpx, "Client", FakeCloudflareClient)
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="cloudflare-prod",
            backend="cloudflare_kv",
            cf_account_id="account-123",
            cf_namespace_id="namespace-456",
            cf_kv_key="mcp/security/oauth/cache",
            cf_api_token_env="CLOUDFLARE_API_TOKEN",
        )

        assert cli_module._write_oauth_cache_payload_to_cloudflare(cache_settings=settings, entries={}) is True
        assert cli_module._write_oauth_cache_payload_to_cloudflare(cache_settings=settings, entries={}) is False
        assert cli_module._write_oauth_cache_payload_to_cloudflare(cache_settings=settings, entries={}) is False
        assert cli_module._write_oauth_cache_payload_to_cloudflare(cache_settings=settings, entries={}) is False

    def test_cloudflare_build_client_and_required_guards(self, monkeypatch):
        """Cloudflare helpers should fail closed when token/url/key identity is missing."""
        monkeypatch.delenv("CLOUDFLARE_API_TOKEN", raising=False)

        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="cloudflare-prod",
            backend="cloudflare_kv",
            cf_account_id="account-123",
            cf_namespace_id="namespace-456",
            cf_kv_key="mcp/security/oauth/cache",
            cf_api_token_env="CLOUDFLARE_API_TOKEN",
            cf_api_url="https://api.cloudflare.com/client/v4",
        )
        assert cli_module._build_cloudflare_http_client(cache_settings=settings) is None
        assert cli_module._read_oauth_cache_payload_from_cloudflare(cache_settings=settings) is None
        assert cli_module._write_oauth_cache_payload_to_cloudflare(cache_settings=settings, entries={}) is False

        monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "token")
        assert (
            cli_module._build_cloudflare_http_client(
                cache_settings=cli_module.OAuthCacheSettings(
                    persistent=True,
                    namespace="cloudflare-prod",
                    backend="cloudflare_kv",
                    cf_account_id="account-123",
                    cf_namespace_id="namespace-456",
                    cf_kv_key="mcp/security/oauth/cache",
                    cf_api_token_env="CLOUDFLARE_API_TOKEN",
                    cf_api_url="   ",
                )
            )
            is None
        )

        missing_settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="cloudflare-prod",
            backend="cloudflare_kv",
            cf_account_id=None,
            cf_namespace_id="namespace-456",
            cf_kv_key="mcp/security/oauth/cache",
            cf_api_token_env="CLOUDFLARE_API_TOKEN",
        )
        assert cli_module._read_oauth_cache_payload_from_cloudflare(cache_settings=missing_settings) is None
        assert cli_module._write_oauth_cache_payload_to_cloudflare(cache_settings=missing_settings, entries={}) is False

    def test_persist_cloudflare_removes_deleted_in_memory_entry(self, monkeypatch):
        """Cloudflare persister should remove cache key when in-memory entry is missing."""
        cli_module._clear_oauth_token_cache()
        seen_entries: dict[str, dict[str, object]] = {}

        monkeypatch.setattr(
            cli_module,
            "_load_oauth_persistent_cache_entries_from_cloudflare",
            lambda *, cache_settings: {"stale-key": {"access_token": "old-token"}},
        )

        def fake_write(*, cache_settings: cli_module.OAuthCacheSettings, entries: dict[str, dict[str, object]]) -> bool:
            del cache_settings
            seen_entries.update(entries)
            return True

        monkeypatch.setattr(cli_module, "_write_oauth_cache_payload_to_cloudflare", fake_write)

        cli_module._persist_oauth_cache_entry_cloudflare(
            cache_key="stale-key",
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="cloudflare-prod",
                backend="cloudflare_kv",
                cf_account_id="account-123",
                cf_namespace_id="namespace-456",
                cf_kv_key="mcp/security/oauth/cache",
                cf_api_token_env="CLOUDFLARE_API_TOKEN",
            ),
        )

        assert seen_entries == {}

    def test_build_etcd_key_normalizes_path(self):
        """etcd key builder should normalize leading/trailing slashes."""
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="etcd-prod",
            backend="etcd_kv",
            etcd_key="/mcp/security/oauth/cache/",
        )

        key_name = cli_module._build_etcd_kv_key(cache_settings=settings)

        assert key_name == "mcp/security/oauth/cache"

    def test_read_etcd_payload_parses_raw_value(self, monkeypatch):
        """etcd reader should parse envelope from v3 range response value."""
        expected_key = base64.b64encode(b"mcp/security/oauth/cache").decode("utf-8")
        encoded_payload = base64.b64encode(
            json.dumps({"schema_version": cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2, "entries": {}}).encode("utf-8")
        ).decode("utf-8")

        class FakeResponse:
            def __init__(self, *, status_code: int, payload: object) -> None:
                self.status_code = status_code
                self._payload = payload

            def raise_for_status(self) -> None:
                if self.status_code >= 400:
                    raise RuntimeError(f"status={self.status_code}")

            def json(self) -> object:
                return self._payload

        class FakeEtcdClient:
            call_count = 0

            def __init__(self, **kwargs: object) -> None:
                del kwargs

            def post(self, path: str, **kwargs: object) -> FakeResponse:
                assert path == "/v3/kv/range"
                request_payload = kwargs.get("json")
                assert request_payload == {"key": expected_key}
                FakeEtcdClient.call_count += 1
                if FakeEtcdClient.call_count == 1:
                    return FakeResponse(status_code=200, payload={"kvs": [{"value": encoded_payload}]})
                return FakeResponse(status_code=200, payload={"kvs": []})

            def close(self) -> None:
                return None

        monkeypatch.setattr(cli_module.httpx, "Client", FakeEtcdClient)
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="etcd-prod",
            backend="etcd_kv",
            etcd_key="mcp/security/oauth/cache",
            etcd_api_url="https://etcd.example.com:2379",
            etcd_token_env="ETCD_TOKEN",
        )

        first = cli_module._read_oauth_cache_payload_from_etcd(cache_settings=settings)
        second = cli_module._read_oauth_cache_payload_from_etcd(cache_settings=settings)
        assert isinstance(first, dict)
        assert first.get("schema_version") == cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2
        assert isinstance(second, dict)
        assert second.get("entries") == {}

    def test_read_etcd_payload_bypasses_errors_and_missing_key(self, monkeypatch):
        """etcd reader should fail closed for errors and map missing key to empty envelope."""

        class FakeResponse:
            def __init__(self, *, status_code: int, payload: object) -> None:
                self.status_code = status_code
                self._payload = payload

            def raise_for_status(self) -> None:
                if self.status_code >= 400:
                    raise RuntimeError(f"status={self.status_code}")

            def json(self) -> object:
                return self._payload

        class FakeEtcdClient:
            call_count = 0

            def __init__(self, **kwargs: object) -> None:
                del kwargs

            def post(self, path: str, **kwargs: object) -> FakeResponse:
                del path, kwargs
                FakeEtcdClient.call_count += 1
                if FakeEtcdClient.call_count == 1:
                    return FakeResponse(status_code=404, payload={})
                if FakeEtcdClient.call_count == 2:
                    return FakeResponse(status_code=500, payload={})
                return FakeResponse(status_code=200, payload={"kvs": [{"value": "not-base64"}]})

            def close(self) -> None:
                return None

        monkeypatch.setattr(cli_module.httpx, "Client", FakeEtcdClient)
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="etcd-prod",
            backend="etcd_kv",
            etcd_key="mcp/security/oauth/cache",
            etcd_token_env="ETCD_TOKEN",
        )

        first = cli_module._read_oauth_cache_payload_from_etcd(cache_settings=settings)
        second = cli_module._read_oauth_cache_payload_from_etcd(cache_settings=settings)
        third = cli_module._read_oauth_cache_payload_from_etcd(cache_settings=settings)
        assert isinstance(first, dict)
        assert first.get("entries") == {}
        assert second is None
        assert third is None

    def test_etcd_write_success_and_bypass_paths(self, monkeypatch):
        """etcd writer should support success flow and fail-closed preflight/post paths."""
        expected_key = base64.b64encode(b"mcp/security/oauth/cache").decode("utf-8")

        class FakeResponse:
            def __init__(self, *, status_code: int, payload: object) -> None:
                self.status_code = status_code
                self._payload = payload

            def raise_for_status(self) -> None:
                if self.status_code >= 400:
                    raise RuntimeError(f"status={self.status_code}")

            def json(self) -> object:
                return self._payload

        class FakeEtcdClient:
            init_count = 0

            def __init__(self, **kwargs: object) -> None:
                del kwargs
                FakeEtcdClient.init_count += 1
                self._scenario = FakeEtcdClient.init_count

            def post(self, path: str, **kwargs: object) -> FakeResponse:
                request_payload = kwargs.get("json")
                if path == "/v3/kv/range":
                    assert request_payload == {"key": expected_key}
                    if self._scenario == 1:
                        return FakeResponse(status_code=200, payload={"kvs": [{"key": expected_key, "value": "e30="}]})
                    if self._scenario == 2:
                        return FakeResponse(status_code=200, payload={"kvs": []})
                    if self._scenario == 3:
                        return FakeResponse(status_code=500, payload={})
                    return FakeResponse(status_code=200, payload={"kvs": [{"key": expected_key, "value": "e30="}]})
                if path == "/v3/kv/put":
                    if self._scenario == 1:
                        assert isinstance(request_payload, dict)
                        assert request_payload.get("key") == expected_key
                        encoded_value = request_payload.get("value")
                        assert isinstance(encoded_value, str)
                        decoded_payload = base64.b64decode(encoded_value.encode("utf-8")).decode("utf-8")
                        parsed_payload = json.loads(decoded_payload)
                        assert parsed_payload["schema_version"] == cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2
                        assert isinstance(parsed_payload["entries"], dict)
                        return FakeResponse(status_code=200, payload={})
                    raise RuntimeError("write failed")
                raise AssertionError(path)

            def close(self) -> None:
                return None

        monkeypatch.setattr(cli_module.httpx, "Client", FakeEtcdClient)
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="etcd-prod",
            backend="etcd_kv",
            etcd_key="mcp/security/oauth/cache",
            etcd_token_env="ETCD_TOKEN",
        )

        assert cli_module._write_oauth_cache_payload_to_etcd(cache_settings=settings, entries={}) is True
        assert cli_module._write_oauth_cache_payload_to_etcd(cache_settings=settings, entries={}) is False
        assert cli_module._write_oauth_cache_payload_to_etcd(cache_settings=settings, entries={}) is False
        assert cli_module._write_oauth_cache_payload_to_etcd(cache_settings=settings, entries={}) is False

    def test_etcd_build_client_and_required_guards(self, monkeypatch):
        """etcd helpers should fail closed when api_url/key identity is missing."""
        monkeypatch.delenv("ETCD_TOKEN", raising=False)

        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="etcd-prod",
            backend="etcd_kv",
            etcd_key="mcp/security/oauth/cache",
            etcd_token_env="ETCD_TOKEN",
            etcd_api_url="http://127.0.0.1:2379",
        )
        client = cli_module._build_etcd_http_client(cache_settings=settings)
        assert client is not None
        assert client.headers.get("Authorization") is None
        client.close()

        monkeypatch.setenv("ETCD_TOKEN", "token")
        client_with_token = cli_module._build_etcd_http_client(cache_settings=settings)
        assert client_with_token is not None
        assert client_with_token.headers.get("Authorization") == "Bearer token"
        client_with_token.close()

        assert (
            cli_module._build_etcd_http_client(
                cache_settings=cli_module.OAuthCacheSettings(
                    persistent=True,
                    namespace="etcd-prod",
                    backend="etcd_kv",
                    etcd_key="mcp/security/oauth/cache",
                    etcd_token_env="ETCD_TOKEN",
                    etcd_api_url="   ",
                )
            )
            is None
        )

        missing_settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="etcd-prod",
            backend="etcd_kv",
            etcd_key=None,
            etcd_token_env="ETCD_TOKEN",
        )
        assert cli_module._read_oauth_cache_payload_from_etcd(cache_settings=missing_settings) is None
        assert cli_module._write_oauth_cache_payload_to_etcd(cache_settings=missing_settings, entries={}) is False

    def test_persist_etcd_removes_deleted_in_memory_entry(self, monkeypatch):
        """etcd persister should remove cache key when in-memory entry is missing."""
        cli_module._clear_oauth_token_cache()
        seen_entries: dict[str, dict[str, object]] = {}

        monkeypatch.setattr(
            cli_module,
            "_load_oauth_persistent_cache_entries_from_etcd",
            lambda *, cache_settings: {"stale-key": {"access_token": "old-token"}},
        )

        def fake_write(*, cache_settings: cli_module.OAuthCacheSettings, entries: dict[str, dict[str, object]]) -> bool:
            del cache_settings
            seen_entries.update(entries)
            return True

        monkeypatch.setattr(cli_module, "_write_oauth_cache_payload_to_etcd", fake_write)

        cli_module._persist_oauth_cache_entry_etcd(
            cache_key="stale-key",
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="etcd-prod",
                backend="etcd_kv",
                etcd_key="mcp/security/oauth/cache",
                etcd_token_env="ETCD_TOKEN",
            ),
        )

        assert seen_entries == {}

    def test_load_etcd_entries_parses_and_bypasses_payload(self, monkeypatch):
        """etcd loader should parse payload entries and bypass cleanly on provider None."""
        monkeypatch.setattr(
            cli_module,
            "_read_oauth_cache_payload_from_etcd",
            lambda *, cache_settings: {
                "schema_version": cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2,
                "entries": {"k": {"access_token": "t"}},
            },
        )
        parsed_entries = cli_module._load_oauth_persistent_cache_entries_from_etcd(
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="etcd-prod",
                backend="etcd_kv",
                etcd_key="mcp/security/oauth/cache",
            )
        )
        assert parsed_entries == {"k": {"access_token": "t"}}

        monkeypatch.setattr(cli_module, "_read_oauth_cache_payload_from_etcd", lambda *, cache_settings: None)
        bypass_entries = cli_module._load_oauth_persistent_cache_entries_from_etcd(
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="etcd-prod",
                backend="etcd_kv",
                etcd_key="mcp/security/oauth/cache",
            )
        )
        assert bypass_entries == {}

    def test_etcd_build_client_bypasses_client_init_error(self, monkeypatch):
        """etcd client builder should fail closed when HTTP client init raises."""
        monkeypatch.setattr(
            cli_module.httpx,
            "Client",
            lambda **kwargs: (_ for _ in ()).throw(RuntimeError("client-init-failed")),
        )

        client = cli_module._build_etcd_http_client(
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="etcd-prod",
                backend="etcd_kv",
                etcd_key="mcp/security/oauth/cache",
                etcd_api_url="http://127.0.0.1:2379",
            )
        )
        assert client is None

    def test_build_postgres_cache_key_normalizes_path(self):
        """Postgres key builder should normalize leading/trailing slashes."""
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="postgres-prod",
            backend="postgres_kv",
            postgres_cache_key="/mcp/security/oauth/cache/",
        )

        key_name = cli_module._build_postgres_cache_key(cache_settings=settings)

        assert key_name == "mcp/security/oauth/cache"

    def test_read_postgres_payload_parses_and_bypasses_paths(self, monkeypatch):
        """Postgres reader should parse payload, map missing row to empty envelope, and bypass on errors."""

        class FakeCursor:
            def __init__(self, scenario: int) -> None:
                self._scenario = scenario

            def execute(self, sql: str, params: tuple[object, ...]) -> None:
                assert "SELECT payload_json FROM mcp_oauth_cache_store" in sql
                assert params == ("mcp/security/oauth/cache",)
                if self._scenario == 3:
                    raise RuntimeError("db-read-failed")

            def fetchone(self) -> tuple[object, ...] | None:
                if self._scenario == 1:
                    return (
                        json.dumps(
                            {
                                "schema_version": cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2,
                                "entries": {"k": {"access_token": "t"}},
                            }
                        ),
                    )
                if self._scenario == 2:
                    return None
                if self._scenario == 4:
                    return ("{invalid-json",)
                return None

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb) -> bool:
                del exc_type, exc, tb
                return False

        class FakeConnection:
            call_count = 0
            close_count = 0

            def __init__(self) -> None:
                FakeConnection.call_count += 1
                self._scenario = FakeConnection.call_count

            def cursor(self):
                return FakeCursor(self._scenario)

            def close(self) -> None:
                FakeConnection.close_count += 1

        monkeypatch.setattr(cli_module, "_build_postgres_connection", lambda *, cache_settings: FakeConnection())
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="postgres-prod",
            backend="postgres_kv",
            postgres_cache_key="mcp/security/oauth/cache",
            postgres_dsn_env="POSTGRES_DSN",
        )

        first = cli_module._read_oauth_cache_payload_from_postgres(cache_settings=settings)
        second = cli_module._read_oauth_cache_payload_from_postgres(cache_settings=settings)
        third = cli_module._read_oauth_cache_payload_from_postgres(cache_settings=settings)
        fourth = cli_module._read_oauth_cache_payload_from_postgres(cache_settings=settings)

        assert first == {
            "schema_version": cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2,
            "entries": {"k": {"access_token": "t"}},
        }
        assert isinstance(second, dict)
        assert second.get("entries") == {}
        assert third is None
        assert fourth is None
        assert FakeConnection.close_count == 4

    def test_postgres_write_success_and_bypass_paths(self, monkeypatch):
        """Postgres writer should support success flow and fail closed when preflight/update fails."""

        class FakeCursor:
            def __init__(self, scenario: int) -> None:
                self._scenario = scenario
                self.rowcount = 1

            def execute(self, sql: str, params: tuple[object, ...]) -> None:
                if sql.startswith("SELECT cache_key FROM mcp_oauth_cache_store"):
                    assert params == ("mcp/security/oauth/cache",)
                    if self._scenario == 3:
                        raise RuntimeError("preflight-failed")
                    return
                if sql.startswith("UPDATE mcp_oauth_cache_store SET payload_json = %s"):
                    payload_text, cache_key = params
                    assert cache_key == "mcp/security/oauth/cache"
                    assert isinstance(payload_text, str)
                    parsed_payload = json.loads(payload_text)
                    assert parsed_payload["schema_version"] == cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2
                    assert isinstance(parsed_payload["entries"], dict)
                    if self._scenario == 4:
                        self.rowcount = 0
                    if self._scenario == 5:
                        raise RuntimeError("update-failed")
                    return
                raise AssertionError(sql)

            def fetchone(self) -> tuple[object, ...] | None:
                if self._scenario == 1:
                    return ("mcp/security/oauth/cache",)
                if self._scenario == 2:
                    return None
                if self._scenario in (4, 5):
                    return ("mcp/security/oauth/cache",)
                return None

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb) -> bool:
                del exc_type, exc, tb
                return False

        class FakeConnection:
            init_count = 0

            def __init__(self) -> None:
                FakeConnection.init_count += 1
                self._scenario = FakeConnection.init_count

            def cursor(self):
                return FakeCursor(self._scenario)

            def close(self) -> None:
                return None

        monkeypatch.setattr(cli_module, "_build_postgres_connection", lambda *, cache_settings: FakeConnection())
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="postgres-prod",
            backend="postgres_kv",
            postgres_cache_key="mcp/security/oauth/cache",
            postgres_dsn_env="POSTGRES_DSN",
        )

        assert cli_module._write_oauth_cache_payload_to_postgres(cache_settings=settings, entries={}) is True
        assert cli_module._write_oauth_cache_payload_to_postgres(cache_settings=settings, entries={}) is False
        assert cli_module._write_oauth_cache_payload_to_postgres(cache_settings=settings, entries={}) is False
        assert cli_module._write_oauth_cache_payload_to_postgres(cache_settings=settings, entries={}) is False
        assert cli_module._write_oauth_cache_payload_to_postgres(cache_settings=settings, entries={}) is False

    def test_postgres_connection_builder_and_close_guards(self, monkeypatch):
        """Postgres connection helpers should fail closed for missing module/dsn and close safely."""
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="postgres-prod",
            backend="postgres_kv",
            postgres_cache_key="mcp/security/oauth/cache",
            postgres_dsn_env="POSTGRES_DSN",
        )
        original_import_module = cli_module.importlib.import_module

        monkeypatch.setattr(
            cli_module.importlib,
            "import_module",
            lambda module_name: (
                (_ for _ in ()).throw(ImportError("missing-psycopg"))
                if module_name == "psycopg"
                else original_import_module(module_name)
            ),
        )
        assert cli_module._build_postgres_connection(cache_settings=settings) is None

        class FakePsycopgMissingConnect:
            pass

        monkeypatch.setattr(
            cli_module.importlib,
            "import_module",
            lambda module_name: (
                FakePsycopgMissingConnect if module_name == "psycopg" else original_import_module(module_name)
            ),
        )
        assert cli_module._build_postgres_connection(cache_settings=settings) is None

        monkeypatch.delenv("POSTGRES_DSN", raising=False)
        assert cli_module._build_postgres_connection(cache_settings=settings) is None

        connect_calls: list[tuple[str, bool, int]] = []

        class FakePostgresConnection:
            def close(self) -> None:
                return None

        class FakePsycopg:
            @staticmethod
            def connect(dsn: str, *, autocommit: bool, connect_timeout: int):
                connect_calls.append((dsn, autocommit, connect_timeout))
                return FakePostgresConnection()

        monkeypatch.setenv("POSTGRES_DSN", "postgresql://user:pass@db.example.com:5432/mcp")
        monkeypatch.setattr(
            cli_module.importlib,
            "import_module",
            lambda module_name: FakePsycopg if module_name == "psycopg" else original_import_module(module_name),
        )
        connection = cli_module._build_postgres_connection(cache_settings=settings)
        assert isinstance(connection, FakePostgresConnection)
        assert connect_calls == [("postgresql://user:pass@db.example.com:5432/mcp", True, 10)]

        assert cli_module._close_postgres_connection(object()) is None
        assert cli_module._close_postgres_connection(connection) is None

    def test_postgres_persist_removes_deleted_in_memory_entry(self, monkeypatch):
        """Postgres persister should remove cache key when in-memory entry is missing."""
        cli_module._clear_oauth_token_cache()
        seen_entries: dict[str, dict[str, object]] = {}

        monkeypatch.setattr(
            cli_module,
            "_load_oauth_persistent_cache_entries_from_postgres",
            lambda *, cache_settings: {"stale-key": {"access_token": "old-token"}},
        )

        def fake_write(*, cache_settings: cli_module.OAuthCacheSettings, entries: dict[str, dict[str, object]]) -> bool:
            del cache_settings
            seen_entries.update(entries)
            return True

        monkeypatch.setattr(cli_module, "_write_oauth_cache_payload_to_postgres", fake_write)

        cli_module._persist_oauth_cache_entry_postgres(
            cache_key="stale-key",
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="postgres-prod",
                backend="postgres_kv",
                postgres_cache_key="mcp/security/oauth/cache",
            ),
        )

        assert seen_entries == {}

    def test_load_postgres_entries_parses_and_bypasses_payload(self, monkeypatch):
        """Postgres loader should parse payload entries and bypass cleanly on provider None."""
        monkeypatch.setattr(
            cli_module,
            "_read_oauth_cache_payload_from_postgres",
            lambda *, cache_settings: {
                "schema_version": cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2,
                "entries": {"k": {"access_token": "t"}},
            },
        )
        parsed_entries = cli_module._load_oauth_persistent_cache_entries_from_postgres(
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="postgres-prod",
                backend="postgres_kv",
                postgres_cache_key="mcp/security/oauth/cache",
            )
        )
        assert parsed_entries == {"k": {"access_token": "t"}}

        monkeypatch.setattr(cli_module, "_read_oauth_cache_payload_from_postgres", lambda *, cache_settings: None)
        bypass_entries = cli_module._load_oauth_persistent_cache_entries_from_postgres(
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="postgres-prod",
                backend="postgres_kv",
                postgres_cache_key="mcp/security/oauth/cache",
            )
        )
        assert bypass_entries == {}

    def test_build_mysql_cache_key_normalizes_path(self):
        """MySQL key builder should normalize leading/trailing slashes."""
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="mysql-prod",
            backend="mysql_kv",
            mysql_cache_key="/mcp/security/oauth/cache/",
        )

        key_name = cli_module._build_mysql_cache_key(cache_settings=settings)

        assert key_name == "mcp/security/oauth/cache"

    def test_read_mysql_payload_parses_and_bypasses_paths(self, monkeypatch):
        """MySQL reader should parse payload, map missing row to empty envelope, and bypass on errors."""

        class FakeCursor:
            def __init__(self, scenario: int) -> None:
                self._scenario = scenario

            def execute(self, sql: str, params: tuple[object, ...]) -> None:
                assert "SELECT payload_json FROM mcp_oauth_cache_store" in sql
                assert params == ("mcp/security/oauth/cache",)
                if self._scenario == 4:
                    raise RuntimeError("db-read-failed")

            def fetchone(self) -> tuple[object, ...] | None:
                if self._scenario == 1:
                    return (
                        json.dumps(
                            {
                                "schema_version": cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2,
                                "entries": {"k": {"access_token": "t"}},
                            }
                        ),
                    )
                if self._scenario == 2:
                    return None
                if self._scenario == 3:
                    return (b'{"schema_version":"v2","entries":{"k2":{"access_token":"tb"}}}',)
                if self._scenario == 5:
                    return ("{invalid-json",)
                return None

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb) -> bool:
                del exc_type, exc, tb
                return False

        class FakeConnection:
            call_count = 0
            close_count = 0

            def __init__(self) -> None:
                FakeConnection.call_count += 1
                self._scenario = FakeConnection.call_count

            def cursor(self):
                return FakeCursor(self._scenario)

            def close(self) -> None:
                FakeConnection.close_count += 1

        monkeypatch.setattr(cli_module, "_build_mysql_connection", lambda *, cache_settings: FakeConnection())
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="mysql-prod",
            backend="mysql_kv",
            mysql_cache_key="mcp/security/oauth/cache",
            mysql_dsn_env="MYSQL_DSN",
        )

        first = cli_module._read_oauth_cache_payload_from_mysql(cache_settings=settings)
        second = cli_module._read_oauth_cache_payload_from_mysql(cache_settings=settings)
        third = cli_module._read_oauth_cache_payload_from_mysql(cache_settings=settings)
        fourth = cli_module._read_oauth_cache_payload_from_mysql(cache_settings=settings)
        fifth = cli_module._read_oauth_cache_payload_from_mysql(cache_settings=settings)

        assert first == {
            "schema_version": cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2,
            "entries": {"k": {"access_token": "t"}},
        }
        assert isinstance(second, dict)
        assert second.get("entries") == {}
        assert third == {
            "schema_version": "v2",
            "entries": {"k2": {"access_token": "tb"}},
        }
        assert fourth is None
        assert fifth is None
        assert FakeConnection.close_count == 5

    def test_mysql_write_success_and_bypass_paths(self, monkeypatch):
        """MySQL writer should support success flow and fail closed when preflight/update fails."""

        class FakeCursor:
            def __init__(self, scenario: int) -> None:
                self._scenario = scenario
                self.rowcount = 1

            def execute(self, sql: str, params: tuple[object, ...]) -> None:
                if sql.startswith("SELECT cache_key FROM mcp_oauth_cache_store"):
                    assert params == ("mcp/security/oauth/cache",)
                    if self._scenario == 3:
                        raise RuntimeError("preflight-failed")
                    return
                if sql.startswith("UPDATE mcp_oauth_cache_store SET payload_json = %s"):
                    payload_text, cache_key = params
                    assert cache_key == "mcp/security/oauth/cache"
                    assert isinstance(payload_text, str)
                    parsed_payload = json.loads(payload_text)
                    assert parsed_payload["schema_version"] == cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2
                    assert isinstance(parsed_payload["entries"], dict)
                    if self._scenario == 4:
                        self.rowcount = 0
                    if self._scenario == 5:
                        raise RuntimeError("update-failed")
                    return
                raise AssertionError(sql)

            def fetchone(self) -> tuple[object, ...] | None:
                if self._scenario == 1:
                    return ("mcp/security/oauth/cache",)
                if self._scenario == 2:
                    return None
                if self._scenario in (4, 5):
                    return ("mcp/security/oauth/cache",)
                return None

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb) -> bool:
                del exc_type, exc, tb
                return False

        class FakeConnection:
            init_count = 0

            def __init__(self) -> None:
                FakeConnection.init_count += 1
                self._scenario = FakeConnection.init_count

            def cursor(self):
                return FakeCursor(self._scenario)

            def close(self) -> None:
                return None

        monkeypatch.setattr(cli_module, "_build_mysql_connection", lambda *, cache_settings: FakeConnection())
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="mysql-prod",
            backend="mysql_kv",
            mysql_cache_key="mcp/security/oauth/cache",
            mysql_dsn_env="MYSQL_DSN",
        )

        assert cli_module._write_oauth_cache_payload_to_mysql(cache_settings=settings, entries={}) is True
        assert cli_module._write_oauth_cache_payload_to_mysql(cache_settings=settings, entries={}) is False
        assert cli_module._write_oauth_cache_payload_to_mysql(cache_settings=settings, entries={}) is False
        assert cli_module._write_oauth_cache_payload_to_mysql(cache_settings=settings, entries={}) is False
        assert cli_module._write_oauth_cache_payload_to_mysql(cache_settings=settings, entries={}) is False

    def test_mysql_connection_builder_and_close_guards(self, monkeypatch):
        """MySQL connection helpers should fail closed for missing module/dsn and close safely."""
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="mysql-prod",
            backend="mysql_kv",
            mysql_cache_key="mcp/security/oauth/cache",
            mysql_dsn_env="MYSQL_DSN",
        )
        original_import_module = cli_module.importlib.import_module

        monkeypatch.setattr(
            cli_module.importlib,
            "import_module",
            lambda module_name: (
                (_ for _ in ()).throw(ImportError("missing-pymysql"))
                if module_name == "pymysql"
                else original_import_module(module_name)
            ),
        )
        assert cli_module._build_mysql_connection(cache_settings=settings) is None

        class FakePyMySQLMissingConnect:
            pass

        monkeypatch.setattr(
            cli_module.importlib,
            "import_module",
            lambda module_name: (
                FakePyMySQLMissingConnect if module_name == "pymysql" else original_import_module(module_name)
            ),
        )
        assert cli_module._build_mysql_connection(cache_settings=settings) is None

        monkeypatch.delenv("MYSQL_DSN", raising=False)
        assert cli_module._build_mysql_connection(cache_settings=settings) is None

        monkeypatch.setenv("MYSQL_DSN", "postgresql://user:pass@db.example.com:3306/mcp")
        monkeypatch.setattr(
            cli_module.importlib,
            "import_module",
            lambda module_name: (
                FakePyMySQLMissingConnect if module_name == "pymysql" else original_import_module(module_name)
            ),
        )
        assert cli_module._build_mysql_connection(cache_settings=settings) is None

        connect_calls: list[dict[str, object]] = []

        class FakeMySQLConnection:
            def close(self) -> None:
                return None

        class FakePyMySQL:
            @staticmethod
            def connect(**kwargs: object) -> FakeMySQLConnection:
                connect_calls.append(dict(kwargs))
                return FakeMySQLConnection()

        monkeypatch.setenv("MYSQL_DSN", "mysql://user%40name:pass%2Bword@db.example.com:3307/mcp")
        monkeypatch.setattr(
            cli_module.importlib,
            "import_module",
            lambda module_name: FakePyMySQL if module_name == "pymysql" else original_import_module(module_name),
        )
        connection = cli_module._build_mysql_connection(cache_settings=settings)
        assert isinstance(connection, FakeMySQLConnection)
        assert connect_calls == [
            {
                "host": "db.example.com",
                "port": 3307,
                "database": "mcp",
                "connect_timeout": 10,
                "autocommit": True,
                "charset": "utf8mb4",
                "user": "user@name",
                "password": "pass+word",
            }
        ]

        assert cli_module._close_mysql_connection(object()) is None
        assert cli_module._close_mysql_connection(connection) is None

    def test_mysql_persist_removes_deleted_in_memory_entry(self, monkeypatch):
        """MySQL persister should remove cache key when in-memory entry is missing."""
        cli_module._clear_oauth_token_cache()
        seen_entries: dict[str, dict[str, object]] = {}

        monkeypatch.setattr(
            cli_module,
            "_load_oauth_persistent_cache_entries_from_mysql",
            lambda *, cache_settings: {"stale-key": {"access_token": "old-token"}},
        )

        def fake_write(*, cache_settings: cli_module.OAuthCacheSettings, entries: dict[str, dict[str, object]]) -> bool:
            del cache_settings
            seen_entries.update(entries)
            return True

        monkeypatch.setattr(cli_module, "_write_oauth_cache_payload_to_mysql", fake_write)

        cli_module._persist_oauth_cache_entry_mysql(
            cache_key="stale-key",
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="mysql-prod",
                backend="mysql_kv",
                mysql_cache_key="mcp/security/oauth/cache",
            ),
        )

        assert seen_entries == {}

    def test_load_mysql_entries_parses_and_bypasses_payload(self, monkeypatch):
        """MySQL loader should parse payload entries and bypass cleanly on provider None."""
        monkeypatch.setattr(
            cli_module,
            "_read_oauth_cache_payload_from_mysql",
            lambda *, cache_settings: {
                "schema_version": cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2,
                "entries": {"k": {"access_token": "t"}},
            },
        )
        parsed_entries = cli_module._load_oauth_persistent_cache_entries_from_mysql(
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="mysql-prod",
                backend="mysql_kv",
                mysql_cache_key="mcp/security/oauth/cache",
            )
        )
        assert parsed_entries == {"k": {"access_token": "t"}}

        monkeypatch.setattr(cli_module, "_read_oauth_cache_payload_from_mysql", lambda *, cache_settings: None)
        bypass_entries = cli_module._load_oauth_persistent_cache_entries_from_mysql(
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="mysql-prod",
                backend="mysql_kv",
                mysql_cache_key="mcp/security/oauth/cache",
            )
        )
        assert bypass_entries == {}

    def test_build_mongo_cache_key_normalizes_path(self):
        """Mongo key builder should normalize leading/trailing slashes."""
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="mongo-prod",
            backend="mongo_kv",
            mongo_cache_key="/mcp/security/oauth/cache/",
        )

        key_name = cli_module._build_mongo_cache_key(cache_settings=settings)

        assert key_name == "mcp/security/oauth/cache"

    def test_read_mongo_payload_parses_and_bypasses_paths(self, monkeypatch):
        """Mongo reader should parse payload, map missing document to empty envelope, and bypass on errors."""

        class FakeCollection:
            def __init__(self, scenario: int) -> None:
                self._scenario = scenario

            def find_one(self, query: dict[str, object]) -> dict[str, object] | None:
                assert query == {"cache_key": "mcp/security/oauth/cache"}
                if self._scenario == 1:
                    return {
                        "payload_json": json.dumps(
                            {
                                "schema_version": cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2,
                                "entries": {"k": {"access_token": "t"}},
                            }
                        )
                    }
                if self._scenario == 2:
                    return None
                if self._scenario == 3:
                    return {"payload_json": b'{"schema_version":"v2","entries":{"k2":{"access_token":"tb"}}}'}
                if self._scenario == 4:
                    raise RuntimeError("mongo-read-failed")
                if self._scenario == 5:
                    return {"payload_json": "{invalid-json"}
                return None

        class FakeDatabase:
            def __init__(self, scenario: int) -> None:
                self._scenario = scenario

            def __getitem__(self, collection_name: str) -> FakeCollection:
                assert collection_name == "oauth_cache_store"
                return FakeCollection(self._scenario)

        class FakeClient:
            call_count = 0
            close_count = 0

            def __init__(self) -> None:
                FakeClient.call_count += 1
                self._scenario = FakeClient.call_count

            def __getitem__(self, database_name: str) -> FakeDatabase:
                assert database_name == "mcp_security_scanner"
                return FakeDatabase(self._scenario)

            def close(self) -> None:
                FakeClient.close_count += 1

        monkeypatch.setattr(cli_module, "_build_mongo_client", lambda *, cache_settings: FakeClient())
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="mongo-prod",
            backend="mongo_kv",
            mongo_cache_key="mcp/security/oauth/cache",
            mongo_dsn_env="MONGODB_URI",
        )

        first = cli_module._read_oauth_cache_payload_from_mongo(cache_settings=settings)
        second = cli_module._read_oauth_cache_payload_from_mongo(cache_settings=settings)
        third = cli_module._read_oauth_cache_payload_from_mongo(cache_settings=settings)
        fourth = cli_module._read_oauth_cache_payload_from_mongo(cache_settings=settings)
        fifth = cli_module._read_oauth_cache_payload_from_mongo(cache_settings=settings)

        assert first == {
            "schema_version": cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2,
            "entries": {"k": {"access_token": "t"}},
        }
        assert isinstance(second, dict)
        assert second.get("entries") == {}
        assert third == {
            "schema_version": "v2",
            "entries": {"k2": {"access_token": "tb"}},
        }
        assert fourth is None
        assert fifth is None
        assert FakeClient.close_count == 5

    def test_mongo_write_success_and_bypass_paths(self, monkeypatch):
        """Mongo writer should support success flow and fail closed when preflight/update fails."""

        class FakeUpdateResult:
            def __init__(self, matched_count: int) -> None:
                self.matched_count = matched_count

        class FakeCollection:
            def __init__(self, scenario: int) -> None:
                self._scenario = scenario

            def find_one(self, query: dict[str, object]) -> dict[str, object] | None:
                assert query == {"cache_key": "mcp/security/oauth/cache"}
                if self._scenario == 1:
                    return {"cache_key": "mcp/security/oauth/cache"}
                if self._scenario == 2:
                    return None
                if self._scenario == 3:
                    raise RuntimeError("preflight-failed")
                if self._scenario in (4, 5):
                    return {"cache_key": "mcp/security/oauth/cache"}
                return None

            def update_one(self, filter_query: dict[str, object], update_doc: dict[str, object]) -> FakeUpdateResult:
                assert filter_query == {"cache_key": "mcp/security/oauth/cache"}
                set_doc = update_doc.get("$set")
                assert isinstance(set_doc, dict)
                payload_text = set_doc.get("payload_json")
                assert isinstance(payload_text, str)
                parsed_payload = json.loads(payload_text)
                assert parsed_payload["schema_version"] == cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2
                assert isinstance(parsed_payload["entries"], dict)
                if self._scenario == 4:
                    return FakeUpdateResult(matched_count=0)
                if self._scenario == 5:
                    raise RuntimeError("update-failed")
                return FakeUpdateResult(matched_count=1)

        class FakeDatabase:
            def __init__(self, scenario: int) -> None:
                self._scenario = scenario

            def __getitem__(self, collection_name: str) -> FakeCollection:
                assert collection_name == "oauth_cache_store"
                return FakeCollection(self._scenario)

        class FakeClient:
            init_count = 0

            def __init__(self) -> None:
                FakeClient.init_count += 1
                self._scenario = FakeClient.init_count

            def __getitem__(self, database_name: str) -> FakeDatabase:
                assert database_name == "mcp_security_scanner"
                return FakeDatabase(self._scenario)

            def close(self) -> None:
                return None

        monkeypatch.setattr(cli_module, "_build_mongo_client", lambda *, cache_settings: FakeClient())
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="mongo-prod",
            backend="mongo_kv",
            mongo_cache_key="mcp/security/oauth/cache",
            mongo_dsn_env="MONGODB_URI",
        )

        assert cli_module._write_oauth_cache_payload_to_mongo(cache_settings=settings, entries={}) is True
        assert cli_module._write_oauth_cache_payload_to_mongo(cache_settings=settings, entries={}) is False
        assert cli_module._write_oauth_cache_payload_to_mongo(cache_settings=settings, entries={}) is False
        assert cli_module._write_oauth_cache_payload_to_mongo(cache_settings=settings, entries={}) is False
        assert cli_module._write_oauth_cache_payload_to_mongo(cache_settings=settings, entries={}) is False

    def test_mongo_client_builder_and_close_guards(self, monkeypatch):
        """Mongo client helpers should fail closed for missing module/dsn and close safely."""
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="mongo-prod",
            backend="mongo_kv",
            mongo_cache_key="mcp/security/oauth/cache",
            mongo_dsn_env="MONGODB_URI",
        )
        original_import_module = cli_module.importlib.import_module

        monkeypatch.setattr(
            cli_module.importlib,
            "import_module",
            lambda module_name: (
                (_ for _ in ()).throw(ImportError("missing-pymongo"))
                if module_name == "pymongo"
                else original_import_module(module_name)
            ),
        )
        assert cli_module._build_mongo_client(cache_settings=settings) is None

        class FakePyMongoMissingClient:
            pass

        monkeypatch.setattr(
            cli_module.importlib,
            "import_module",
            lambda module_name: (
                FakePyMongoMissingClient if module_name == "pymongo" else original_import_module(module_name)
            ),
        )
        assert cli_module._build_mongo_client(cache_settings=settings) is None

        monkeypatch.delenv("MONGODB_URI", raising=False)
        assert cli_module._build_mongo_client(cache_settings=settings) is None

        connect_calls: list[tuple[str, int]] = []

        class FakeMongoClient:
            def __init__(self, dsn: str, **kwargs: int) -> None:
                connect_calls.append((dsn, kwargs["serverSelectionTimeoutMS"]))

            def close(self) -> None:
                return None

        class FakePyMongo:
            MongoClient = FakeMongoClient

        monkeypatch.setenv("MONGODB_URI", "mongodb://user:pass@db.example.com:27017/mcp")
        monkeypatch.setattr(
            cli_module.importlib,
            "import_module",
            lambda module_name: FakePyMongo if module_name == "pymongo" else original_import_module(module_name),
        )
        connection = cli_module._build_mongo_client(cache_settings=settings)
        assert isinstance(connection, FakeMongoClient)
        assert connect_calls == [("mongodb://user:pass@db.example.com:27017/mcp", 10000)]

        assert cli_module._close_mongo_client(object()) is None
        assert cli_module._close_mongo_client(connection) is None

    def test_mongo_persist_removes_deleted_in_memory_entry(self, monkeypatch):
        """Mongo persister should remove cache key when in-memory entry is missing."""
        cli_module._clear_oauth_token_cache()
        seen_entries: dict[str, dict[str, object]] = {}

        monkeypatch.setattr(
            cli_module,
            "_load_oauth_persistent_cache_entries_from_mongo",
            lambda *, cache_settings: {"stale-key": {"access_token": "old-token"}},
        )

        def fake_write(*, cache_settings: cli_module.OAuthCacheSettings, entries: dict[str, dict[str, object]]) -> bool:
            del cache_settings
            seen_entries.update(entries)
            return True

        monkeypatch.setattr(cli_module, "_write_oauth_cache_payload_to_mongo", fake_write)

        cli_module._persist_oauth_cache_entry_mongo(
            cache_key="stale-key",
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="mongo-prod",
                backend="mongo_kv",
                mongo_cache_key="mcp/security/oauth/cache",
            ),
        )

        assert seen_entries == {}

    def test_load_mongo_entries_parses_and_bypasses_payload(self, monkeypatch):
        """Mongo loader should parse payload entries and bypass cleanly on provider None."""
        monkeypatch.setattr(
            cli_module,
            "_read_oauth_cache_payload_from_mongo",
            lambda *, cache_settings: {
                "schema_version": cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2,
                "entries": {"k": {"access_token": "t"}},
            },
        )
        parsed_entries = cli_module._load_oauth_persistent_cache_entries_from_mongo(
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="mongo-prod",
                backend="mongo_kv",
                mongo_cache_key="mcp/security/oauth/cache",
            )
        )
        assert parsed_entries == {"k": {"access_token": "t"}}

        monkeypatch.setattr(cli_module, "_read_oauth_cache_payload_from_mongo", lambda *, cache_settings: None)
        bypass_entries = cli_module._load_oauth_persistent_cache_entries_from_mongo(
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="mongo-prod",
                backend="mongo_kv",
                mongo_cache_key="mcp/security/oauth/cache",
            )
        )
        assert bypass_entries == {}

    def test_build_dynamodb_cache_key_normalizes_path(self):
        """DynamoDB key builder should normalize leading/trailing slashes."""
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="dynamodb-prod",
            backend="dynamodb_kv",
            dynamodb_cache_key="/mcp/security/oauth/cache/",
        )

        key_name = cli_module._build_dynamodb_cache_key(cache_settings=settings)

        assert key_name == "mcp/security/oauth/cache"

    def test_read_dynamodb_payload_parses_and_bypasses_paths(self, monkeypatch):
        """DynamoDB reader should parse payload and map missing item/payload to empty envelope."""

        class FakeDynamoClient:
            call_count = 0

            def get_item(self, **kwargs: object) -> dict[str, object]:
                assert kwargs.get("TableName") == "mcp_oauth_cache_store"
                assert kwargs.get("Key") == {"cache_key": {"S": "mcp/security/oauth/cache"}}
                FakeDynamoClient.call_count += 1
                if FakeDynamoClient.call_count == 1:
                    return {
                        "Item": {
                            "payload_json": {
                                "S": json.dumps(
                                    {
                                        "schema_version": cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2,
                                        "entries": {"k": {"access_token": "t"}},
                                    }
                                )
                            }
                        }
                    }
                if FakeDynamoClient.call_count == 2:
                    return {}
                if FakeDynamoClient.call_count == 3:
                    return {"Item": {"payload_json": {"S": ""}}}
                if FakeDynamoClient.call_count == 4:
                    return {"Item": {"payload_json": {"S": "{invalid-json"}}}
                raise RuntimeError("dynamodb-read-failed")

        monkeypatch.setattr(cli_module, "_build_dynamodb_client", lambda *, cache_settings: FakeDynamoClient())
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="dynamodb-prod",
            backend="dynamodb_kv",
            dynamodb_cache_key="mcp/security/oauth/cache",
            aws_region="eu-west-2",
        )

        first = cli_module._read_oauth_cache_payload_from_dynamodb(cache_settings=settings)
        second = cli_module._read_oauth_cache_payload_from_dynamodb(cache_settings=settings)
        third = cli_module._read_oauth_cache_payload_from_dynamodb(cache_settings=settings)
        fourth = cli_module._read_oauth_cache_payload_from_dynamodb(cache_settings=settings)
        fifth = cli_module._read_oauth_cache_payload_from_dynamodb(cache_settings=settings)

        assert first == {
            "schema_version": cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2,
            "entries": {"k": {"access_token": "t"}},
        }
        assert isinstance(second, dict)
        assert second.get("entries") == {}
        assert isinstance(third, dict)
        assert third.get("entries") == {}
        assert fourth is None
        assert fifth is None

    def test_dynamodb_write_success_and_bypass_paths(self, monkeypatch):
        """DynamoDB writer should support success flow and fail closed when preflight/update fails."""

        class FakeDynamoClient:
            call_count = 0

            def __init__(self) -> None:
                FakeDynamoClient.call_count += 1
                self._scenario = FakeDynamoClient.call_count

            def get_item(self, **kwargs: object) -> dict[str, object]:
                assert kwargs.get("TableName") == "mcp_oauth_cache_store"
                assert kwargs.get("Key") == {"cache_key": {"S": "mcp/security/oauth/cache"}}
                if self._scenario == 1:
                    return {"Item": {"cache_key": {"S": "mcp/security/oauth/cache"}}}
                if self._scenario == 2:
                    return {}
                if self._scenario == 3:
                    raise RuntimeError("preflight-failed")
                return {"Item": {"cache_key": {"S": "mcp/security/oauth/cache"}}}

            def update_item(self, **kwargs: object) -> dict[str, object]:
                assert kwargs.get("TableName") == "mcp_oauth_cache_store"
                assert kwargs.get("Key") == {"cache_key": {"S": "mcp/security/oauth/cache"}}
                assert kwargs.get("ConditionExpression") == "attribute_exists(#cache_key)"
                names = kwargs.get("ExpressionAttributeNames")
                assert names == {"#payload_json": "payload_json", "#cache_key": "cache_key"}
                values = kwargs.get("ExpressionAttributeValues")
                assert isinstance(values, dict)
                payload_attr = values.get(":payload_json")
                assert isinstance(payload_attr, dict)
                payload_value = payload_attr.get("S")
                assert isinstance(payload_value, str)
                parsed_payload = json.loads(payload_value)
                assert parsed_payload["schema_version"] == cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2
                if self._scenario == 4:
                    raise RuntimeError("update-failed")
                return {}

        monkeypatch.setattr(cli_module, "_build_dynamodb_client", lambda *, cache_settings: FakeDynamoClient())
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="dynamodb-prod",
            backend="dynamodb_kv",
            dynamodb_cache_key="mcp/security/oauth/cache",
            aws_region="eu-west-2",
        )

        assert cli_module._write_oauth_cache_payload_to_dynamodb(cache_settings=settings, entries={}) is True
        assert cli_module._write_oauth_cache_payload_to_dynamodb(cache_settings=settings, entries={}) is False
        assert cli_module._write_oauth_cache_payload_to_dynamodb(cache_settings=settings, entries={}) is False
        assert cli_module._write_oauth_cache_payload_to_dynamodb(cache_settings=settings, entries={}) is False

    def test_dynamodb_client_builder_and_required_guards(self, monkeypatch):
        """DynamoDB helpers should fail closed when module/client/key identity is missing."""
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="dynamodb-prod",
            backend="dynamodb_kv",
            dynamodb_cache_key="mcp/security/oauth/cache",
            aws_region="eu-west-2",
            aws_endpoint_url="https://dynamodb.eu-west-2.amazonaws.com",
        )
        original_import_module = cli_module.importlib.import_module

        monkeypatch.setattr(
            cli_module.importlib,
            "import_module",
            lambda module_name: (
                (_ for _ in ()).throw(ImportError("missing-boto3"))
                if module_name == "boto3"
                else original_import_module(module_name)
            ),
        )
        assert cli_module._build_dynamodb_client(cache_settings=settings) is None

        class FakeBoto3MissingClient:
            pass

        monkeypatch.setattr(
            cli_module.importlib,
            "import_module",
            lambda module_name: (
                FakeBoto3MissingClient if module_name == "boto3" else original_import_module(module_name)
            ),
        )
        assert cli_module._build_dynamodb_client(cache_settings=settings) is None

        client_calls: list[dict[str, object]] = []

        class FakeBoto3:
            @staticmethod
            def client(service_name: str, **kwargs: object) -> object:
                client_calls.append({"service_name": service_name, **kwargs})
                return object()

        monkeypatch.setattr(
            cli_module.importlib,
            "import_module",
            lambda module_name: FakeBoto3 if module_name == "boto3" else original_import_module(module_name),
        )
        assert cli_module._build_dynamodb_client(cache_settings=settings) is not None
        assert client_calls == [
            {
                "service_name": "dynamodb",
                "region_name": "eu-west-2",
                "endpoint_url": "https://dynamodb.eu-west-2.amazonaws.com",
            }
        ]

        missing_key_settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="dynamodb-prod",
            backend="dynamodb_kv",
            dynamodb_cache_key=None,
            aws_region="eu-west-2",
        )
        assert cli_module._read_oauth_cache_payload_from_dynamodb(cache_settings=missing_key_settings) is None
        assert (
            cli_module._write_oauth_cache_payload_to_dynamodb(cache_settings=missing_key_settings, entries={}) is False
        )

    def test_dynamodb_persist_removes_deleted_in_memory_entry(self, monkeypatch):
        """DynamoDB persister should remove cache key when in-memory entry is missing."""
        cli_module._clear_oauth_token_cache()
        seen_entries: dict[str, dict[str, object]] = {}

        monkeypatch.setattr(
            cli_module,
            "_load_oauth_persistent_cache_entries_from_dynamodb",
            lambda *, cache_settings: {"stale-key": {"access_token": "old-token"}},
        )

        def fake_write(*, cache_settings: cli_module.OAuthCacheSettings, entries: dict[str, dict[str, object]]) -> bool:
            del cache_settings
            seen_entries.update(entries)
            return True

        monkeypatch.setattr(cli_module, "_write_oauth_cache_payload_to_dynamodb", fake_write)

        cli_module._persist_oauth_cache_entry_dynamodb(
            cache_key="stale-key",
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="dynamodb-prod",
                backend="dynamodb_kv",
                dynamodb_cache_key="mcp/security/oauth/cache",
            ),
        )

        assert seen_entries == {}

    def test_load_dynamodb_entries_parses_and_bypasses_payload(self, monkeypatch):
        """DynamoDB loader should parse payload entries and bypass cleanly on provider None."""
        monkeypatch.setattr(
            cli_module,
            "_read_oauth_cache_payload_from_dynamodb",
            lambda *, cache_settings: {
                "schema_version": cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2,
                "entries": {"k": {"access_token": "t"}},
            },
        )
        parsed_entries = cli_module._load_oauth_persistent_cache_entries_from_dynamodb(
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="dynamodb-prod",
                backend="dynamodb_kv",
                dynamodb_cache_key="mcp/security/oauth/cache",
            )
        )
        assert parsed_entries == {"k": {"access_token": "t"}}

        monkeypatch.setattr(cli_module, "_read_oauth_cache_payload_from_dynamodb", lambda *, cache_settings: None)
        bypass_entries = cli_module._load_oauth_persistent_cache_entries_from_dynamodb(
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="dynamodb-prod",
                backend="dynamodb_kv",
                dynamodb_cache_key="mcp/security/oauth/cache",
            )
        )
        assert bypass_entries == {}

    def test_build_s3_bucket_and_key_normalize_values(self):
        """S3 bucket/key builders should normalize configured values."""
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="s3-prod",
            backend="s3_object_kv",
            s3_bucket="mcp-security-cache-prod",
            s3_object_key="/mcp/security/oauth/cache.json/",
        )

        bucket_name = cli_module._build_s3_bucket_name(cache_settings=settings)
        object_key = cli_module._build_s3_object_key(cache_settings=settings)

        assert bucket_name == "mcp-security-cache-prod"
        assert object_key == "mcp/security/oauth/cache.json"

    def test_read_s3_payload_parses_and_bypasses_paths(self, monkeypatch):
        """S3 reader should parse payload and map missing object/payload to empty envelope."""

        class FakeBody:
            def __init__(self, payload: bytes | str) -> None:
                self._payload = payload

            def read(self) -> bytes | str:
                return self._payload

            def close(self) -> None:
                return None

        class NoSuchKeyError(Exception):
            def __init__(self) -> None:
                self.response = {"Error": {"Code": "NoSuchKey"}}
                super().__init__("missing-object")

        class FakeS3Client:
            call_count = 0

            def get_object(self, **kwargs: object) -> dict[str, object]:
                assert kwargs.get("Bucket") == "mcp-security-cache-prod"
                assert kwargs.get("Key") == "mcp/security/oauth/cache.json"
                FakeS3Client.call_count += 1
                if FakeS3Client.call_count == 1:
                    return {
                        "Body": FakeBody(
                            json.dumps(
                                {
                                    "schema_version": cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2,
                                    "entries": {"k": {"access_token": "t"}},
                                }
                            ).encode("utf-8")
                        )
                    }
                if FakeS3Client.call_count == 2:
                    raise NoSuchKeyError()
                if FakeS3Client.call_count == 3:
                    return {"Body": FakeBody(b"")}
                if FakeS3Client.call_count == 4:
                    return {"Body": FakeBody("{invalid-json")}
                raise RuntimeError("s3-read-failed")

        monkeypatch.setattr(cli_module, "_build_s3_object_client", lambda *, cache_settings: FakeS3Client())
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="s3-prod",
            backend="s3_object_kv",
            s3_bucket="mcp-security-cache-prod",
            s3_object_key="mcp/security/oauth/cache.json",
            aws_region="eu-west-2",
        )

        first = cli_module._read_oauth_cache_payload_from_s3_object(cache_settings=settings)
        second = cli_module._read_oauth_cache_payload_from_s3_object(cache_settings=settings)
        third = cli_module._read_oauth_cache_payload_from_s3_object(cache_settings=settings)
        fourth = cli_module._read_oauth_cache_payload_from_s3_object(cache_settings=settings)
        fifth = cli_module._read_oauth_cache_payload_from_s3_object(cache_settings=settings)

        assert first == {
            "schema_version": cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2,
            "entries": {"k": {"access_token": "t"}},
        }
        assert isinstance(second, dict)
        assert second.get("entries") == {}
        assert isinstance(third, dict)
        assert third.get("entries") == {}
        assert fourth is None
        assert fifth is None

    def test_s3_write_success_and_bypass_paths(self, monkeypatch):
        """S3 writer should support success flow and fail closed when preflight/write fails."""

        class FakeBody:
            def close(self) -> None:
                return None

        class MissingObjectError(Exception):
            def __init__(self) -> None:
                self.response = {"Error": {"Code": "NoSuchKey"}}
                super().__init__("missing-object")

        class FakeS3Client:
            call_count = 0

            def __init__(self) -> None:
                FakeS3Client.call_count += 1
                self._scenario = FakeS3Client.call_count

            def get_object(self, **kwargs: object) -> dict[str, object]:
                assert kwargs.get("Bucket") == "mcp-security-cache-prod"
                assert kwargs.get("Key") == "mcp/security/oauth/cache.json"
                if self._scenario == 1:
                    return {"Body": FakeBody()}
                if self._scenario == 2:
                    raise MissingObjectError()
                if self._scenario == 3:
                    raise RuntimeError("preflight-failed")
                return {"Body": FakeBody()}

            def put_object(self, **kwargs: object) -> dict[str, object]:
                assert kwargs.get("Bucket") == "mcp-security-cache-prod"
                assert kwargs.get("Key") == "mcp/security/oauth/cache.json"
                assert kwargs.get("ContentType") == "application/json"
                body_value = kwargs.get("Body")
                assert isinstance(body_value, (bytes, bytearray))
                parsed_payload = json.loads(bytes(body_value).decode("utf-8"))
                assert parsed_payload["schema_version"] == cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2
                if self._scenario == 4:
                    raise RuntimeError("write-failed")
                return {}

        monkeypatch.setattr(cli_module, "_build_s3_object_client", lambda *, cache_settings: FakeS3Client())
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="s3-prod",
            backend="s3_object_kv",
            s3_bucket="mcp-security-cache-prod",
            s3_object_key="mcp/security/oauth/cache.json",
            aws_region="eu-west-2",
        )

        assert cli_module._write_oauth_cache_payload_to_s3_object(cache_settings=settings, entries={}) is True
        assert cli_module._write_oauth_cache_payload_to_s3_object(cache_settings=settings, entries={}) is False
        assert cli_module._write_oauth_cache_payload_to_s3_object(cache_settings=settings, entries={}) is False
        assert cli_module._write_oauth_cache_payload_to_s3_object(cache_settings=settings, entries={}) is False

    def test_s3_client_builder_and_required_guards(self, monkeypatch):
        """S3 helpers should fail closed when module/client/bucket/object identity is missing."""
        settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="s3-prod",
            backend="s3_object_kv",
            s3_bucket="mcp-security-cache-prod",
            s3_object_key="mcp/security/oauth/cache.json",
            aws_region="eu-west-2",
            aws_endpoint_url="https://s3.eu-west-2.amazonaws.com",
        )
        original_import_module = cli_module.importlib.import_module

        monkeypatch.setattr(
            cli_module.importlib,
            "import_module",
            lambda module_name: (
                (_ for _ in ()).throw(ImportError("missing-boto3"))
                if module_name == "boto3"
                else original_import_module(module_name)
            ),
        )
        assert cli_module._build_s3_object_client(cache_settings=settings) is None

        class FakeBoto3MissingClient:
            pass

        monkeypatch.setattr(
            cli_module.importlib,
            "import_module",
            lambda module_name: (
                FakeBoto3MissingClient if module_name == "boto3" else original_import_module(module_name)
            ),
        )
        assert cli_module._build_s3_object_client(cache_settings=settings) is None

        client_calls: list[dict[str, object]] = []

        class FakeBoto3:
            @staticmethod
            def client(service_name: str, **kwargs: object) -> object:
                client_calls.append({"service_name": service_name, **kwargs})
                return object()

        monkeypatch.setattr(
            cli_module.importlib,
            "import_module",
            lambda module_name: FakeBoto3 if module_name == "boto3" else original_import_module(module_name),
        )
        assert cli_module._build_s3_object_client(cache_settings=settings) is not None
        assert client_calls == [
            {
                "service_name": "s3",
                "region_name": "eu-west-2",
                "endpoint_url": "https://s3.eu-west-2.amazonaws.com",
            }
        ]

        missing_bucket_settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="s3-prod",
            backend="s3_object_kv",
            s3_bucket=None,
            s3_object_key="mcp/security/oauth/cache.json",
            aws_region="eu-west-2",
        )
        assert cli_module._read_oauth_cache_payload_from_s3_object(cache_settings=missing_bucket_settings) is None
        assert (
            cli_module._write_oauth_cache_payload_to_s3_object(cache_settings=missing_bucket_settings, entries={})
            is False
        )

        missing_key_settings = cli_module.OAuthCacheSettings(
            persistent=True,
            namespace="s3-prod",
            backend="s3_object_kv",
            s3_bucket="mcp-security-cache-prod",
            s3_object_key=None,
            aws_region="eu-west-2",
        )
        assert cli_module._read_oauth_cache_payload_from_s3_object(cache_settings=missing_key_settings) is None
        assert (
            cli_module._write_oauth_cache_payload_to_s3_object(cache_settings=missing_key_settings, entries={}) is False
        )

    def test_s3_persist_removes_deleted_in_memory_entry(self, monkeypatch):
        """S3 persister should remove cache key when in-memory entry is missing."""
        cli_module._clear_oauth_token_cache()
        seen_entries: dict[str, dict[str, object]] = {}

        monkeypatch.setattr(
            cli_module,
            "_load_oauth_persistent_cache_entries_from_s3_object",
            lambda *, cache_settings: {"stale-key": {"access_token": "old-token"}},
        )

        def fake_write(*, cache_settings: cli_module.OAuthCacheSettings, entries: dict[str, dict[str, object]]) -> bool:
            del cache_settings
            seen_entries.update(entries)
            return True

        monkeypatch.setattr(cli_module, "_write_oauth_cache_payload_to_s3_object", fake_write)

        cli_module._persist_oauth_cache_entry_s3_object(
            cache_key="stale-key",
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="s3-prod",
                backend="s3_object_kv",
                s3_bucket="mcp-security-cache-prod",
                s3_object_key="mcp/security/oauth/cache.json",
            ),
        )

        assert seen_entries == {}

    def test_load_s3_entries_parses_and_bypasses_payload(self, monkeypatch):
        """S3 loader should parse payload entries and bypass cleanly on provider None."""
        monkeypatch.setattr(
            cli_module,
            "_read_oauth_cache_payload_from_s3_object",
            lambda *, cache_settings: {
                "schema_version": cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2,
                "entries": {"k": {"access_token": "t"}},
            },
        )
        parsed_entries = cli_module._load_oauth_persistent_cache_entries_from_s3_object(
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="s3-prod",
                backend="s3_object_kv",
                s3_bucket="mcp-security-cache-prod",
                s3_object_key="mcp/security/oauth/cache.json",
            )
        )
        assert parsed_entries == {"k": {"access_token": "t"}}

        monkeypatch.setattr(cli_module, "_read_oauth_cache_payload_from_s3_object", lambda *, cache_settings: None)
        bypass_entries = cli_module._load_oauth_persistent_cache_entries_from_s3_object(
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="s3-prod",
                backend="s3_object_kv",
                s3_bucket="mcp-security-cache-prod",
                s3_object_key="mcp/security/oauth/cache.json",
            )
        )
        assert bypass_entries == {}

    def test_resolve_oauth_cache_key_set_prefers_keyring(self, monkeypatch):
        """Key-set resolver should prefer keyring over fallback key file."""
        keyring_calls = {"value": 0}
        file_calls = {"value": 0}

        keyring_material = cli_module.OAuthCacheKeyMaterial(
            key_id="k_keyring",
            fernet_key=b"ZmFrZV9rZXlfZm9yX3Rlc3RpbmdfMDAwMDAwMDAwMDA=",
            source="keyring",
        )
        file_material = cli_module.OAuthCacheKeyMaterial(
            key_id="k_file",
            fernet_key=b"ZmFrZV9rZXlfZm9yX3Rlc3RpbmdfMTExMTExMTExMTE=",
            source="file",
        )
        keyring_set = cli_module.OAuthCacheKeySet(active=keyring_material, historical=(), source="keyring")
        file_set = cli_module.OAuthCacheKeySet(active=file_material, historical=(), source="file")

        def fake_keyring() -> cli_module.OAuthCacheKeySet | None:
            keyring_calls["value"] += 1
            return keyring_set

        def fake_file() -> cli_module.OAuthCacheKeySet | None:
            file_calls["value"] += 1
            return file_set

        monkeypatch.setattr(cli_module, "_read_oauth_cache_key_set_from_keyring", fake_keyring)
        monkeypatch.setattr(cli_module, "_read_oauth_cache_key_set_from_file", fake_file)

        resolved_key_set = cli_module._resolve_oauth_cache_key_set(create_if_missing=False)

        assert resolved_key_set == keyring_set
        assert keyring_calls["value"] == 1
        assert file_calls["value"] == 0

    def test_build_connector_config_oauth_device_code_basic_requires_client_secret_env(self, monkeypatch):
        """oauth_device_code with client_secret_basic should require client_secret_env."""
        monkeypatch.setenv("MCP_DEVICE_CLIENT_ID", "device-client")
        monkeypatch.setattr(cli_module, "_is_interactive_tty", lambda: True)

        connector_config, finding = _build_connector_config_from_config_entry(
            server_name="device_basic_server",
            raw_server_config={
                "transport": "sse",
                "url": "https://example.com/sse",
                "auth": {
                    "type": "oauth_device_code",
                    "device_authorization_url": "https://auth.example.com/device",
                    "token_url": "https://auth.example.com/token",
                    "client_id_env": "MCP_DEVICE_CLIENT_ID",
                    "token_endpoint_auth_method": "client_secret_basic",
                },
            },
            timeout=6,
        )

        assert connector_config is None
        assert finding is not None
        assert finding.category == "auth_config_error"
        assert "client_secret_env is required" in finding.evidence

    def test_build_connector_config_oauth_cache_reuses_and_refreshes_by_expiry(self, monkeypatch):
        """OAuth cache should reuse token before expiry and refresh after expiry."""
        cli_module._clear_oauth_token_cache()
        monkeypatch.setenv("MCP_OAUTH_CLIENT_ID", "client-cache")
        monkeypatch.setenv("MCP_OAUTH_CLIENT_SECRET", "secret-cache")

        now_state = {"value": 100.0}

        def fake_now() -> float:
            return float(now_state["value"])

        monkeypatch.setattr(cli_module, "_oauth_now", fake_now)

        call_count = {"value": 0}

        def fake_request(
            *,
            token_url: str,
            client_id: str,
            client_secret: str,
            scope: str | None,
            audience: str | None,
            token_endpoint_auth_method: str,
            timeout_seconds: int,
        ) -> tuple[str | None, float | None, str | None, int | None]:
            del token_url, client_id, client_secret, scope, audience, token_endpoint_auth_method, timeout_seconds
            call_count["value"] += 1
            if call_count["value"] == 1:
                return "token-first", 31.0, None, 200
            return "token-second", 31.0, None, 200

        monkeypatch.setattr(cli_module, "_request_oauth_client_credentials_token", fake_request)

        raw_server_config = {
            "transport": "streamable-http",
            "url": "https://example.com/mcp",
            "auth": {
                "type": "oauth_client_credentials",
                "token_url": "https://auth.example.com/token",
                "client_id_env": "MCP_OAUTH_CLIENT_ID",
                "client_secret_env": "MCP_OAUTH_CLIENT_SECRET",
            },
        }

        first_config, first_finding = _build_connector_config_from_config_entry(
            server_name="oauth_cache_server",
            raw_server_config=raw_server_config,
            timeout=8,
        )
        assert first_finding is None
        assert first_config is not None
        assert first_config["headers"]["Authorization"] == "Bearer token-first"
        assert call_count["value"] == 1

        now_state["value"] = 100.5
        second_config, second_finding = _build_connector_config_from_config_entry(
            server_name="oauth_cache_server",
            raw_server_config=raw_server_config,
            timeout=8,
        )
        assert second_finding is None
        assert second_config is not None
        assert second_config["headers"]["Authorization"] == "Bearer token-first"
        assert call_count["value"] == 1

        now_state["value"] = 102.0
        third_config, third_finding = _build_connector_config_from_config_entry(
            server_name="oauth_cache_server",
            raw_server_config=raw_server_config,
            timeout=8,
        )
        assert third_finding is None
        assert third_config is not None
        assert third_config["headers"]["Authorization"] == "Bearer token-second"
        assert call_count["value"] == 2

    def test_build_connector_config_oauth_device_code_refresh_flow(self, monkeypatch):
        """Expired device-code token should refresh using cached refresh_token."""
        cli_module._clear_oauth_token_cache()
        monkeypatch.setenv("MCP_DEVICE_CLIENT_ID", "device-client")
        monkeypatch.setenv("MCP_DEVICE_CLIENT_SECRET", "device-secret")
        monkeypatch.setattr(cli_module, "_is_interactive_tty", lambda: True)

        now_state = {"value": 100.0}

        def fake_now() -> float:
            return float(now_state["value"])

        monkeypatch.setattr(cli_module, "_oauth_now", fake_now)

        call_state = {"device": 0, "poll": 0, "refresh": 0}

        def fake_device_authorization(
            *,
            device_authorization_url: str,
            client_id: str,
            client_secret: str | None,
            scope: str | None,
            audience: str | None,
            timeout_seconds: int,
        ) -> tuple[dict[str, object] | None, str | None, int | None]:
            del scope, audience
            call_state["device"] += 1
            assert device_authorization_url == "https://auth.example.com/device"
            assert client_id == "device-client"
            assert client_secret == "device-secret"
            assert timeout_seconds == 7
            return (
                {
                    "device_code": "dev-code",
                    "verification_uri": "https://auth.example.com/verify",
                    "user_code": "ABCD",
                    "interval": 1,
                    "expires_in": 60,
                },
                None,
                200,
            )

        def fake_poll(
            *,
            token_url: str,
            device_code: str,
            client_id: str,
            client_secret: str | None,
            token_endpoint_auth_method: str,
            timeout_seconds: int,
            poll_interval_seconds: int,
            device_expires_in: float | None,
        ) -> tuple[str | None, float | None, str | None, str | None, int | None]:
            call_state["poll"] += 1
            assert token_url == "https://auth.example.com/token"
            assert device_code == "dev-code"
            assert client_id == "device-client"
            assert client_secret == "device-secret"
            assert token_endpoint_auth_method == "client_secret_post"
            assert timeout_seconds == 7
            assert poll_interval_seconds == 1
            assert device_expires_in == 60.0
            return "first-access-token", 1.0, "refresh-token-1", None, 200

        def fake_refresh(
            *,
            token_url: str,
            refresh_token: str,
            client_id: str,
            client_secret: str | None,
            token_endpoint_auth_method: str,
            timeout_seconds: int,
        ) -> tuple[str | None, float | None, str | None, str | None, int | None]:
            call_state["refresh"] += 1
            assert token_url == "https://auth.example.com/token"
            assert refresh_token == "refresh-token-1"
            assert client_id == "device-client"
            assert client_secret == "device-secret"
            assert token_endpoint_auth_method == "client_secret_post"
            assert timeout_seconds == 7
            return "second-access-token", 300.0, "refresh-token-2", None, 200

        monkeypatch.setattr(cli_module, "_request_oauth_device_authorization", fake_device_authorization)
        monkeypatch.setattr(cli_module, "_poll_oauth_device_code_token", fake_poll)
        monkeypatch.setattr(cli_module, "_request_oauth_refresh_token", fake_refresh)

        raw_server_config = {
            "transport": "sse",
            "url": "https://example.com/sse",
            "auth": {
                "type": "oauth_device_code",
                "device_authorization_url": "https://auth.example.com/device",
                "token_url": "https://auth.example.com/token",
                "client_id_env": "MCP_DEVICE_CLIENT_ID",
                "client_secret_env": "MCP_DEVICE_CLIENT_SECRET",
            },
        }

        first_config, first_finding = _build_connector_config_from_config_entry(
            server_name="device_oauth_server",
            raw_server_config=raw_server_config,
            timeout=7,
        )
        assert first_finding is None
        assert first_config is not None
        assert first_config["headers"]["Authorization"] == "Bearer first-access-token"

        now_state["value"] = 101.0
        second_config, second_finding = _build_connector_config_from_config_entry(
            server_name="device_oauth_server",
            raw_server_config=raw_server_config,
            timeout=7,
        )
        assert second_finding is None
        assert second_config is not None
        assert second_config["headers"]["Authorization"] == "Bearer second-access-token"

        now_state["value"] = 102.0
        third_config, third_finding = _build_connector_config_from_config_entry(
            server_name="device_oauth_server",
            raw_server_config=raw_server_config,
            timeout=7,
        )
        assert third_finding is None
        assert third_config is not None
        assert third_config["headers"]["Authorization"] == "Bearer second-access-token"

        assert call_state == {"device": 1, "poll": 1, "refresh": 1}

    def test_build_connector_config_oauth_device_code_invalid_grant_fallbacks_to_primary(self, monkeypatch):
        """invalid_grant on refresh should drop refresh token and fallback to primary flow once."""
        cli_module._clear_oauth_token_cache()
        monkeypatch.setenv("MCP_DEVICE_CLIENT_ID", "device-client")
        monkeypatch.setenv("MCP_DEVICE_CLIENT_SECRET", "device-secret")
        monkeypatch.setattr(cli_module, "_is_interactive_tty", lambda: True)

        now_state = {"value": 100.0}

        def fake_now() -> float:
            return float(now_state["value"])

        monkeypatch.setattr(cli_module, "_oauth_now", fake_now)

        cache_key = cli_module._build_oauth_cache_key(
            token_url="https://auth.example.com/token",
            client_id="device-client",
            scope=None,
            audience=None,
        )
        cli_module._store_oauth_token_cache(
            cache_key=cache_key,
            token="expired-token",
            expires_in=1.0,
            refresh_token="refresh-stale",
        )

        call_state = {"device": 0, "poll": 0, "refresh": 0}

        def fake_refresh(
            *,
            token_url: str,
            refresh_token: str,
            client_id: str,
            client_secret: str | None,
            token_endpoint_auth_method: str,
            timeout_seconds: int,
        ) -> tuple[str | None, float | None, str | None, str | None, int | None]:
            call_state["refresh"] += 1
            assert token_url == "https://auth.example.com/token"
            assert refresh_token == "refresh-stale"
            assert client_id == "device-client"
            assert client_secret == "device-secret"
            assert token_endpoint_auth_method == "client_secret_post"
            assert timeout_seconds == 7
            return None, None, None, "OAuth endpoint returned error 'invalid_grant' (HTTP 400).", 400

        def fake_device_authorization(
            *,
            device_authorization_url: str,
            client_id: str,
            client_secret: str | None,
            scope: str | None,
            audience: str | None,
            timeout_seconds: int,
        ) -> tuple[dict[str, object] | None, str | None, int | None]:
            del scope, audience
            call_state["device"] += 1
            assert device_authorization_url == "https://auth.example.com/device"
            assert client_id == "device-client"
            assert client_secret == "device-secret"
            assert timeout_seconds == 7
            return (
                {
                    "device_code": "device-fallback",
                    "verification_uri": "https://auth.example.com/verify",
                    "user_code": "ABCD",
                    "interval": 1,
                    "expires_in": 60,
                },
                None,
                200,
            )

        def fake_poll(
            *,
            token_url: str,
            device_code: str,
            client_id: str,
            client_secret: str | None,
            token_endpoint_auth_method: str,
            timeout_seconds: int,
            poll_interval_seconds: int,
            device_expires_in: float | None,
        ) -> tuple[str | None, float | None, str | None, str | None, int | None]:
            call_state["poll"] += 1
            assert token_url == "https://auth.example.com/token"
            assert device_code == "device-fallback"
            assert client_id == "device-client"
            assert client_secret == "device-secret"
            assert token_endpoint_auth_method == "client_secret_post"
            assert timeout_seconds == 7
            assert poll_interval_seconds == 1
            assert device_expires_in == 60.0
            return "fresh-access", 300.0, "refresh-fresh", None, 200

        monkeypatch.setattr(cli_module, "_request_oauth_refresh_token", fake_refresh)
        monkeypatch.setattr(cli_module, "_request_oauth_device_authorization", fake_device_authorization)
        monkeypatch.setattr(cli_module, "_poll_oauth_device_code_token", fake_poll)

        connector_config, finding = _build_connector_config_from_config_entry(
            server_name="device_oauth_server",
            raw_server_config={
                "transport": "sse",
                "url": "https://example.com/sse",
                "auth": {
                    "type": "oauth_device_code",
                    "device_authorization_url": "https://auth.example.com/device",
                    "token_url": "https://auth.example.com/token",
                    "client_id_env": "MCP_DEVICE_CLIENT_ID",
                    "client_secret_env": "MCP_DEVICE_CLIENT_SECRET",
                },
            },
            timeout=7,
        )

        assert finding is None
        assert connector_config is not None
        assert connector_config["headers"]["Authorization"] == "Bearer fresh-access"
        assert call_state == {"device": 1, "poll": 1, "refresh": 1}

    def test_build_connector_config_oauth_device_code_invalid_grant_headless_returns_finding(self, monkeypatch):
        """Headless mode should return auth_token_error when refresh fails and re-auth is required."""
        cli_module._clear_oauth_token_cache()
        monkeypatch.setenv("MCP_DEVICE_CLIENT_ID", "device-client")
        monkeypatch.setenv("MCP_DEVICE_CLIENT_SECRET", "device-secret")
        monkeypatch.setattr(cli_module, "_is_interactive_tty", lambda: False)

        cache_key = cli_module._build_oauth_cache_key(
            token_url="https://auth.example.com/token",
            client_id="device-client",
            scope=None,
            audience=None,
        )
        cli_module._store_oauth_token_cache(
            cache_key=cache_key,
            token="expired-token",
            expires_in=1.0,
            refresh_token="refresh-stale",
        )

        def fake_refresh(
            *,
            token_url: str,
            refresh_token: str,
            client_id: str,
            client_secret: str | None,
            token_endpoint_auth_method: str,
            timeout_seconds: int,
        ) -> tuple[str | None, float | None, str | None, str | None, int | None]:
            del token_url, refresh_token, client_id, client_secret, token_endpoint_auth_method, timeout_seconds
            return None, None, None, "OAuth endpoint returned error 'invalid_token' (HTTP 401).", 401

        monkeypatch.setattr(cli_module, "_request_oauth_refresh_token", fake_refresh)

        connector_config, finding = _build_connector_config_from_config_entry(
            server_name="device_oauth_server",
            raw_server_config={
                "transport": "sse",
                "url": "https://example.com/sse",
                "auth": {
                    "type": "oauth_device_code",
                    "device_authorization_url": "https://auth.example.com/device",
                    "token_url": "https://auth.example.com/token",
                    "client_id_env": "MCP_DEVICE_CLIENT_ID",
                    "client_secret_env": "MCP_DEVICE_CLIENT_SECRET",
                },
            },
            timeout=7,
        )

        assert connector_config is None
        assert finding is not None
        assert finding.category == "auth_token_error"
        assert "interactive re-authorization" in finding.evidence

    def test_poll_oauth_device_code_token_handles_pending_and_slow_down(self, monkeypatch):
        """Polling should handle authorization_pending and slow_down before success."""
        responses = [
            ({"error": "authorization_pending"}, None, 400),
            ({"error": "slow_down"}, None, 400),
            ({"access_token": "token-ok", "expires_in": 120, "refresh_token": "refresh-ok"}, None, 200),
        ]

        def fake_request_payload(
            *,
            endpoint_url: str,
            request_data: dict[str, str],
            timeout_seconds: int,
            endpoint_name: str,
            client_id: str | None = None,
            client_secret: str | None = None,
            token_endpoint_auth_method: str = "client_secret_post",
        ) -> tuple[dict[str, object] | None, str | None, int | None]:
            assert endpoint_url == "https://auth.example.com/token"
            assert request_data["grant_type"] == "urn:ietf:params:oauth:grant-type:device_code"
            assert request_data["device_code"] == "device-code"
            assert request_data["client_id"] == "client-id"
            assert timeout_seconds == 9
            assert endpoint_name == "Token endpoint"
            assert client_id == "client-id"
            assert client_secret is None
            assert token_endpoint_auth_method == "client_secret_post"
            payload, error, http_status = responses.pop(0)
            return payload, error, http_status

        monkeypatch.setattr(cli_module, "_request_oauth_form_payload", fake_request_payload)

        now_state = {"value": 0.0}
        sleeps: list[float] = []

        def fake_now() -> float:
            return float(now_state["value"])

        def fake_sleep(seconds: float) -> None:
            sleeps.append(seconds)
            now_state["value"] += seconds

        monkeypatch.setattr(cli_module, "_oauth_now", fake_now)
        monkeypatch.setattr(cli_module, "_oauth_sleep", fake_sleep)

        token_value, expires_in, refresh_token, token_error, http_status, token_type = (
            cli_module._poll_oauth_device_code_token(
                token_url="https://auth.example.com/token",
                device_code="device-code",
                client_id="client-id",
                client_secret=None,
                token_endpoint_auth_method="client_secret_post",
                timeout_seconds=9,
                poll_interval_seconds=1,
                device_expires_in=30.0,
            )
        )

        assert token_error is None
        assert http_status == 200
        assert token_value == "token-ok"
        assert expires_in == 120.0
        assert refresh_token == "refresh-ok"
        assert token_type is None
        assert sleeps == [1.0, 6.0]

    @pytest.mark.parametrize(
        ("error_code", "expected_message"),
        [
            ("access_denied", "denied"),
            ("expired_token", "expired"),
        ],
    )
    def test_poll_oauth_device_code_token_handles_terminal_errors(
        self,
        monkeypatch,
        error_code: str,
        expected_message: str,
    ):
        """Polling should map terminal OAuth errors to deterministic messages."""

        def fake_request_payload(
            *,
            endpoint_url: str,
            request_data: dict[str, str],
            timeout_seconds: int,
            endpoint_name: str,
            client_id: str | None = None,
            client_secret: str | None = None,
            token_endpoint_auth_method: str = "client_secret_post",
        ) -> tuple[dict[str, object] | None, str | None, int | None]:
            del endpoint_url, request_data, timeout_seconds, endpoint_name, client_id, client_secret
            assert token_endpoint_auth_method == "client_secret_post"
            return {"error": error_code}, None, 400

        monkeypatch.setattr(cli_module, "_request_oauth_form_payload", fake_request_payload)

        token_value, expires_in, refresh_token, token_error, http_status, token_type = (
            cli_module._poll_oauth_device_code_token(
                token_url="https://auth.example.com/token",
                device_code="device-code",
                client_id="client-id",
                client_secret=None,
                token_endpoint_auth_method="client_secret_post",
                timeout_seconds=5,
                poll_interval_seconds=1,
                device_expires_in=30.0,
            )
        )

        assert token_value is None
        assert expires_in is None
        assert refresh_token is None
        assert token_error is not None
        assert expected_message in token_error
        assert http_status == 400
        assert token_type is None

    def test_build_connector_config_success_for_oauth_auth_code_pkce_auth(self, monkeypatch):
        """Auth-code PKCE should resolve token and override explicit header."""
        cli_module._clear_oauth_token_cache()
        monkeypatch.setattr(cli_module, "_is_interactive_tty", lambda: True)
        monkeypatch.setenv("MCP_AUTH_CODE_CLIENT_ID", "auth-code-client")
        monkeypatch.setattr(cli_module, "_generate_pkce_code_verifier", lambda: "verifier-fixed")
        monkeypatch.setattr(cli_module, "_generate_oauth_state", lambda: "state-fixed")

        def fake_auth_code_flow(
            *,
            server_name: str,
            authorization_url: str,
            client_id: str,
            scope: str | None,
            audience: str | None,
            redirect_host: str,
            redirect_port: int,
            callback_path: str,
            code_challenge: str,
            expected_state: str,
            timeout_seconds: int,
        ) -> tuple[str | None, str | None, str | None, str | None]:
            assert server_name == "auth_code_server"
            assert authorization_url == "https://auth.example.com/authorize"
            assert client_id == "auth-code-client"
            assert scope == "mcp.read"
            assert audience == "scanner"
            assert redirect_host == "127.0.0.1"
            assert redirect_port == 8765
            assert callback_path == "/callback"
            assert code_challenge
            assert expected_state == "state-fixed"
            assert timeout_seconds == 9
            return "auth-code-value", "state-fixed", "http://127.0.0.1:8765/callback", None

        def fake_token_exchange(
            *,
            token_url: str,
            auth_code: str,
            redirect_uri: str,
            client_id: str,
            code_verifier: str,
            scope: str | None,
            audience: str | None,
            timeout_seconds: int,
        ) -> tuple[str | None, float | None, str | None, str | None, int | None]:
            assert token_url == "https://auth.example.com/token"
            assert auth_code == "auth-code-value"
            assert redirect_uri == "http://127.0.0.1:8765/callback"
            assert client_id == "auth-code-client"
            assert code_verifier == "verifier-fixed"
            assert scope == "mcp.read"
            assert audience == "scanner"
            assert timeout_seconds == 9
            return "auth-code-access-token", 1800.0, "refresh-auth-code", None, 200

        monkeypatch.setattr(cli_module, "_run_oauth_auth_code_pkce_flow", fake_auth_code_flow)
        monkeypatch.setattr(cli_module, "_request_oauth_auth_code_token", fake_token_exchange)

        connector_config, finding = _build_connector_config_from_config_entry(
            server_name="auth_code_server",
            raw_server_config={
                "transport": "sse",
                "url": "https://example.com/sse",
                "headers": {"Authorization": "Bearer old", "X-Trace": 99},
                "auth": {
                    "type": "oauth_auth_code_pkce",
                    "authorization_url": "https://auth.example.com/authorize",
                    "token_url": "https://auth.example.com/token",
                    "client_id_env": "MCP_AUTH_CODE_CLIENT_ID",
                    "scope": "mcp.read",
                    "audience": "scanner",
                },
            },
            timeout=9,
        )

        assert finding is None
        assert connector_config is not None
        headers = connector_config["headers"]
        assert headers["Authorization"] == "Bearer auth-code-access-token"
        assert headers["X-Trace"] == "99"

    def test_build_connector_config_oauth_auth_code_pkce_state_mismatch_returns_finding(self, monkeypatch):
        """State mismatch in callback should produce auth_token_error."""
        cli_module._clear_oauth_token_cache()
        monkeypatch.setattr(cli_module, "_is_interactive_tty", lambda: True)
        monkeypatch.setenv("MCP_AUTH_CODE_CLIENT_ID", "auth-code-client")
        monkeypatch.setattr(cli_module, "_generate_pkce_code_verifier", lambda: "verifier-fixed")
        monkeypatch.setattr(cli_module, "_generate_oauth_state", lambda: "state-expected")

        def fake_auth_code_flow(
            *,
            server_name: str,
            authorization_url: str,
            client_id: str,
            scope: str | None,
            audience: str | None,
            redirect_host: str,
            redirect_port: int,
            callback_path: str,
            code_challenge: str,
            expected_state: str,
            timeout_seconds: int,
        ) -> tuple[str | None, str | None, str | None, str | None]:
            del (
                server_name,
                authorization_url,
                client_id,
                scope,
                audience,
                redirect_host,
                redirect_port,
                callback_path,
                code_challenge,
                expected_state,
                timeout_seconds,
            )
            return "auth-code-value", "state-actual", "http://127.0.0.1:8765/callback", None

        monkeypatch.setattr(cli_module, "_run_oauth_auth_code_pkce_flow", fake_auth_code_flow)

        connector_config, finding = _build_connector_config_from_config_entry(
            server_name="auth_code_server",
            raw_server_config={
                "transport": "sse",
                "url": "https://example.com/sse",
                "auth": {
                    "type": "oauth_auth_code_pkce",
                    "authorization_url": "https://auth.example.com/authorize",
                    "token_url": "https://auth.example.com/token",
                    "client_id_env": "MCP_AUTH_CODE_CLIENT_ID",
                },
            },
            timeout=9,
        )

        assert connector_config is None
        assert finding is not None
        assert finding.category == "auth_token_error"
        assert "state mismatch" in finding.evidence

    def test_build_connector_config_oauth_auth_code_pkce_refresh_flow(self, monkeypatch):
        """Expired auth-code token should refresh using cached refresh_token."""
        cli_module._clear_oauth_token_cache()
        monkeypatch.setattr(cli_module, "_is_interactive_tty", lambda: True)
        monkeypatch.setenv("MCP_AUTH_CODE_CLIENT_ID", "auth-code-client")

        now_state = {"value": 100.0}

        def fake_now() -> float:
            return float(now_state["value"])

        monkeypatch.setattr(cli_module, "_oauth_now", fake_now)

        calls = {"flow": 0, "exchange": 0, "refresh": 0}

        def fake_auth_code_flow(
            *,
            server_name: str,
            authorization_url: str,
            client_id: str,
            scope: str | None,
            audience: str | None,
            redirect_host: str,
            redirect_port: int,
            callback_path: str,
            code_challenge: str,
            expected_state: str,
            timeout_seconds: int,
        ) -> tuple[str | None, str | None, str | None, str | None]:
            del (
                server_name,
                authorization_url,
                client_id,
                scope,
                audience,
                redirect_host,
                redirect_port,
                callback_path,
                code_challenge,
                expected_state,
                timeout_seconds,
            )
            calls["flow"] += 1
            return "auth-code-value", "state-fixed", "http://127.0.0.1:8765/callback", None

        def fake_token_exchange(
            *,
            token_url: str,
            auth_code: str,
            redirect_uri: str,
            client_id: str,
            code_verifier: str,
            scope: str | None,
            audience: str | None,
            timeout_seconds: int,
        ) -> tuple[str | None, float | None, str | None, str | None, int | None]:
            del token_url, auth_code, redirect_uri, client_id, code_verifier, scope, audience, timeout_seconds
            calls["exchange"] += 1
            return "access-first", 1.0, "refresh-first", None, 200

        def fake_refresh(
            *,
            token_url: str,
            refresh_token: str,
            client_id: str,
            client_secret: str | None,
            token_endpoint_auth_method: str,
            timeout_seconds: int,
        ) -> tuple[str | None, float | None, str | None, str | None, int | None]:
            assert client_secret is None
            assert token_endpoint_auth_method == "client_secret_post"
            del token_url, refresh_token, client_id, timeout_seconds
            calls["refresh"] += 1
            return "access-second", 120.0, "refresh-second", None, 200

        monkeypatch.setattr(cli_module, "_generate_pkce_code_verifier", lambda: "verifier-fixed")
        monkeypatch.setattr(cli_module, "_generate_oauth_state", lambda: "state-fixed")
        monkeypatch.setattr(cli_module, "_run_oauth_auth_code_pkce_flow", fake_auth_code_flow)
        monkeypatch.setattr(cli_module, "_request_oauth_auth_code_token", fake_token_exchange)
        monkeypatch.setattr(cli_module, "_request_oauth_refresh_token", fake_refresh)

        raw_server_config = {
            "transport": "sse",
            "url": "https://example.com/sse",
            "auth": {
                "type": "oauth_auth_code_pkce",
                "authorization_url": "https://auth.example.com/authorize",
                "token_url": "https://auth.example.com/token",
                "client_id_env": "MCP_AUTH_CODE_CLIENT_ID",
            },
        }

        first_config, first_finding = _build_connector_config_from_config_entry(
            server_name="auth_code_server",
            raw_server_config=raw_server_config,
            timeout=6,
        )
        assert first_finding is None
        assert first_config is not None
        assert first_config["headers"]["Authorization"] == "Bearer access-first"

        now_state["value"] = 102.0
        second_config, second_finding = _build_connector_config_from_config_entry(
            server_name="auth_code_server",
            raw_server_config=raw_server_config,
            timeout=6,
        )
        assert second_finding is None
        assert second_config is not None
        assert second_config["headers"]["Authorization"] == "Bearer access-second"

        assert calls == {"flow": 1, "exchange": 1, "refresh": 1}

    def test_request_oauth_auth_code_token_payload(self, monkeypatch):
        """Auth-code token exchange should send expected form payload."""
        captured: dict[str, object] = {}

        def fake_form_payload(
            *,
            endpoint_url: str,
            request_data: dict[str, str],
            timeout_seconds: int,
            endpoint_name: str,
            client_id: str | None = None,
            client_secret: str | None = None,
            token_endpoint_auth_method: str = "client_secret_post",
        ) -> tuple[dict[str, object] | None, str | None, int | None]:
            captured["endpoint_url"] = endpoint_url
            captured["request_data"] = request_data
            captured["timeout_seconds"] = timeout_seconds
            captured["endpoint_name"] = endpoint_name
            captured["client_id"] = client_id
            captured["client_secret"] = client_secret
            captured["token_endpoint_auth_method"] = token_endpoint_auth_method
            return {"access_token": "token-ok", "refresh_token": "refresh-ok", "expires_in": 120}, None, 200

        monkeypatch.setattr(cli_module, "_request_oauth_form_payload", fake_form_payload)

        token_value, expires_in, refresh_token, token_error, http_status, token_type = (
            cli_module._request_oauth_auth_code_token(
                token_url="https://auth.example.com/token",
                auth_code="code-123",
                redirect_uri="http://127.0.0.1:8765/callback",
                client_id="client-123",
                code_verifier="verifier-123",
                scope="mcp.read",
                audience="scanner",
                timeout_seconds=8,
            )
        )

        assert token_error is None
        assert http_status == 200
        assert token_value == "token-ok"
        assert expires_in == 120.0
        assert refresh_token == "refresh-ok"
        assert token_type is None
        assert captured["endpoint_url"] == "https://auth.example.com/token"
        assert captured["endpoint_name"] == "Token endpoint"
        request_data = captured["request_data"]
        assert isinstance(request_data, dict)
        assert request_data["grant_type"] == "authorization_code"
        assert request_data["code"] == "code-123"
        assert request_data["redirect_uri"] == "http://127.0.0.1:8765/callback"
        assert request_data["client_id"] == "client-123"
        assert request_data["code_verifier"] == "verifier-123"
        assert request_data["scope"] == "mcp.read"
        assert request_data["audience"] == "scanner"

    def test_request_oauth_form_payload_supports_client_secret_basic(self, monkeypatch):
        """OAuth form helper should send Basic auth and omit client_secret from body."""
        captured: dict[str, object] = {}

        class FakeResponse:
            status_code = 200
            text = ""

            @staticmethod
            def json() -> dict[str, object]:
                return {"access_token": "token-ok"}

        def fake_post(url: str, data: dict[str, str], headers: dict[str, str], timeout: int) -> FakeResponse:
            captured["url"] = url
            captured["data"] = data
            captured["headers"] = headers
            captured["timeout"] = timeout
            return FakeResponse()

        monkeypatch.setattr(cli_module.httpx, "post", fake_post)

        payload, request_error, http_status = cli_module._request_oauth_form_payload(
            endpoint_url="https://auth.example.com/token",
            request_data={"grant_type": "client_credentials", "client_id": "client-a", "client_secret": "secret-a"},
            timeout_seconds=7,
            endpoint_name="Token endpoint",
            client_id="client-a",
            client_secret="secret-a",
            token_endpoint_auth_method="client_secret_basic",
        )

        assert request_error is None
        assert http_status == 200
        assert payload == {"access_token": "token-ok"}
        assert captured["url"] == "https://auth.example.com/token"
        assert captured["timeout"] == 7
        headers = captured["headers"]
        assert isinstance(headers, dict)
        assert headers["Content-Type"] == "application/x-www-form-urlencoded"
        assert headers["Authorization"].startswith("Basic ")
        request_data = captured["data"]
        assert isinstance(request_data, dict)
        assert request_data["grant_type"] == "client_credentials"
        assert request_data["client_id"] == "client-a"
        assert "client_secret" not in request_data

    def test_request_oauth_form_payload_parses_form_encoded_error(self, monkeypatch):
        """OAuth form helper should parse form-encoded error payloads safely."""

        class FakeResponse:
            status_code = 400
            text = "error=invalid_grant&error_description=Bad+token"

            @staticmethod
            def json() -> dict[str, object]:
                raise ValueError("not json")

        def fake_post(url: str, data: dict[str, str], headers: dict[str, str], timeout: int) -> FakeResponse:
            del url, data, headers, timeout
            return FakeResponse()

        monkeypatch.setattr(cli_module.httpx, "post", fake_post)

        payload, request_error, http_status = cli_module._request_oauth_form_payload(
            endpoint_url="https://auth.example.com/token",
            request_data={"grant_type": "refresh_token"},
            timeout_seconds=5,
            endpoint_name="Token endpoint",
        )

        assert request_error is None
        assert http_status == 400
        assert payload is not None
        assert payload["error"] == "invalid_grant"
        assert payload["error_description"] == "Bad token"

    def test_request_oauth_form_payload_retries_retryable_status(self, monkeypatch):
        """OAuth form helper should retry once on retryable HTTP status codes."""
        calls = {"value": 0}
        sleeps: list[float] = []

        class RetryResponse:
            status_code = 429
            text = ""

            @staticmethod
            def json() -> dict[str, object]:
                return {"error": "temporarily_unavailable"}

        class SuccessResponse:
            status_code = 200
            text = ""

            @staticmethod
            def json() -> dict[str, object]:
                return {"access_token": "token-ok"}

        def fake_post(url: str, data: dict[str, str], headers: dict[str, str], timeout: int) -> object:
            del url, data, headers, timeout
            calls["value"] += 1
            if calls["value"] == 1:
                return RetryResponse()
            return SuccessResponse()

        monkeypatch.setattr(cli_module.httpx, "post", fake_post)
        monkeypatch.setattr(cli_module, "_oauth_sleep", lambda seconds: sleeps.append(seconds))

        payload, request_error, http_status = cli_module._request_oauth_form_payload(
            endpoint_url="https://auth.example.com/token",
            request_data={"grant_type": "client_credentials", "client_id": "client-a"},
            timeout_seconds=5,
            endpoint_name="Token endpoint",
        )

        assert request_error is None
        assert http_status == 200
        assert payload == {"access_token": "token-ok"}
        assert calls["value"] == 2
        assert sleeps == [cli_module._oauth_request_backoff_seconds(1)]

    def test_load_oauth_cache_entries_locked_requires_key_set(self):
        """Locked cache loader should reject missing key_set/key_material input."""
        entries, load_error = cli_module._load_oauth_cache_entries_locked()
        assert entries == {}
        assert load_error is not None
        assert "required" in load_error

    def test_load_oauth_cache_entries_locked_handles_read_error(self, monkeypatch):
        """Locked cache loader should return deterministic read error on OSError."""
        encryption_key = cli_module._generate_fernet_key()
        assert encryption_key is not None
        key_set = cli_module.OAuthCacheKeySet(
            active=cli_module.OAuthCacheKeyMaterial(
                key_id="k_read",
                fernet_key=encryption_key,
                source="test",
            ),
            historical=(),
            source="test",
        )

        class FakeCachePath:
            @staticmethod
            def read_bytes() -> bytes:
                raise OSError("read failed")

        monkeypatch.setattr(cli_module, "_OAUTH_PERSISTENT_CACHE_FILE", FakeCachePath())

        entries, load_error = cli_module._load_oauth_cache_entries_locked(key_set=key_set, recover_corrupt=False)
        assert entries == {}
        assert load_error == "Unable to read OAuth cache file."

    def test_parse_oauth_cache_entries_rejects_non_object_entries(self):
        """Cache payload parser should reject non-object entries field."""
        entries, parse_error = cli_module._parse_oauth_cache_entries_from_payload(
            {
                "schema_version": cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2,
                "entries": [],
            }
        )
        assert entries == {}
        assert parse_error is not None
        assert "entries" in parse_error

    def test_parse_oauth_cache_key_set_with_historical_and_prune(self):
        """Key-set parser should keep active key and prune historical list deterministically."""
        keys: list[str] = []
        for _ in range(5):
            generated = cli_module._generate_fernet_key()
            assert generated is not None
            keys.append(generated.decode("ascii"))

        raw_payload = json.dumps(
            {
                "active": {"key_id": "k_active", "fernet_key": keys[0]},
                "historical": [
                    {"key_id": "k_h1", "fernet_key": keys[1]},
                    {"key_id": "k_h2", "fernet_key": keys[2]},
                    {"key_id": "k_h1", "fernet_key": keys[1]},
                    {"key_id": "k_h3", "fernet_key": keys[3]},
                    {"key_id": "k_h4", "fernet_key": keys[4]},
                ],
            }
        )

        parsed = cli_module._parse_oauth_cache_key_set(raw_payload, source="file")
        assert parsed is not None
        assert parsed.active.key_id == "k_active"
        assert [item.key_id for item in parsed.historical] == ["k_h1", "k_h2", "k_h3"]

    def test_parse_oauth_cache_key_set_rejects_invalid_active_payload(self):
        """Key-set parser should reject invalid active payload objects."""
        parsed = cli_module._parse_oauth_cache_key_set(
            json.dumps(
                {
                    "active": {"key_id": "", "fernet_key": "bad"},
                    "historical": [],
                }
            ),
            source="file",
        )
        assert parsed is None

    def test_parse_oauth_cache_key_set_supports_legacy_metadata_shape(self):
        """Key-set parser should support legacy single-object key metadata."""
        encryption_key = cli_module._generate_fernet_key()
        assert encryption_key is not None
        parsed = cli_module._parse_oauth_cache_key_set(
            json.dumps({"key_id": "k_legacy", "fernet_key": encryption_key.decode("ascii")}),
            source="file",
        )
        assert parsed is not None
        assert parsed.active.key_id == "k_legacy"
        assert parsed.historical == ()

    def test_store_oauth_cache_key_set_returns_none_when_all_stores_fail(self, monkeypatch):
        """Key-set store should return None when both keyring and file stores fail."""
        encryption_key = cli_module._generate_fernet_key()
        assert encryption_key is not None
        key_set = cli_module.OAuthCacheKeySet(
            active=cli_module.OAuthCacheKeyMaterial(
                key_id="k_store_fail",
                fernet_key=encryption_key,
                source="test",
            ),
            historical=(),
            source="test",
        )
        monkeypatch.setattr(cli_module, "_write_oauth_cache_key_set_to_keyring", lambda value: False)
        monkeypatch.setattr(cli_module, "_write_oauth_cache_key_set_to_file", lambda value: False)
        assert cli_module._store_oauth_cache_key_set(key_set) is None

    def test_resolve_oauth_cache_key_set_creates_when_missing(self, monkeypatch):
        """Resolver should generate/store a new key-set when missing and allowed."""
        encryption_key = cli_module._generate_fernet_key()
        assert encryption_key is not None
        generated_key = cli_module.OAuthCacheKeyMaterial(
            key_id="k_generated",
            fernet_key=encryption_key,
            source="generated",
        )
        stored_key_set = cli_module.OAuthCacheKeySet(active=generated_key, historical=(), source="file")

        monkeypatch.setattr(cli_module, "_read_oauth_cache_key_set_from_keyring", lambda: None)
        monkeypatch.setattr(cli_module, "_read_oauth_cache_key_set_from_file", lambda: None)
        monkeypatch.setattr(cli_module, "_generate_oauth_cache_key_material", lambda: generated_key)
        monkeypatch.setattr(cli_module, "_store_oauth_cache_key_set", lambda key_set: stored_key_set)

        resolved = cli_module._resolve_oauth_cache_key_set(create_if_missing=True)
        assert resolved == stored_key_set

    def test_write_oauth_cache_entries_locked_returns_false_on_encrypt_failure(self, monkeypatch):
        """Locked cache writer should fail when encryption helper returns None."""
        encryption_key = cli_module._generate_fernet_key()
        assert encryption_key is not None
        key_set = cli_module.OAuthCacheKeySet(
            active=cli_module.OAuthCacheKeyMaterial(
                key_id="k_write_fail",
                fernet_key=encryption_key,
                source="test",
            ),
            historical=(),
            source="test",
        )
        monkeypatch.setattr(cli_module, "_encrypt_oauth_cache_payload", lambda entries, key_material: None)
        assert cli_module._write_oauth_cache_entries_locked(key_set=key_set, entries={}) is False

    def test_build_oauth_decrypt_candidates_deduplicates_by_key_id(self):
        """Decrypt candidates should skip duplicate and empty key IDs."""
        encryption_key = cli_module._generate_fernet_key()
        assert encryption_key is not None
        active = cli_module.OAuthCacheKeyMaterial(key_id="k_primary", fernet_key=encryption_key, source="test")
        duplicate = cli_module.OAuthCacheKeyMaterial(key_id="k_primary", fernet_key=encryption_key, source="test")
        empty = cli_module.OAuthCacheKeyMaterial(key_id=" ", fernet_key=encryption_key, source="test")
        secondary = cli_module.OAuthCacheKeyMaterial(key_id="k_secondary", fernet_key=encryption_key, source="test")
        key_set = cli_module.OAuthCacheKeySet(active=active, historical=(duplicate, empty, secondary), source="test")

        candidates = cli_module._build_oauth_decrypt_candidates(key_set)
        assert [item.key_id for item in candidates] == ["k_primary", "k_secondary"]

    def test_decrypt_oauth_cache_payload_with_key_set_prefers_matching_key_id(self):
        """Decrypt helper should prefer payload matching key_id when multiple keys can decrypt."""
        pytest.importorskip("cryptography")
        shared_key = cli_module._generate_fernet_key()
        assert shared_key is not None

        from cryptography.fernet import Fernet

        payload = {
            "schema_version": cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2,
            "key_id": "k_hist",
            "entries": {},
        }
        encrypted_payload = Fernet(shared_key).encrypt(json.dumps(payload).encode("utf-8"))

        active = cli_module.OAuthCacheKeyMaterial(key_id="k_active", fernet_key=shared_key, source="test")
        historical = cli_module.OAuthCacheKeyMaterial(key_id="k_hist", fernet_key=shared_key, source="test")
        key_set = cli_module.OAuthCacheKeySet(active=active, historical=(historical,), source="test")

        parsed_payload = cli_module._decrypt_oauth_cache_payload_with_key_set(encrypted_payload, key_set)
        assert parsed_payload is not None
        assert parsed_payload["key_id"] == "k_hist"

    def test_decrypt_oauth_cache_payload_with_key_set_fallback_without_key_id(self):
        """Decrypt helper should return fallback payload when no key_id is present."""
        pytest.importorskip("cryptography")
        shared_key = cli_module._generate_fernet_key()
        assert shared_key is not None

        from cryptography.fernet import Fernet

        payload = {
            "schema_version": cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2,
            "entries": {"k": {"access_token": "token"}},
        }
        encrypted_payload = Fernet(shared_key).encrypt(json.dumps(payload).encode("utf-8"))

        active = cli_module.OAuthCacheKeyMaterial(key_id="k_active", fernet_key=shared_key, source="test")
        historical = cli_module.OAuthCacheKeyMaterial(key_id="k_hist", fernet_key=shared_key, source="test")
        key_set = cli_module.OAuthCacheKeySet(active=active, historical=(historical,), source="test")

        parsed_payload = cli_module._decrypt_oauth_cache_payload_with_key_set(encrypted_payload, key_set)
        assert parsed_payload == payload

    def test_oauth_persistent_cache_encrypt_decrypt_roundtrip(self):
        """Encrypted cache payload should decrypt back to original entries."""
        pytest.importorskip("cryptography")
        encryption_key = cli_module._generate_fernet_key()
        assert encryption_key is not None
        key_material = cli_module.OAuthCacheKeyMaterial(
            key_id="k_test",
            fernet_key=encryption_key,
            source="test",
        )

        entries: dict[str, dict[str, object]] = {
            "ns\x1fhttps://auth.example.com/token\x1fclient\x1f\x1f": {
                "access_token": "token-1",
                "expires_at": 123.0,
                "refresh_token": "refresh-1",
                "token_type": "Bearer",
            }
        }
        encrypted_payload = cli_module._encrypt_oauth_cache_payload(
            entries=entries,
            key_material=key_material,
        )
        assert encrypted_payload is not None

        parsed_payload = cli_module._decrypt_oauth_cache_payload(
            encrypted_payload=encrypted_payload,
            encryption_key=encryption_key,
        )
        assert parsed_payload is not None
        assert parsed_payload["schema_version"] == cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2
        assert parsed_payload["key_id"] == "k_test"
        assert "updated_at" in parsed_payload
        assert parsed_payload["entries"] == entries

    def test_create_oauth_callback_http_server_retries_random_port(self):
        """Callback server should fallback to random port if preferred is unavailable."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as occupied_socket:
            occupied_socket.bind(("127.0.0.1", 0))
            occupied_socket.listen(1)
            occupied_port = occupied_socket.getsockname()[1]

            callback_server, callback_port, callback_payload, callback_error = (
                cli_module._create_oauth_callback_http_server(
                    host="127.0.0.1",
                    preferred_port=int(occupied_port),
                    callback_path="/callback",
                )
            )

        assert callback_error is None
        assert callback_server is not None
        assert callback_port is not None
        assert callback_payload is not None
        assert callback_port != occupied_port
        callback_server.server_close()

    def test_generate_pkce_code_challenge_matches_known_vector(self):
        """PKCE challenge helper should produce deterministic S256 challenge."""
        challenge = cli_module._generate_pkce_code_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
        assert challenge == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

    def test_run_oauth_auth_code_pkce_flow_success_with_local_callback(self, monkeypatch):
        """Auth-code PKCE flow should capture code/state via local callback listener."""

        def fake_emit(server_name: str, authorization_request_url: str) -> None:
            assert server_name == "pkce-server"
            parsed_url = urlparse(authorization_request_url)
            query_params = parse_qs(parsed_url.query)
            redirect_uri = query_params["redirect_uri"][0]

            def _send_callback() -> None:
                time.sleep(0.1)
                callback_url = f"{redirect_uri}?code=code-local&state=state-local"
                httpx.get(callback_url, timeout=2)

            threading.Thread(target=_send_callback, daemon=True).start()

        import httpx

        monkeypatch.setattr(cli_module, "_emit_oauth_auth_code_pkce_instructions", fake_emit)

        auth_code, callback_state, redirect_uri, flow_error = cli_module._run_oauth_auth_code_pkce_flow(
            server_name="pkce-server",
            authorization_url="https://auth.example.com/authorize?prompt=consent",
            client_id="client-123",
            scope="mcp.read",
            audience="scanner",
            redirect_host="127.0.0.1",
            redirect_port=8765,
            callback_path="/callback",
            code_challenge="challenge-123",
            expected_state="state-local",
            timeout_seconds=3,
        )

        assert flow_error is None
        assert auth_code == "code-local"
        assert callback_state == "state-local"
        assert redirect_uri is not None

    def test_run_oauth_auth_code_pkce_flow_handles_callback_error(self, monkeypatch):
        """Auth-code PKCE flow should surface OAuth callback errors."""

        def fake_emit(server_name: str, authorization_request_url: str) -> None:
            del server_name
            parsed_url = urlparse(authorization_request_url)
            query_params = parse_qs(parsed_url.query)
            redirect_uri = query_params["redirect_uri"][0]

            def _send_callback() -> None:
                time.sleep(0.1)
                callback_url = f"{redirect_uri}?error=access_denied&error_description=Denied"
                httpx.get(callback_url, timeout=2)

            threading.Thread(target=_send_callback, daemon=True).start()

        import httpx

        monkeypatch.setattr(cli_module, "_emit_oauth_auth_code_pkce_instructions", fake_emit)

        auth_code, callback_state, redirect_uri, flow_error = cli_module._run_oauth_auth_code_pkce_flow(
            server_name="pkce-server",
            authorization_url="https://auth.example.com/authorize",
            client_id="client-123",
            scope=None,
            audience=None,
            redirect_host="127.0.0.1",
            redirect_port=8765,
            callback_path="/callback",
            code_challenge="challenge-123",
            expected_state="state-local",
            timeout_seconds=3,
        )

        assert auth_code is None
        assert callback_state is None
        assert redirect_uri is not None
        assert flow_error is not None
        assert "access_denied" in flow_error

    def test_build_connector_config_auth_missing_env_returns_finding(self, monkeypatch):
        """Missing auth env values should return auth_config_error findings."""
        monkeypatch.delenv("MCP_MISSING_TOKEN", raising=False)
        connector_config, finding = _build_connector_config_from_config_entry(
            server_name="auth_server",
            raw_server_config={
                "transport": "sse",
                "url": "https://example.com/sse",
                "auth": {"type": "bearer", "token_env": "MCP_MISSING_TOKEN"},
            },
            timeout=9,
        )

        assert connector_config is None
        assert finding is not None
        assert finding.category == "auth_config_error"
        assert finding.metadata["server_name"] == "auth_server"
        assert finding.metadata["transport"] == "sse"
        assert finding.metadata["auth_type"] == "bearer"
        assert finding.metadata["env_var"] == "MCP_MISSING_TOKEN"
        assert "MCP_MISSING_TOKEN" in finding.evidence

    @pytest.mark.parametrize(
        ("raw_server_config", "expected_category"),
        [
            (42, "invalid_config_entry"),
            ({"transport": 7, "command": "python"}, "invalid_transport"),
            ({"transport": "grpc", "command": "python"}, "unsupported_transport"),
            ({"transport": "sse"}, "invalid_config_entry"),
            ({"transport": "sse", "url": "ftp://example.com/sse"}, "invalid_url"),
            ({"transport": "sse", "url": "https://example.com/sse", "headers": "bad"}, "invalid_headers"),
            ({"transport": "streamable-http"}, "invalid_config_entry"),
            ({"transport": "streamable-http", "url": "ftp://example.com/mcp"}, "invalid_url"),
            (
                {"transport": "streamable-http", "url": "https://example.com/mcp", "headers": "bad"},
                "invalid_headers",
            ),
            ({"transport": "stdio"}, "invalid_config_entry"),
            (
                {"transport": "stdio", "command": "python", "auth": {"type": "bearer", "token_env": "X"}},
                "auth_config_error",
            ),
            ({"transport": "stdio", "command": "python", "args": "--bad"}, "invalid_args"),
            ({"transport": "stdio", "command": "python", "env": "--bad"}, "invalid_env"),
            ({"transport": "sse", "url": "https://example.com/sse", "auth": "bad"}, "auth_config_error"),
            ({"transport": "sse", "url": "https://example.com/sse", "auth": {"type": "unknown"}}, "auth_config_error"),
            (
                {
                    "transport": "sse",
                    "url": "https://example.com/sse",
                    "auth": {
                        "type": "oauth_client_credentials",
                        "client_id_env": "CLIENT_ID_ENV",
                        "client_secret_env": "CLIENT_SECRET_ENV",
                    },
                },
                "auth_config_error",
            ),
            (
                {
                    "transport": "sse",
                    "url": "https://example.com/sse",
                    "auth": {
                        "type": "oauth_client_credentials",
                        "token_url": "ftp://auth.example.com/token",
                        "client_id_env": "CLIENT_ID_ENV",
                        "client_secret_env": "CLIENT_SECRET_ENV",
                    },
                },
                "auth_config_error",
            ),
            (
                {
                    "transport": "sse",
                    "url": "https://example.com/sse",
                    "auth": {
                        "type": "oauth_client_credentials",
                        "token_url": "https://auth.example.com/token",
                        "client_id_env": "CLIENT_ID_ENV",
                        "client_secret_env": "CLIENT_SECRET_ENV",
                        "token_endpoint_auth_method": "unknown",
                    },
                },
                "auth_config_error",
            ),
            (
                {
                    "transport": "sse",
                    "url": "https://example.com/sse",
                    "auth": {
                        "type": "oauth_device_code",
                        "token_url": "https://auth.example.com/token",
                        "client_id_env": "CLIENT_ID_ENV",
                    },
                },
                "auth_config_error",
            ),
            (
                {
                    "transport": "sse",
                    "url": "https://example.com/sse",
                    "auth": {
                        "type": "oauth_device_code",
                        "device_authorization_url": "https://auth.example.com/device",
                        "token_url": "https://auth.example.com/token",
                        "client_id_env": "CLIENT_ID_ENV",
                        "token_endpoint_auth_method": "client_secret_basic",
                    },
                },
                "auth_config_error",
            ),
            (
                {
                    "transport": "sse",
                    "url": "https://example.com/sse",
                    "auth": {
                        "type": "oauth_device_code",
                        "device_authorization_url": "ftp://auth.example.com/device",
                        "token_url": "https://auth.example.com/token",
                        "client_id_env": "CLIENT_ID_ENV",
                    },
                },
                "auth_config_error",
            ),
            (
                {
                    "transport": "sse",
                    "url": "https://example.com/sse",
                    "auth": {
                        "type": "oauth_auth_code_pkce",
                        "token_url": "https://auth.example.com/token",
                        "client_id_env": "CLIENT_ID_ENV",
                    },
                },
                "auth_config_error",
            ),
            (
                {
                    "transport": "sse",
                    "url": "https://example.com/sse",
                    "auth": {
                        "type": "oauth_auth_code_pkce",
                        "authorization_url": "https://auth.example.com/authorize",
                        "token_url": "https://auth.example.com/token",
                        "client_id_env": "CLIENT_ID_ENV",
                        "callback_path": "callback",
                    },
                },
                "auth_config_error",
            ),
            (
                {
                    "transport": "sse",
                    "url": "https://example.com/sse",
                    "auth": {
                        "type": "oauth_auth_code_pkce",
                        "authorization_url": "https://auth.example.com/authorize",
                        "token_url": "https://auth.example.com/token",
                        "client_id_env": "CLIENT_ID_ENV",
                        "redirect_port": 70000,
                    },
                },
                "auth_config_error",
            ),
            (
                {
                    "transport": "sse",
                    "url": "https://example.com/sse",
                    "auth": {
                        "type": "bearer",
                        "token_env": "TOKEN_ENV",
                        "cache": {"persistent": True},
                    },
                },
                "auth_config_error",
            ),
            (
                {
                    "transport": "sse",
                    "url": "https://example.com/sse",
                    "auth": {
                        "type": "oauth_client_credentials",
                        "cache": "bad",
                    },
                },
                "auth_config_error",
            ),
            (
                {
                    "transport": "sse",
                    "url": "https://example.com/sse",
                    "auth": {
                        "type": "oauth_client_credentials",
                        "cache": {"persistent": "yes"},
                    },
                },
                "auth_config_error",
            ),
            (
                {
                    "transport": "sse",
                    "url": "https://example.com/sse",
                    "auth": {
                        "type": "oauth_client_credentials",
                        "cache": {"namespace": ""},
                    },
                },
                "auth_config_error",
            ),
            (
                {
                    "transport": "sse",
                    "url": "https://example.com/sse",
                    "auth": {
                        "type": "oauth_client_credentials",
                        "cache": {"persistent": True, "namespace": "ns", "extra": 1},
                    },
                },
                "auth_config_error",
            ),
        ],
    )
    def test_build_connector_config_error_paths(self, raw_server_config: object, expected_category: str):
        """Invalid entries should return categorized findings without connector config."""
        connector_config, finding = _build_connector_config_from_config_entry(
            server_name="sample",
            raw_server_config=raw_server_config,
            timeout=5,
        )

        assert connector_config is None
        assert finding is not None
        assert finding.category == expected_category
        assert finding.metadata["server_name"] == "sample"

    def test_compose_stdio_command_handles_args_and_rejects_invalid_shape(self):
        """Command composer should preserve token semantics and reject non-list args."""
        command = _compose_stdio_command(
            "python",
            ["-m", "server.module", "--name", "value with space"],
        )

        assert command is not None
        assert shlex.split(command) == ["python", "-m", "server.module", "--name", "value with space"]
        assert _compose_stdio_command("python", None) == "python"
        assert _compose_stdio_command("python", "--bad") is None

    def test_build_target_connector_configs_for_url_and_stdio(self):
        """CLI target parser should infer streamable-http then sse for URL targets."""
        url_configs = _build_target_connector_configs("https://example.com/sse", timeout=9)
        stdio_configs = _build_target_connector_configs("python -m my_server", timeout=9)

        assert url_configs == [
            {"type": "streamable-http", "url": "https://example.com/sse", "timeout": 9},
            {"type": "sse", "url": "https://example.com/sse", "timeout": 9},
        ]
        assert stdio_configs == [{"type": "stdio", "command": "python -m my_server", "timeout": 9}]

    def test_build_target_connector_configs_accepts_url_target_options(self, monkeypatch, tmp_path: Path):
        """URL target config builder should normalize headers/auth/mTLS options into transport candidates."""
        monkeypatch.setenv("URL_HELPER_API_KEY", "key-value")
        cert_file = tmp_path / "client.crt"
        key_file = tmp_path / "client.key"
        cert_file.write_text("cert", encoding="utf-8")
        key_file.write_text("key", encoding="utf-8")

        url_configs = _build_target_connector_configs(
            "https://example.com/sse",
            timeout=9,
            url_target_options=URLTargetOptions(
                headers_json=json.dumps({"X-Trace": 7}),
                auth_json=json.dumps({"type": "api_key", "key_env": "URL_HELPER_API_KEY"}),
                mtls_cert_file=str(cert_file),
                mtls_key_file=str(key_file),
            ),
        )

        assert [item["type"] for item in url_configs] == ["streamable-http", "sse"]
        for item in url_configs:
            headers = item.get("headers")
            assert isinstance(headers, dict)
            assert headers["X-Trace"] == "7"
            assert headers["X-API-Key"] == "key-value"
            assert item["mtls_cert_file"] == str(cert_file)
            assert item["mtls_key_file"] == str(key_file)

    def test_build_target_connector_configs_rejects_url_options_for_stdio_target(self):
        """URL options should fail fast for stdio targets."""
        with pytest.raises(ValueError, match="URL auth/mTLS options are only supported"):
            _build_target_connector_configs(
                "python -m my_server",
                timeout=9,
                url_target_options=URLTargetOptions(headers_json="{}"),
            )

    def test_discover_capabilities_falls_back_to_second_transport(self, monkeypatch):
        """Capability discovery should fallback when first transport attempt fails."""
        attempts: list[str] = []

        class FakeConnector:
            def __init__(self, server_name: str) -> None:
                self.server_name = server_name

            async def connect(self, config: dict[str, object]) -> bool:
                transport = str(config["type"])
                attempts.append(transport)
                if transport == "streamable-http":
                    raise ConnectionError("streamable unavailable")
                return True

            async def get_server_capabilities(self) -> ServerCapabilities:
                return ServerCapabilities(server_name=self.server_name, tools=[], resources=[], prompts=[])

            async def disconnect(self) -> None:
                return None

        monkeypatch.setattr(cli_module, "MCPServerConnector", FakeConnector)

        capabilities = asyncio.run(
            cli_module._discover_capabilities(
                "example.com",
                [
                    {"type": "streamable-http", "url": "https://example.com/mcp", "timeout": 5},
                    {"type": "sse", "url": "https://example.com/sse", "timeout": 5},
                ],
            )
        )

        assert capabilities.server_name == "example.com"
        assert attempts == ["streamable-http", "sse"]

    def test_discover_capabilities_raises_after_all_attempts_fail(self, monkeypatch):
        """Capability discovery should fail when all transport attempts fail."""

        class FakeConnector:
            def __init__(self, server_name: str) -> None:
                self.server_name = server_name

            async def connect(self, config: dict[str, object]) -> bool:
                raise ConnectionError(f"cannot connect via {config['type']}")

            async def get_server_capabilities(self) -> ServerCapabilities:
                raise AssertionError("should not be called")

            async def disconnect(self) -> None:
                return None

        monkeypatch.setattr(cli_module, "MCPServerConnector", FakeConnector)

        with pytest.raises(ConnectionError, match="Attempts: streamable-http:"):
            asyncio.run(
                cli_module._discover_capabilities(
                    "example.com",
                    [
                        {"type": "streamable-http", "url": "https://example.com/mcp", "timeout": 5},
                        {"type": "sse", "url": "https://example.com/sse", "timeout": 5},
                    ],
                )
            )

    def test_helper_parsing_and_filtering(self):
        """Helper functions should parse names, thresholds and filters correctly."""
        findings = [
            Finding(
                analyzer_name="x",
                severity=Severity.LOW,
                category="cat",
                title="low",
                description="d",
                evidence="e",
            ),
            Finding(
                analyzer_name="x",
                severity=Severity.HIGH,
                category="cat",
                title="high",
                description="d",
                evidence="e",
            ),
        ]

        assert _derive_server_name("python3 /tmp/server.py") == "python3"
        assert _derive_server_name("   ") == "mcp-server"
        assert _derive_server_name("https://api.example.com/sse") == "api.example.com"
        assert _parse_severity_threshold("all") is None
        assert _parse_severity_threshold("high") == Severity.HIGH

        filtered = _filter_findings(findings, Severity.MEDIUM)
        assert [item.title for item in filtered] == ["high"]

    def test_mutation_to_finding_severity_and_category_mapping(self):
        """Mutation findings should map to Sprint 2 severity/category contract."""
        added_finding = _mutation_to_finding(
            {
                "type": "added",
                "tool_name": "new_tool",
                "baseline": None,
                "current": {"overall_hash": "abc"},
                "changed_fields": [],
            }
        )
        removed_finding = _mutation_to_finding(
            {
                "type": "removed",
                "tool_name": "old_tool",
                "baseline": {"overall_hash": "old"},
                "current": None,
                "changed_fields": [],
            }
        )
        changed_finding = _mutation_to_finding(
            {
                "type": "changed",
                "tool_name": "tool_x",
                "baseline": {"overall_hash": "old"},
                "current": {"overall_hash": "new"},
                "changed_fields": ["overall_hash"],
            }
        )

        assert added_finding.severity == Severity.MEDIUM
        assert added_finding.category == "tool_added"
        assert removed_finding.severity == Severity.HIGH
        assert removed_finding.category == "tool_removed"
        assert changed_finding.severity == Severity.HIGH
        assert changed_finding.category == "tool_changed"
        assert changed_finding.owasp_id == "LLM05"

    def test_safe_json_dump_falls_back_to_repr_for_unserializable_values(self):
        """safe JSON dump should not raise on non-serializable payloads."""

        class _Unserializable:
            def __repr__(self) -> str:
                return "<unserializable>"

        payload = {"value": _Unserializable()}
        dumped = _safe_json_dump(payload)
        assert dumped == repr(payload)

    def test_oauth_cache_supported_backend_contract_is_explicit_and_stable(self):
        """Supported backend set should remain explicit for post-1.0 stabilization."""
        assert set(cli_module._SUPPORTED_OAUTH_CACHE_BACKENDS) == {
            "local",
            "aws_secrets_manager",
            "aws_ssm_parameter_store",
            "gcp_secret_manager",
            "azure_key_vault",
            "hashicorp_vault",
            "kubernetes_secrets",
            "oci_vault",
            "doppler_secrets",
            "onepassword_connect",
            "bitwarden_secrets",
            "infisical_secrets",
            "akeyless_secrets",
            "gitlab_variables",
            "gitlab_group_variables",
            "gitlab_instance_variables",
            "github_actions_variables",
            "github_environment_variables",
            "github_organization_variables",
            "consul_kv",
            "redis_kv",
            "cloudflare_kv",
            "etcd_kv",
            "postgres_kv",
            "mysql_kv",
            "mongo_kv",
            "dynamodb_kv",
            "s3_object_kv",
        }

    def test_oauth_cache_remote_expected_handler_maps_are_derived_from_specs(self):
        """Expected remote handler maps should mirror canonical backend specs exactly."""
        expected_loaders = {
            backend: loader
            for backend, (loader, _persister) in cli_module._OAUTH_REMOTE_PERSISTENT_CACHE_BACKEND_SPECS.items()
        }
        expected_persisters = {
            backend: persister
            for backend, (_loader, persister) in cli_module._OAUTH_REMOTE_PERSISTENT_CACHE_BACKEND_SPECS.items()
        }
        assert cli_module._OAUTH_REMOTE_PERSISTENT_CACHE_EXPECTED_LOADERS == expected_loaders
        assert cli_module._OAUTH_REMOTE_PERSISTENT_CACHE_EXPECTED_PERSISTERS == expected_persisters

    def test_oauth_cache_backend_set_delta_is_sorted_and_deterministic(self):
        """Contract delta formatter should emit deterministic missing/extra ordering."""
        delta = cli_module._format_oauth_backend_set_delta(
            expected={"zeta_backend", "alpha_backend", "beta_backend"},
            actual={"beta_backend", "omega_backend"},
        )
        assert delta == "missing=['alpha_backend', 'zeta_backend'], extra=['omega_backend']"

    def test_oauth_cache_remote_handler_maps_cover_all_non_local_backends(self):
        """Remote backend spec should be the single source of truth for load/persist handler maps."""
        remote_backends = set(cli_module._SUPPORTED_OAUTH_CACHE_BACKENDS) - {cli_module._OAUTH_CACHE_BACKEND_LOCAL}
        expected_loaders = {
            backend: loader
            for backend, (loader, _persister) in cli_module._OAUTH_REMOTE_PERSISTENT_CACHE_BACKEND_SPECS.items()
        }
        expected_persisters = {
            backend: persister
            for backend, (_loader, persister) in cli_module._OAUTH_REMOTE_PERSISTENT_CACHE_BACKEND_SPECS.items()
        }

        assert set(cli_module._OAUTH_REMOTE_PERSISTENT_CACHE_BACKEND_SPECS) == remote_backends
        assert set(cli_module._OAUTH_REMOTE_PERSISTENT_CACHE_LOADERS) == remote_backends
        assert set(cli_module._OAUTH_REMOTE_PERSISTENT_CACHE_PERSISTERS) == remote_backends
        assert cli_module._OAUTH_REMOTE_PERSISTENT_CACHE_LOADERS == expected_loaders
        assert cli_module._OAUTH_REMOTE_PERSISTENT_CACHE_PERSISTERS == expected_persisters

        for function_name in cli_module._OAUTH_REMOTE_PERSISTENT_CACHE_LOADERS.values():
            assert callable(getattr(cli_module, function_name, None))

        for function_name in cli_module._OAUTH_REMOTE_PERSISTENT_CACHE_PERSISTERS.values():
            assert callable(getattr(cli_module, function_name, None))

    def test_oauth_cache_backend_contract_snapshot_matches_canonical_maps(self):
        """Contract snapshot helper should expose canonical backend maps without drift."""
        snapshot = cli_module._oauth_cache_backend_contract_snapshot()

        assert snapshot["remote_supported_backends"] == (
            set(cli_module._SUPPORTED_OAUTH_CACHE_BACKENDS) - {cli_module._OAUTH_CACHE_BACKEND_LOCAL}
        )
        assert snapshot["remote_backends"] == cli_module._OAUTH_REMOTE_PERSISTENT_CACHE_BACKENDS
        assert snapshot["loader_map"] == cli_module._OAUTH_REMOTE_PERSISTENT_CACHE_LOADERS
        assert snapshot["persister_map"] == cli_module._OAUTH_REMOTE_PERSISTENT_CACHE_PERSISTERS
        assert snapshot["expected_loaders"] == {
            backend: loader
            for backend, (loader, _persister) in cli_module._OAUTH_REMOTE_PERSISTENT_CACHE_BACKEND_SPECS.items()
        }
        assert snapshot["expected_persisters"] == {
            backend: persister
            for backend, (_loader, persister) in cli_module._OAUTH_REMOTE_PERSISTENT_CACHE_BACKEND_SPECS.items()
        }

    def test_oauth_cache_backend_contract_error_returns_none_for_consistent_maps(self):
        """Backend contract helper should return no error when canonical maps are aligned."""
        assert cli_module._oauth_cache_backend_contract_error() is None

    def test_oauth_cache_backend_contract_error_detects_loader_source_mismatch(self, monkeypatch):
        """Backend contract helper should detect map/source drift for loader mapping."""
        broken_loaders = dict(cli_module._OAUTH_REMOTE_PERSISTENT_CACHE_LOADERS)
        backend_name = next(iter(cli_module._OAUTH_REMOTE_PERSISTENT_CACHE_BACKEND_SPECS))
        expected_loader, _expected_persister = cli_module._OAUTH_REMOTE_PERSISTENT_CACHE_BACKEND_SPECS[backend_name]
        broken_loaders[backend_name] = "_missing_loader_symbol"
        monkeypatch.setattr(cli_module, "_OAUTH_REMOTE_PERSISTENT_CACHE_LOADERS", broken_loaders)

        contract_error = cli_module._oauth_cache_backend_contract_error()

        assert contract_error is not None
        assert "remote loader source mismatch" in contract_error
        assert f"backend={backend_name}" in contract_error
        assert f"expected={expected_loader}" in contract_error
        assert "actual=_missing_loader_symbol" in contract_error

    def test_oauth_cache_backend_contract_error_detects_loader_callable_mismatch(self, monkeypatch):
        """Backend contract helper should fail when loader map points to a non-callable symbol."""
        broken_loaders = dict(cli_module._OAUTH_REMOTE_PERSISTENT_CACHE_LOADERS)
        broken_specs = dict(cli_module._OAUTH_REMOTE_PERSISTENT_CACHE_BACKEND_SPECS)
        backend_name = next(iter(cli_module._OAUTH_REMOTE_PERSISTENT_CACHE_BACKEND_SPECS))
        loader_symbol = "_oauth_contract_non_callable_loader"
        broken_loaders[backend_name] = loader_symbol
        current_loader, current_persister = broken_specs[backend_name]
        assert isinstance(current_loader, str)
        broken_specs[backend_name] = (loader_symbol, current_persister)
        monkeypatch.setattr(cli_module, "_OAUTH_REMOTE_PERSISTENT_CACHE_LOADERS", broken_loaders)
        monkeypatch.setattr(cli_module, "_OAUTH_REMOTE_PERSISTENT_CACHE_BACKEND_SPECS", broken_specs)
        monkeypatch.setattr(cli_module, loader_symbol, object(), raising=False)

        contract_error = cli_module._oauth_cache_backend_contract_error()

        assert contract_error is not None
        assert "remote loader callable mismatch" in contract_error
        assert f"backend={backend_name}" in contract_error
        assert f"symbol={loader_symbol}" in contract_error

    def test_oauth_cache_backend_contract_error_detects_persister_source_mismatch(self, monkeypatch):
        """Backend contract helper should detect map/source drift for persister mapping."""
        broken_persisters = dict(cli_module._OAUTH_REMOTE_PERSISTENT_CACHE_PERSISTERS)
        backend_name = next(iter(cli_module._OAUTH_REMOTE_PERSISTENT_CACHE_BACKEND_SPECS))
        _expected_loader, expected_persister = cli_module._OAUTH_REMOTE_PERSISTENT_CACHE_BACKEND_SPECS[backend_name]
        broken_persisters[backend_name] = "_missing_persister_symbol"
        monkeypatch.setattr(cli_module, "_OAUTH_REMOTE_PERSISTENT_CACHE_PERSISTERS", broken_persisters)

        contract_error = cli_module._oauth_cache_backend_contract_error()

        assert contract_error is not None
        assert "remote persister source mismatch" in contract_error
        assert f"backend={backend_name}" in contract_error
        assert f"expected={expected_persister}" in contract_error
        assert "actual=_missing_persister_symbol" in contract_error

    def test_oauth_cache_backend_contract_error_detects_persister_callable_mismatch(self, monkeypatch):
        """Backend contract helper should fail when persister map points to a non-callable symbol."""
        broken_persisters = dict(cli_module._OAUTH_REMOTE_PERSISTENT_CACHE_PERSISTERS)
        broken_specs = dict(cli_module._OAUTH_REMOTE_PERSISTENT_CACHE_BACKEND_SPECS)
        backend_name = next(iter(cli_module._OAUTH_REMOTE_PERSISTENT_CACHE_BACKEND_SPECS))
        persister_symbol = "_oauth_contract_non_callable_persister"
        broken_persisters[backend_name] = persister_symbol
        current_loader, current_persister = broken_specs[backend_name]
        assert isinstance(current_persister, str)
        broken_specs[backend_name] = (current_loader, persister_symbol)
        monkeypatch.setattr(cli_module, "_OAUTH_REMOTE_PERSISTENT_CACHE_PERSISTERS", broken_persisters)
        monkeypatch.setattr(cli_module, "_OAUTH_REMOTE_PERSISTENT_CACHE_BACKEND_SPECS", broken_specs)
        monkeypatch.setattr(cli_module, persister_symbol, object(), raising=False)

        contract_error = cli_module._oauth_cache_backend_contract_error()

        assert contract_error is not None
        assert "remote persister callable mismatch" in contract_error
        assert f"backend={backend_name}" in contract_error
        assert f"symbol={persister_symbol}" in contract_error

    def test_oauth_cache_backend_contract_error_detects_supported_backend_set_mismatch(self, monkeypatch):
        """Backend contract helper should fail when supported-set and remote backend specs drift."""
        monkeypatch.setattr(
            cli_module,
            "_SUPPORTED_OAUTH_CACHE_BACKENDS",
            frozenset({cli_module._OAUTH_CACHE_BACKEND_LOCAL}),
        )

        contract_error = cli_module._oauth_cache_backend_contract_error()

        assert contract_error is not None
        assert "supported backend set mismatch" in contract_error
        assert "missing=[" in contract_error
        assert "extra=[]" in contract_error
        assert "aws_secrets_manager" in contract_error

    def test_oauth_cache_backend_contract_error_detects_loader_map_key_mismatch(self, monkeypatch):
        """Backend contract helper should report deterministic missing/extra detail for loader map drift."""
        broken_loaders = dict(cli_module._OAUTH_REMOTE_PERSISTENT_CACHE_LOADERS)
        removed_backend = next(iter(cli_module._OAUTH_REMOTE_PERSISTENT_CACHE_BACKEND_SPECS))
        broken_loaders.pop(removed_backend)
        broken_loaders["oauth_contract_extra_loader_backend"] = "_oauth_contract_extra_loader_symbol"
        monkeypatch.setattr(cli_module, "_OAUTH_REMOTE_PERSISTENT_CACHE_LOADERS", broken_loaders)

        contract_error = cli_module._oauth_cache_backend_contract_error()

        assert contract_error is not None
        assert "remote loader map mismatch" in contract_error
        assert f"missing=['{removed_backend}']" in contract_error
        assert "extra=['oauth_contract_extra_loader_backend']" in contract_error

    def test_oauth_cache_backend_contract_error_detects_persister_map_key_mismatch(self, monkeypatch):
        """Backend contract helper should report deterministic missing/extra detail for persister map drift."""
        broken_persisters = dict(cli_module._OAUTH_REMOTE_PERSISTENT_CACHE_PERSISTERS)
        removed_backend = next(iter(cli_module._OAUTH_REMOTE_PERSISTENT_CACHE_BACKEND_SPECS))
        broken_persisters.pop(removed_backend)
        broken_persisters["oauth_contract_extra_persister_backend"] = "_oauth_contract_extra_persister_symbol"
        monkeypatch.setattr(cli_module, "_OAUTH_REMOTE_PERSISTENT_CACHE_PERSISTERS", broken_persisters)

        contract_error = cli_module._oauth_cache_backend_contract_error()

        assert contract_error is not None
        assert "remote persister map mismatch" in contract_error
        assert f"missing=['{removed_backend}']" in contract_error
        assert "extra=['oauth_contract_extra_persister_backend']" in contract_error

    @pytest.mark.parametrize(
        "backend",
        sorted(set(cli_module._SUPPORTED_OAUTH_CACHE_BACKENDS) - {cli_module._OAUTH_CACHE_BACKEND_LOCAL}),
    )
    def test_oauth_cache_remote_dispatch_resolvers_cover_all_remote_backends(self, backend: str):
        """Remote backend contract must resolve callable loader/persister handlers for every remote backend."""
        loader = cli_module._resolve_oauth_remote_persistent_cache_loader(backend)
        persister = cli_module._resolve_oauth_remote_persistent_cache_persister(backend)
        assert callable(loader)
        assert callable(persister)

    def test_oauth_cache_remote_dispatch_resolvers_return_none_for_non_remote_backend(self):
        """Resolver helpers should not resolve handlers for local/unknown backends."""
        assert cli_module._resolve_oauth_remote_persistent_cache_loader(cli_module._OAUTH_CACHE_BACKEND_LOCAL) is None
        assert (
            cli_module._resolve_oauth_remote_persistent_cache_persister(cli_module._OAUTH_CACHE_BACKEND_LOCAL) is None
        )
        assert cli_module._resolve_oauth_remote_persistent_cache_loader("unknown_backend") is None
        assert cli_module._resolve_oauth_remote_persistent_cache_persister("unknown_backend") is None

    def test_oauth_cache_remote_dispatch_generic_resolver_validates_callables(self, monkeypatch):
        """Generic remote resolver should only resolve callable symbols."""
        handler_symbol = "_oauth_contract_dummy_handler"
        non_callable_symbol = "_oauth_contract_non_callable_handler"
        monkeypatch.setattr(cli_module, handler_symbol, lambda **_: None, raising=False)
        monkeypatch.setattr(cli_module, non_callable_symbol, object(), raising=False)
        handler_map = {
            "ok": handler_symbol,
            "bad": non_callable_symbol,
        }

        resolved_ok = cli_module._resolve_oauth_remote_persistent_cache_handler("ok", handler_map)
        resolved_bad = cli_module._resolve_oauth_remote_persistent_cache_handler("bad", handler_map)
        resolved_missing = cli_module._resolve_oauth_remote_persistent_cache_handler("missing", handler_map)

        assert callable(resolved_ok)
        assert resolved_bad is None
        assert resolved_missing is None

    @pytest.mark.parametrize(
        ("backend", "loader_name"),
        [
            ("local", "_load_oauth_persistent_cache_entries_local"),
            *sorted(cli_module._OAUTH_REMOTE_PERSISTENT_CACHE_LOADERS.items()),
        ],
    )
    def test_oauth_cache_load_dispatch_contract(self, monkeypatch, backend: str, loader_name: str):
        """Persistent cache load should dispatch to exactly one backend loader."""
        called: list[tuple[str, str]] = []
        sentinel = {"contract": {"access_token": "cached-token"}}

        backend_loaders = set(cli_module._OAUTH_REMOTE_PERSISTENT_CACHE_LOADERS.values())

        for name in backend_loaders:
            monkeypatch.setattr(
                cli_module,
                name,
                lambda *, cache_settings, _name=name: called.append((_name, cache_settings.backend)) or sentinel,
            )

        monkeypatch.setattr(
            cli_module,
            "_load_oauth_persistent_cache_entries_local",
            lambda: called.append(("_load_oauth_persistent_cache_entries_local", "local")) or sentinel,
        )

        entries = cli_module._load_oauth_persistent_cache_entries(
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="contract",
                backend=backend,
            )
        )
        assert entries == sentinel
        assert called == [(loader_name, backend)]

    @pytest.mark.parametrize(
        ("backend", "persist_name"),
        [
            ("local", "_persist_oauth_cache_entry_local"),
            *sorted(cli_module._OAUTH_REMOTE_PERSISTENT_CACHE_PERSISTERS.items()),
        ],
    )
    def test_oauth_cache_persist_dispatch_contract(self, monkeypatch, backend: str, persist_name: str):
        """Persistent cache write should dispatch to exactly one backend persister."""
        called: list[tuple[str, str, str]] = []
        cache_key = "contract-key"

        backend_persisters = set(cli_module._OAUTH_REMOTE_PERSISTENT_CACHE_PERSISTERS.values())

        for name in backend_persisters:
            monkeypatch.setattr(
                cli_module,
                name,
                lambda *, cache_key, cache_settings, _name=name: called.append(
                    (_name, cache_key, cache_settings.backend)
                ),
            )

        monkeypatch.setattr(
            cli_module,
            "_persist_oauth_cache_entry_local",
            lambda cache_key: called.append(("_persist_oauth_cache_entry_local", cache_key, "local")),
        )

        cli_module._persist_oauth_cache_entry(
            cache_key,
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="contract",
                backend=backend,
            ),
        )
        assert called == [(persist_name, cache_key, backend)]

    @pytest.mark.parametrize("backend", sorted(cli_module._SUPPORTED_OAUTH_CACHE_BACKENDS))
    def test_oauth_cache_load_dispatch_bypasses_on_loader_exception(self, monkeypatch, backend: str):
        """Persistent cache load should fail closed (empty payload) when backend loader raises."""

        def raise_loader(*args: object, **kwargs: object) -> dict[str, dict[str, object]]:
            del args, kwargs
            raise RuntimeError("loader-boom")

        if backend == cli_module._OAUTH_CACHE_BACKEND_LOCAL:
            monkeypatch.setattr(cli_module, "_load_oauth_persistent_cache_entries_local", raise_loader)
        else:
            loader_name = cli_module._OAUTH_REMOTE_PERSISTENT_CACHE_LOADERS[backend]
            monkeypatch.setattr(cli_module, loader_name, raise_loader)

        entries = cli_module._load_oauth_persistent_cache_entries(
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="contract",
                backend=backend,
            )
        )
        assert entries == {}

    @pytest.mark.parametrize("backend", sorted(cli_module._SUPPORTED_OAUTH_CACHE_BACKENDS))
    def test_oauth_cache_persist_dispatch_bypasses_on_persister_exception(self, monkeypatch, backend: str):
        """Persistent cache write should bypass silently when backend persister raises."""
        cache_key = "contract-key"
        cli_module._clear_oauth_token_cache()
        cli_module._OAUTH_TOKEN_CACHE[cache_key] = {
            "access_token": "access-token",
            "expires_at": cli_module._oauth_now() + 300.0,
        }

        def raise_persister(*args: object, **kwargs: object) -> None:
            del args, kwargs
            raise RuntimeError("persister-boom")

        if backend == cli_module._OAUTH_CACHE_BACKEND_LOCAL:
            monkeypatch.setattr(cli_module, "_persist_oauth_cache_entry_local", raise_persister)
        else:
            persist_name = cli_module._OAUTH_REMOTE_PERSISTENT_CACHE_PERSISTERS[backend]
            monkeypatch.setattr(cli_module, persist_name, raise_persister)

        cli_module._persist_oauth_cache_entry(
            cache_key,
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=True,
                namespace="contract",
                backend=backend,
            ),
        )
        assert cli_module._OAUTH_TOKEN_CACHE[cache_key]["access_token"] == "access-token"
        cli_module._clear_oauth_token_cache()

    @pytest.mark.parametrize("backend", sorted(cli_module._SUPPORTED_OAUTH_CACHE_BACKENDS))
    def test_oauth_cache_hydrate_skips_persistent_layer_when_disabled(self, monkeypatch, backend: str):
        """Hydration should skip persistent backend loaders when persistence is disabled."""
        cache_key = "contract-key"
        cli_module._clear_oauth_token_cache()

        monkeypatch.setattr(
            cli_module,
            "_load_oauth_persistent_cache_entries",
            lambda cache_settings=None: (_ for _ in ()).throw(
                AssertionError("persistent cache loader must not be called when persistent=false")
            ),
        )

        cli_module._hydrate_oauth_cache_from_persistent(
            cache_key=cache_key,
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=False,
                namespace="contract",
                backend=backend,
            ),
        )

        assert cache_key not in cli_module._OAUTH_TOKEN_CACHE

    @pytest.mark.parametrize("backend", sorted(cli_module._SUPPORTED_OAUTH_CACHE_BACKENDS))
    def test_store_oauth_cache_skips_persist_when_persistence_disabled(self, monkeypatch, backend: str):
        """Token store should not invoke persistence layer when persistent=false."""
        cache_key = "contract-store"
        cli_module._clear_oauth_token_cache()
        persist_calls: list[str] = []

        monkeypatch.setattr(
            cli_module,
            "_persist_oauth_cache_entry",
            lambda cache_key, cache_settings=None: persist_calls.append(cache_key),
        )

        cli_module._store_oauth_token_cache(
            cache_key=cache_key,
            token="access-token",
            expires_in=120.0,
            refresh_token="refresh-token",
            persistent=False,
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=False,
                namespace="contract",
                backend=backend,
            ),
        )

        assert persist_calls == []
        assert cache_key in cli_module._OAUTH_TOKEN_CACHE
        cli_module._clear_oauth_token_cache()

    @pytest.mark.parametrize("backend", sorted(cli_module._SUPPORTED_OAUTH_CACHE_BACKENDS))
    def test_drop_refresh_token_skips_persist_when_persistence_disabled(self, monkeypatch, backend: str):
        """Refresh-token drop should not invoke persistence layer when persistent=false."""
        cache_key = "contract-drop"
        cli_module._clear_oauth_token_cache()
        cli_module._OAUTH_TOKEN_CACHE[cache_key] = {
            "access_token": "access-token",
            "refresh_token": "refresh-token",
            "expires_at": cli_module._oauth_now() + 120.0,
        }
        persist_calls: list[str] = []

        monkeypatch.setattr(
            cli_module,
            "_persist_oauth_cache_entry",
            lambda cache_key, cache_settings=None: persist_calls.append(cache_key),
        )

        cli_module._drop_oauth_refresh_token(
            cache_key=cache_key,
            persistent=False,
            cache_settings=cli_module.OAuthCacheSettings(
                persistent=False,
                namespace="contract",
                backend=backend,
            ),
        )

        assert persist_calls == []
        assert "refresh_token" not in cli_module._OAUTH_TOKEN_CACHE[cache_key]
        cli_module._clear_oauth_token_cache()

    @pytest.mark.parametrize(
        ("primary_builder_name", "secondary_builder_name", "read_fn_name", "write_fn_name", "settings"),
        [
            (
                "_build_aws_secrets_manager_client",
                None,
                "_read_oauth_cache_payload_from_aws",
                "_write_oauth_cache_payload_to_aws",
                cli_module.OAuthCacheSettings(
                    persistent=True,
                    namespace="contract",
                    backend="aws_secrets_manager",
                    aws_secret_id="mcp-security/oauth-cache",
                ),
            ),
            (
                "_build_aws_ssm_parameter_store_client",
                None,
                "_read_oauth_cache_payload_from_aws_ssm",
                "_write_oauth_cache_payload_to_aws_ssm",
                cli_module.OAuthCacheSettings(
                    persistent=True,
                    namespace="contract",
                    backend="aws_ssm_parameter_store",
                    aws_ssm_parameter_name="/mcp-security/oauth-cache",
                ),
            ),
            (
                "_build_gcp_secret_manager_client",
                None,
                "_read_oauth_cache_payload_from_gcp",
                "_write_oauth_cache_payload_to_gcp",
                cli_module.OAuthCacheSettings(
                    persistent=True,
                    namespace="contract",
                    backend="gcp_secret_manager",
                    gcp_secret_name="projects/demo/secrets/cache",
                ),
            ),
            (
                "_build_azure_key_vault_client",
                None,
                "_read_oauth_cache_payload_from_azure",
                "_write_oauth_cache_payload_to_azure",
                cli_module.OAuthCacheSettings(
                    persistent=True,
                    namespace="contract",
                    backend="azure_key_vault",
                    azure_vault_url="https://mcp-security.vault.azure.net",
                    azure_secret_name="mcp-security-oauth-cache",
                ),
            ),
            (
                "_build_hashicorp_vault_client",
                None,
                "_read_oauth_cache_payload_from_vault",
                "_write_oauth_cache_payload_to_vault",
                cli_module.OAuthCacheSettings(
                    persistent=True,
                    namespace="contract",
                    backend="hashicorp_vault",
                    vault_url="https://vault.example.com",
                    vault_secret_path="kv/mcp-security/oauth-cache",
                ),
            ),
            (
                "_build_kubernetes_secret_client",
                None,
                "_read_oauth_cache_payload_from_kubernetes",
                "_write_oauth_cache_payload_to_kubernetes",
                cli_module.OAuthCacheSettings(
                    persistent=True,
                    namespace="contract",
                    backend="kubernetes_secrets",
                    k8s_secret_namespace="mcp-security",
                    k8s_secret_name="oauth-cache",
                ),
            ),
            (
                "_build_oci_secrets_client",
                "_build_oci_vault_client",
                "_read_oauth_cache_payload_from_oci",
                "_write_oauth_cache_payload_to_oci",
                cli_module.OAuthCacheSettings(
                    persistent=True,
                    namespace="contract",
                    backend="oci_vault",
                    oci_secret_ocid="ocid1.secret.oc1.iad.exampleuniqueid1234567890",
                ),
            ),
            (
                "_build_doppler_http_client",
                None,
                "_read_oauth_cache_payload_from_doppler",
                "_write_oauth_cache_payload_to_doppler",
                cli_module.OAuthCacheSettings(
                    persistent=True,
                    namespace="contract",
                    backend="doppler_secrets",
                    doppler_project="security-platform",
                    doppler_config="prd",
                    doppler_secret_name="MCP_OAUTH_CACHE",
                    doppler_token_env="DOPPLER_TOKEN",
                ),
            ),
            (
                "_build_onepassword_connect_http_client",
                None,
                "_read_oauth_cache_payload_from_onepassword_connect",
                "_write_oauth_cache_payload_to_onepassword_connect",
                cli_module.OAuthCacheSettings(
                    persistent=True,
                    namespace="contract",
                    backend="onepassword_connect",
                    op_connect_host="https://op-connect.example.com",
                    op_vault_id="vault-123",
                    op_item_id="item-456",
                    op_field_label="oauth_cache",
                    op_connect_token_env="OP_CONNECT_TOKEN",
                ),
            ),
            (
                "_build_bitwarden_http_client",
                None,
                "_read_oauth_cache_payload_from_bitwarden",
                "_write_oauth_cache_payload_to_bitwarden",
                cli_module.OAuthCacheSettings(
                    persistent=True,
                    namespace="contract",
                    backend="bitwarden_secrets",
                    bw_secret_id="11111111-2222-3333-4444-555555555555",
                    bw_access_token_env="BWS_ACCESS_TOKEN",
                    bw_api_url="https://api.bitwarden.com",
                ),
            ),
            (
                "_build_infisical_http_client",
                None,
                "_read_oauth_cache_payload_from_infisical",
                "_write_oauth_cache_payload_to_infisical",
                cli_module.OAuthCacheSettings(
                    persistent=True,
                    namespace="contract",
                    backend="infisical_secrets",
                    infisical_project_id="workspace-123",
                    infisical_environment="prod",
                    infisical_secret_name="MCP_OAUTH_CACHE",
                    infisical_token_env="INFISICAL_TOKEN",
                    infisical_api_url="https://app.infisical.com/api",
                ),
            ),
            (
                "_build_akeyless_http_client",
                None,
                "_read_oauth_cache_payload_from_akeyless",
                "_write_oauth_cache_payload_to_akeyless",
                cli_module.OAuthCacheSettings(
                    persistent=True,
                    namespace="contract",
                    backend="akeyless_secrets",
                    akeyless_secret_name="/prod/mcp/oauth_cache",
                    akeyless_token_env="AKEYLESS_TOKEN",
                    akeyless_api_url="https://api.akeyless.io",
                ),
            ),
            (
                "_build_gitlab_http_client",
                None,
                "_read_oauth_cache_payload_from_gitlab",
                "_write_oauth_cache_payload_to_gitlab",
                cli_module.OAuthCacheSettings(
                    persistent=True,
                    namespace="contract",
                    backend="gitlab_variables",
                    gitlab_project_id="12345",
                    gitlab_variable_key="MCP_OAUTH_CACHE",
                    gitlab_token_env="GITLAB_TOKEN",
                    gitlab_api_url="https://gitlab.example.com/api/v4",
                ),
            ),
            (
                "_build_gitlab_http_client",
                None,
                "_read_oauth_cache_payload_from_gitlab",
                "_write_oauth_cache_payload_to_gitlab",
                cli_module.OAuthCacheSettings(
                    persistent=True,
                    namespace="contract",
                    backend="gitlab_group_variables",
                    gitlab_group_id="67890",
                    gitlab_variable_key="MCP_OAUTH_CACHE",
                    gitlab_token_env="GITLAB_TOKEN",
                    gitlab_api_url="https://gitlab.example.com/api/v4",
                ),
            ),
            (
                "_build_gitlab_http_client",
                None,
                "_read_oauth_cache_payload_from_gitlab",
                "_write_oauth_cache_payload_to_gitlab",
                cli_module.OAuthCacheSettings(
                    persistent=True,
                    namespace="contract",
                    backend="gitlab_instance_variables",
                    gitlab_variable_key="MCP_OAUTH_CACHE",
                    gitlab_token_env="GITLAB_TOKEN",
                    gitlab_api_url="https://gitlab.example.com/api/v4",
                ),
            ),
            (
                "_build_github_http_client",
                None,
                "_read_oauth_cache_payload_from_github",
                "_write_oauth_cache_payload_to_github",
                cli_module.OAuthCacheSettings(
                    persistent=True,
                    namespace="contract",
                    backend="github_actions_variables",
                    github_repository="ogulcanaydogan/mcp-security-scanner",
                    github_variable_name="MCP_OAUTH_CACHE",
                    github_token_env="GITHUB_TOKEN",
                    github_api_url="https://api.github.com",
                ),
            ),
            (
                "_build_github_http_client",
                None,
                "_read_oauth_cache_payload_from_github_environment",
                "_write_oauth_cache_payload_to_github_environment",
                cli_module.OAuthCacheSettings(
                    persistent=True,
                    namespace="contract",
                    backend="github_environment_variables",
                    github_repository="ogulcanaydogan/mcp-security-scanner",
                    github_environment_name="production",
                    github_variable_name="MCP_OAUTH_CACHE",
                    github_token_env="GITHUB_TOKEN",
                    github_api_url="https://api.github.com",
                ),
            ),
            (
                "_build_github_http_client",
                None,
                "_read_oauth_cache_payload_from_github_organization",
                "_write_oauth_cache_payload_to_github_organization",
                cli_module.OAuthCacheSettings(
                    persistent=True,
                    namespace="contract",
                    backend="github_organization_variables",
                    github_organization="ogulcanaydogan",
                    github_variable_name="MCP_OAUTH_CACHE",
                    github_token_env="GITHUB_TOKEN",
                    github_api_url="https://api.github.com",
                ),
            ),
            (
                "_build_consul_http_client",
                None,
                "_read_oauth_cache_payload_from_consul",
                "_write_oauth_cache_payload_to_consul",
                cli_module.OAuthCacheSettings(
                    persistent=True,
                    namespace="contract",
                    backend="consul_kv",
                    consul_key_path="mcp/security/oauth/cache",
                    consul_token_env="CONSUL_HTTP_TOKEN",
                    consul_api_url="https://consul.example.com",
                ),
            ),
            (
                "_build_redis_client",
                None,
                "_read_oauth_cache_payload_from_redis",
                "_write_oauth_cache_payload_to_redis",
                cli_module.OAuthCacheSettings(
                    persistent=True,
                    namespace="contract",
                    backend="redis_kv",
                    redis_key="mcp/security/oauth/cache",
                    redis_url="redis://127.0.0.1:6379/0",
                    redis_password_env="REDIS_PASSWORD",
                ),
            ),
            (
                "_build_cloudflare_http_client",
                None,
                "_read_oauth_cache_payload_from_cloudflare",
                "_write_oauth_cache_payload_to_cloudflare",
                cli_module.OAuthCacheSettings(
                    persistent=True,
                    namespace="contract",
                    backend="cloudflare_kv",
                    cf_account_id="account-123",
                    cf_namespace_id="namespace-456",
                    cf_kv_key="mcp/security/oauth/cache",
                    cf_api_token_env="CLOUDFLARE_API_TOKEN",
                    cf_api_url="https://api.cloudflare.com/client/v4",
                ),
            ),
            (
                "_build_etcd_http_client",
                None,
                "_read_oauth_cache_payload_from_etcd",
                "_write_oauth_cache_payload_to_etcd",
                cli_module.OAuthCacheSettings(
                    persistent=True,
                    namespace="contract",
                    backend="etcd_kv",
                    etcd_key="mcp/security/oauth/cache",
                    etcd_api_url="http://127.0.0.1:2379",
                    etcd_token_env="ETCD_TOKEN",
                ),
            ),
            (
                "_build_postgres_connection",
                None,
                "_read_oauth_cache_payload_from_postgres",
                "_write_oauth_cache_payload_to_postgres",
                cli_module.OAuthCacheSettings(
                    persistent=True,
                    namespace="contract",
                    backend="postgres_kv",
                    postgres_cache_key="mcp/security/oauth/cache",
                    postgres_dsn_env="POSTGRES_DSN",
                ),
            ),
            (
                "_build_mysql_connection",
                None,
                "_read_oauth_cache_payload_from_mysql",
                "_write_oauth_cache_payload_to_mysql",
                cli_module.OAuthCacheSettings(
                    persistent=True,
                    namespace="contract",
                    backend="mysql_kv",
                    mysql_cache_key="mcp/security/oauth/cache",
                    mysql_dsn_env="MYSQL_DSN",
                ),
            ),
            (
                "_build_mongo_client",
                None,
                "_read_oauth_cache_payload_from_mongo",
                "_write_oauth_cache_payload_to_mongo",
                cli_module.OAuthCacheSettings(
                    persistent=True,
                    namespace="contract",
                    backend="mongo_kv",
                    mongo_cache_key="mcp/security/oauth/cache",
                    mongo_dsn_env="MONGODB_URI",
                ),
            ),
            (
                "_build_dynamodb_client",
                None,
                "_read_oauth_cache_payload_from_dynamodb",
                "_write_oauth_cache_payload_to_dynamodb",
                cli_module.OAuthCacheSettings(
                    persistent=True,
                    namespace="contract",
                    backend="dynamodb_kv",
                    dynamodb_cache_key="mcp/security/oauth/cache",
                    aws_region="eu-west-2",
                ),
            ),
            (
                "_build_s3_object_client",
                None,
                "_read_oauth_cache_payload_from_s3_object",
                "_write_oauth_cache_payload_to_s3_object",
                cli_module.OAuthCacheSettings(
                    persistent=True,
                    namespace="contract",
                    backend="s3_object_kv",
                    s3_bucket="mcp-security-cache-prod",
                    s3_object_key="mcp/security/oauth/cache.json",
                    aws_region="eu-west-2",
                ),
            ),
        ],
    )
    def test_oauth_cache_remote_backends_bypass_when_client_unavailable(
        self,
        monkeypatch,
        primary_builder_name: str,
        secondary_builder_name: str | None,
        read_fn_name: str,
        write_fn_name: str,
        settings: cli_module.OAuthCacheSettings,
    ):
        """Remote backend read/write helpers should fail closed when client builder is unavailable."""
        monkeypatch.setattr(cli_module, primary_builder_name, lambda cache_settings: None)
        if secondary_builder_name is not None:
            monkeypatch.setattr(cli_module, secondary_builder_name, lambda cache_settings: None)

        read_fn = getattr(cli_module, read_fn_name)
        write_fn = getattr(cli_module, write_fn_name)
        assert read_fn(cache_settings=settings) is None
        assert write_fn(cache_settings=settings, entries={}) is False

    def test_load_oauth_persistent_cache_entries_bypass_on_lock_failure(self, monkeypatch):
        """Persistent cache load should bypass cleanly when lock cannot be acquired."""
        monkeypatch.setattr(cli_module, "_acquire_oauth_cache_lock", lambda: (None, "lock-timeout"))
        assert cli_module._load_oauth_persistent_cache_entries() == {}

    def test_persist_oauth_cache_entry_bypass_on_lock_failure(self, monkeypatch):
        """Persistent cache write should no-op when lock cannot be acquired."""
        cli_module._clear_oauth_token_cache()
        cli_module._OAUTH_TOKEN_CACHE["cache-key"] = {"access_token": "token-x"}
        monkeypatch.setattr(cli_module, "_acquire_oauth_cache_lock", lambda: (None, "lock-timeout"))

        cli_module._persist_oauth_cache_entry("cache-key")

        assert cli_module._OAUTH_TOKEN_CACHE["cache-key"]["access_token"] == "token-x"
        cli_module._clear_oauth_token_cache()

    def test_parse_oauth_cache_entries_supports_v1_and_rejects_invalid_schema(self):
        """Cache payload parser should support v1 and reject unknown schema versions."""
        entries, parse_error = cli_module._parse_oauth_cache_entries_from_payload(
            {
                "schema_version": cli_module._OAUTH_CACHE_SCHEMA_VERSION_V1,
                "entries": {"k": {"access_token": "t"}},
            }
        )
        assert parse_error is None
        assert entries == {"k": {"access_token": "t"}}

        invalid_entries, invalid_error = cli_module._parse_oauth_cache_entries_from_payload(
            {
                "schema_version": "v0",
                "entries": {},
            }
        )
        assert invalid_entries == {}
        assert invalid_error is not None
        assert "schema_version" in invalid_error

    def test_persist_oauth_cache_entry_upgrades_v1_payload_to_v2(self, monkeypatch, tmp_path: Path):
        """Persist path should read v1 payload and write back v2 envelope."""
        pytest.importorskip("cryptography")
        cli_module._clear_oauth_token_cache()

        cache_file = tmp_path / "oauth-cache-v1.json.enc"
        key_file = tmp_path / "cache.key"
        lock_file = tmp_path / "oauth-cache-v1.lock"
        monkeypatch.setattr(cli_module, "_OAUTH_PERSISTENT_CACHE_FILE", cache_file)
        monkeypatch.setattr(cli_module, "_OAUTH_PERSISTENT_KEY_FILE", key_file)
        monkeypatch.setattr(cli_module, "_OAUTH_PERSISTENT_CACHE_LOCK_FILE", lock_file)
        monkeypatch.setattr(cli_module, "_read_oauth_cache_key_set_from_keyring", lambda: None)

        encryption_key = cli_module._generate_fernet_key()
        assert encryption_key is not None
        key_file.write_text(encryption_key.decode("ascii"), encoding="utf-8")

        v1_payload = {
            "schema_version": cli_module._OAUTH_CACHE_SCHEMA_VERSION_V1,
            "entries": {
                "ns\x1fhttps://auth.example.com/token\x1fclient\x1f\x1f": {
                    "access_token": "legacy-token",
                    "expires_at": 1234.0,
                }
            },
        }

        from cryptography.fernet import Fernet

        cache_file.write_bytes(Fernet(encryption_key).encrypt(json.dumps(v1_payload).encode("utf-8")))
        cli_module._OAUTH_TOKEN_CACHE["ns\x1fhttps://auth.example.com/token\x1fclient\x1f\x1f"] = {
            "access_token": "new-token",
            "expires_at": 5678.0,
        }

        cli_module._persist_oauth_cache_entry("ns\x1fhttps://auth.example.com/token\x1fclient\x1f\x1f")

        upgraded_payload = json.loads(Fernet(encryption_key).decrypt(cache_file.read_bytes()).decode("utf-8"))
        assert upgraded_payload["schema_version"] == cli_module._OAUTH_CACHE_SCHEMA_VERSION_V2
        assert upgraded_payload["entries"]["ns\x1fhttps://auth.example.com/token\x1fclient\x1f\x1f"][
            "access_token"
        ] == ("new-token")
        cli_module._clear_oauth_token_cache()

    def test_load_oauth_cache_entries_locked_quarantines_invalid_schema(self, monkeypatch, tmp_path: Path):
        """Invalid decrypted payload should be quarantined when recover_corrupt is enabled."""
        pytest.importorskip("cryptography")

        cache_file = tmp_path / "oauth-cache-v1.json.enc"
        monkeypatch.setattr(cli_module, "_OAUTH_PERSISTENT_CACHE_FILE", cache_file)

        encryption_key = cli_module._generate_fernet_key()
        assert encryption_key is not None
        key_material = cli_module.OAuthCacheKeyMaterial(
            key_id="k_test",
            fernet_key=encryption_key,
            source="test",
        )

        from cryptography.fernet import Fernet

        bad_payload = {"schema_version": "unknown", "entries": {}}
        cache_file.write_bytes(Fernet(encryption_key).encrypt(json.dumps(bad_payload).encode("utf-8")))

        entries, load_error = cli_module._load_oauth_cache_entries_locked(
            key_material=key_material,
            recover_corrupt=True,
        )
        assert entries == {}
        assert load_error is not None
        assert "schema_version" in load_error
        assert not cache_file.exists()
        assert sorted(tmp_path.glob("oauth-cache-v1.json.enc.corrupt.*"))

    def test_acquire_oauth_cache_lock_returns_unavailable_when_fcntl_missing(self, monkeypatch):
        """Lock helper should report bypass reason when fcntl cannot be imported."""
        original_import_module = cli_module.importlib.import_module

        def fake_import_module(module_name: str):
            if module_name == "fcntl":
                raise ImportError("missing fcntl")
            return original_import_module(module_name)

        monkeypatch.setattr(cli_module.importlib, "import_module", fake_import_module)
        lock_handle, lock_error = cli_module._acquire_oauth_cache_lock()
        assert lock_handle is None
        assert lock_error is not None
        assert "POSIX file lock is unavailable" in lock_error

    def test_acquire_oauth_cache_lock_times_out_with_retry(self, monkeypatch, tmp_path: Path):
        """Lock helper should retry and return timeout when lock remains busy."""
        monkeypatch.setattr(cli_module, "_OAUTH_PERSISTENT_CACHE_LOCK_FILE", tmp_path / "oauth-cache-v1.lock")

        class FakeFcntl:
            LOCK_EX = 2
            LOCK_NB = 4
            LOCK_UN = 8

            @staticmethod
            def flock(fd: int, flags: int) -> None:
                del fd, flags
                raise OSError(11, "resource busy")

        original_import_module = cli_module.importlib.import_module

        def fake_import_module(module_name: str):
            if module_name == "fcntl":
                return FakeFcntl
            return original_import_module(module_name)

        monotonic_values = iter([10.0, 10.2, 12.5])
        monkeypatch.setattr(cli_module.importlib, "import_module", fake_import_module)
        monkeypatch.setattr(cli_module.time, "monotonic", lambda: next(monotonic_values))
        monkeypatch.setattr(cli_module.time, "sleep", lambda seconds: None)

        lock_handle, lock_error = cli_module._acquire_oauth_cache_lock()
        assert lock_handle is None
        assert lock_error is not None
        assert "Timed out acquiring OAuth cache lock" in lock_error

    def test_write_oauth_cache_key_material_to_file_hardens_permissions(self, monkeypatch, tmp_path: Path):
        """Fallback key file should be persisted with best-effort 0600 permissions."""
        key_file = tmp_path / "cache.key"
        monkeypatch.setattr(cli_module, "_OAUTH_PERSISTENT_KEY_FILE", key_file)

        encryption_key = cli_module._generate_fernet_key()
        assert encryption_key is not None
        key_material = cli_module.OAuthCacheKeyMaterial(
            key_id="k_perm",
            fernet_key=encryption_key,
            source="test",
        )

        assert cli_module._write_oauth_cache_key_material_to_file(key_material) is True
        mode = key_file.stat().st_mode & 0o777
        assert mode == 0o600

    def test_rotate_oauth_persistent_cache_key_fails_when_cache_exists_without_key(self, monkeypatch, tmp_path: Path):
        """Rotation should fail safely when encrypted cache exists but no key can be resolved."""
        cache_file = tmp_path / "oauth-cache-v1.json.enc"
        lock_file = tmp_path / "oauth-cache-v1.lock"
        cache_file.write_bytes(b"encrypted-bytes")
        monkeypatch.setattr(cli_module, "_OAUTH_PERSISTENT_CACHE_FILE", cache_file)
        monkeypatch.setattr(cli_module, "_OAUTH_PERSISTENT_CACHE_LOCK_FILE", lock_file)
        monkeypatch.setattr(cli_module, "_resolve_oauth_cache_key_set", lambda create_if_missing: None)

        with pytest.raises(RuntimeError, match="cache exists"):
            cli_module._rotate_oauth_persistent_cache_key()

    def test_parse_oauth_cache_key_material_supports_json_and_legacy_raw(self):
        """Key parser should support metadata envelope and legacy raw-key fallback."""
        encryption_key = cli_module._generate_fernet_key()
        assert encryption_key is not None

        metadata_value = json.dumps({"key_id": "k_meta", "fernet_key": encryption_key.decode("ascii")})
        parsed_metadata = cli_module._parse_oauth_cache_key_material(metadata_value, source="keyring")
        assert parsed_metadata is not None
        assert parsed_metadata.key_id == "k_meta"
        assert parsed_metadata.source == "keyring"

        parsed_legacy = cli_module._parse_oauth_cache_key_material(encryption_key.decode("ascii"), source="file")
        assert parsed_legacy is not None
        assert parsed_legacy.key_id == "legacy-file"
        assert parsed_legacy.source == "file"

    def test_serialize_oauth_cache_key_material_validation(self):
        """Key serializer should reject invalid key metadata."""
        encryption_key = cli_module._generate_fernet_key()
        assert encryption_key is not None

        invalid_id = cli_module.OAuthCacheKeyMaterial(
            key_id=" ",
            fernet_key=encryption_key,
            source="test",
        )
        assert cli_module._serialize_oauth_cache_key_material(invalid_id) is None

        invalid_bytes = cli_module.OAuthCacheKeyMaterial(
            key_id="k_invalid",
            fernet_key=b"\xff",
            source="test",
        )
        assert cli_module._serialize_oauth_cache_key_material(invalid_bytes) is None

    def test_keyring_key_material_read_and_write(self, monkeypatch):
        """Keyring helper should persist and read metadata payload when keyring is available."""

        class FakeKeyring:
            value: str | None = None

            @classmethod
            def get_password(cls, service: str, username: str) -> str | None:
                assert service == cli_module._OAUTH_PERSISTENT_KEYRING_SERVICE
                assert username == cli_module._OAUTH_PERSISTENT_KEYRING_USERNAME
                return cls.value

            @classmethod
            def set_password(cls, service: str, username: str, value: str) -> None:
                assert service == cli_module._OAUTH_PERSISTENT_KEYRING_SERVICE
                assert username == cli_module._OAUTH_PERSISTENT_KEYRING_USERNAME
                cls.value = value

        original_import_module = cli_module.importlib.import_module

        def fake_import_module(module_name: str):
            if module_name == "keyring":
                return FakeKeyring
            return original_import_module(module_name)

        monkeypatch.setattr(cli_module.importlib, "import_module", fake_import_module)

        encryption_key = cli_module._generate_fernet_key()
        assert encryption_key is not None
        key_material = cli_module.OAuthCacheKeyMaterial(
            key_id="k_keyring",
            fernet_key=encryption_key,
            source="test",
        )

        assert cli_module._write_oauth_cache_key_material_to_keyring(key_material) is True
        parsed = cli_module._read_oauth_cache_key_material_from_keyring()
        assert parsed is not None
        assert parsed.key_id == "k_keyring"
        assert parsed.fernet_key == encryption_key
        assert parsed.source == "keyring"

    def test_read_or_create_oauth_cache_key_file_generates_when_missing(self, monkeypatch):
        """Legacy helper should generate/store key material when no key file exists."""
        generated = cli_module.OAuthCacheKeyMaterial(
            key_id="k_generated",
            fernet_key=b"ZmFrZV9rZXlfZm9yX3Rlc3RpbmdfMTIzNDU2Nzg5MDE=",
            source="generated",
        )
        monkeypatch.setattr(cli_module, "_read_oauth_cache_key_material_from_file", lambda: None)
        monkeypatch.setattr(cli_module, "_generate_oauth_cache_key_material", lambda: generated)
        monkeypatch.setattr(cli_module, "_store_oauth_cache_key_material", lambda key_material: key_material)

        resolved_key = cli_module._read_or_create_oauth_cache_key_file()
        assert resolved_key == generated.fernet_key

    def test_rotate_oauth_persistent_cache_key_fails_when_store_fails(self, monkeypatch, tmp_path: Path):
        """Rotation should surface operational error when new key cannot be stored."""
        monkeypatch.setattr(cli_module, "_OAUTH_PERSISTENT_CACHE_FILE", tmp_path / "oauth-cache-v1.json.enc")

        dummy_handle = object()
        monkeypatch.setattr(cli_module, "_acquire_oauth_cache_lock", lambda: ((dummy_handle, object()), None))
        monkeypatch.setattr(cli_module, "_release_oauth_cache_lock", lambda lock_handle: None)
        monkeypatch.setattr(
            cli_module,
            "_generate_oauth_cache_key_material",
            lambda: cli_module.OAuthCacheKeyMaterial(
                key_id="k_new",
                fernet_key=b"ZmFrZV9rZXlfZm9yX3Rlc3RpbmdfODc2NTQzMjEwOTg=",
                source="generated",
            ),
        )
        monkeypatch.setattr(cli_module, "_store_oauth_cache_key_set", lambda key_set: None)

        with pytest.raises(RuntimeError, match="Failed to store rotated cache key"):
            cli_module._rotate_oauth_persistent_cache_key()

    def test_acquire_oauth_cache_lock_reports_non_retryable_error(self, monkeypatch, tmp_path: Path):
        """Lock helper should fail fast for non-retryable lock errors."""
        monkeypatch.setattr(cli_module, "_OAUTH_PERSISTENT_CACHE_LOCK_FILE", tmp_path / "oauth-cache-v1.lock")

        class FakeFcntl:
            LOCK_EX = 2
            LOCK_NB = 4
            LOCK_UN = 8

            @staticmethod
            def flock(fd: int, flags: int) -> None:
                del fd, flags
                raise OSError(5, "io error")

        original_import_module = cli_module.importlib.import_module

        def fake_import_module(module_name: str):
            if module_name == "fcntl":
                return FakeFcntl
            return original_import_module(module_name)

        monkeypatch.setattr(cli_module.importlib, "import_module", fake_import_module)
        lock_handle, lock_error = cli_module._acquire_oauth_cache_lock()
        assert lock_handle is None
        assert lock_error is not None
        assert "Unable to lock OAuth cache file" in lock_error

    def test_oauth_key_wrapper_helpers_return_expected_values(self, monkeypatch):
        """Compatibility wrappers should proxy key-material helpers correctly."""
        key_material = cli_module.OAuthCacheKeyMaterial(
            key_id="k_wrap",
            fernet_key=b"ZmFrZV9rZXlfZm9yX3Rlc3RpbmdfMTIzNDU2Nzg5MDE=",
            source="test",
        )

        monkeypatch.setattr(
            cli_module,
            "_resolve_oauth_cache_key_material",
            lambda create_if_missing: key_material if create_if_missing else None,
        )
        monkeypatch.setattr(cli_module, "_read_oauth_cache_key_material_from_keyring", lambda: key_material)

        assert cli_module._resolve_oauth_cache_encryption_key() == key_material.fernet_key
        assert cli_module._read_oauth_cache_key_from_keyring() == key_material.fernet_key

    def test_drop_oauth_refresh_token_persists_when_requested(self, monkeypatch):
        """Dropping refresh token with persistent flag should trigger cache persistence."""
        cli_module._clear_oauth_token_cache()
        cache_key = "ns\x1fhttps://auth.example.com/token\x1fclient\x1f\x1f"
        cli_module._OAUTH_TOKEN_CACHE[cache_key] = {
            "access_token": "access-token",
            "refresh_token": "refresh-token",
        }
        persisted: list[str] = []
        monkeypatch.setattr(cli_module, "_persist_oauth_cache_entry", lambda key: persisted.append(key))

        cli_module._drop_oauth_refresh_token(cache_key, persistent=True)

        assert cache_key in persisted
        assert cache_key in cli_module._OAUTH_TOKEN_CACHE
        assert "refresh_token" not in cli_module._OAUTH_TOKEN_CACHE[cache_key]
        cli_module._clear_oauth_token_cache()

    def test_coerce_token_endpoint_auth_method_rejects_invalid_values(self):
        """Token endpoint auth method helper should reject invalid shapes deterministically."""
        method, error = cli_module._coerce_token_endpoint_auth_method(42)
        assert method is None
        assert error is not None
        assert "private_key_jwt" in error

        method, error = cli_module._coerce_token_endpoint_auth_method("unsupported")
        assert method is None
        assert error is not None
        assert "private_key_jwt" in error

    def test_read_auth_file_value_validation_paths(self, monkeypatch, tmp_path: Path):
        """Auth file resolver should cover missing/read-error/empty/success paths."""
        missing_value, missing_error = cli_module._read_auth_file_value(
            str(tmp_path / "missing.pem"), "client_assertion_key_file"
        )
        assert missing_value is None
        assert missing_error is not None
        assert "does not exist" in missing_error

        key_file = tmp_path / "key.pem"
        key_file.write_text("dummy", encoding="utf-8")

        monkeypatch.setattr(Path, "read_text", lambda self, encoding="utf-8": (_ for _ in ()).throw(OSError("boom")))
        read_value, read_error = cli_module._read_auth_file_value(str(key_file), "client_assertion_key_file")
        assert read_value is None
        assert read_error == "auth.client_assertion_key_file could not be read."

    def test_read_auth_file_value_empty_and_success(self, tmp_path: Path):
        """Auth file resolver should reject empty files and accept non-empty content."""
        empty_file = tmp_path / "empty.pem"
        empty_file.write_text("   \n", encoding="utf-8")

        empty_value, empty_error = cli_module._read_auth_file_value(str(empty_file), "client_assertion_key_file")
        assert empty_value is None
        assert empty_error == "auth.client_assertion_key_file file is empty."

        valid_file = tmp_path / "valid.pem"
        valid_file.write_text("-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----", encoding="utf-8")
        valid_value, valid_error = cli_module._read_auth_file_value(str(valid_file), "client_assertion_key_file")
        assert valid_error is None
        assert valid_value is not None
        assert "BEGIN PRIVATE KEY" in valid_value

    def test_resolve_oauth_mtls_config_validation_matrix(self, tmp_path: Path):
        """mTLS helper should enforce pairing, path checks, and success output."""
        cert_file = tmp_path / "client.crt"
        key_file = tmp_path / "client.key"
        ca_file = tmp_path / "ca.pem"
        cert_file.write_text("cert", encoding="utf-8")
        key_file.write_text("key", encoding="utf-8")
        ca_file.write_text("ca", encoding="utf-8")

        config, error = cli_module._resolve_oauth_mtls_config({"mtls_cert_file": 7})
        assert config is None
        assert error is not None
        assert "mtls_cert_file" in error

        config, error = cli_module._resolve_oauth_mtls_config({"mtls_key_file": 7})
        assert config is None
        assert error is not None
        assert "mtls_key_file" in error

        config, error = cli_module._resolve_oauth_mtls_config({"mtls_ca_bundle_file": 7})
        assert config is None
        assert error is not None
        assert "mtls_ca_bundle_file" in error

        config, error = cli_module._resolve_oauth_mtls_config({"mtls_cert_file": str(cert_file)})
        assert config is None
        assert error == "auth.mtls_cert_file and auth.mtls_key_file must be provided together."

        config, error = cli_module._resolve_oauth_mtls_config(
            {"mtls_cert_file": str(tmp_path / "missing.crt"), "mtls_key_file": str(key_file)}
        )
        assert config is None
        assert error == "auth.mtls_cert_file path does not exist or is not a file."

        config, error = cli_module._resolve_oauth_mtls_config(
            {"mtls_cert_file": str(cert_file), "mtls_key_file": str(tmp_path / "missing.key")}
        )
        assert config is None
        assert error == "auth.mtls_key_file path does not exist or is not a file."

        config, error = cli_module._resolve_oauth_mtls_config(
            {
                "mtls_cert_file": str(cert_file),
                "mtls_key_file": str(key_file),
                "mtls_ca_bundle_file": str(tmp_path / "missing-ca.pem"),
            }
        )
        assert config is None
        assert error == "auth.mtls_ca_bundle_file path does not exist or is not a file."

        config, error = cli_module._resolve_oauth_mtls_config(
            {
                "mtls_cert_file": str(cert_file),
                "mtls_key_file": str(key_file),
                "mtls_ca_bundle_file": str(ca_file),
            }
        )
        assert error is None
        assert config is not None
        assert config.cert_file == str(cert_file)
        assert config.key_file == str(key_file)
        assert config.ca_bundle_file == str(ca_file)

    def test_resolve_oauth_private_key_jwt_signer_validation_matrix(self, monkeypatch, tmp_path: Path):
        """private_key_jwt signer resolver should enforce shape/env/file requirements."""
        key_file = tmp_path / "client-assertion.key"
        key_file.write_text(_generate_test_rsa_private_key_pem(), encoding="utf-8")

        signer, env_var, error = cli_module._resolve_oauth_private_key_jwt_signer({})
        assert signer is None
        assert env_var is None
        assert error is not None
        assert "is required" in error

        signer, env_var, error = cli_module._resolve_oauth_private_key_jwt_signer(
            {"client_assertion_key_env": "KEY_ENV", "client_assertion_key_file": str(key_file)}
        )
        assert signer is None
        assert env_var is None
        assert (
            error == "Provide exactly one of auth.client_assertion_key_env or auth.client_assertion_key_file or "
            "auth.client_assertion_kms_key_id."
        )

        signer, env_var, error = cli_module._resolve_oauth_private_key_jwt_signer(
            {
                "client_assertion_key_env": "KEY_ENV",
                "client_assertion_kms_key_id": "arn:aws:kms:eu-west-1:111122223333:key/abcd",
            }
        )
        assert signer is None
        assert env_var is None
        assert (
            error == "Provide exactly one of auth.client_assertion_key_env or auth.client_assertion_key_file or "
            "auth.client_assertion_kms_key_id."
        )

        signer, env_var, error = cli_module._resolve_oauth_private_key_jwt_signer({"client_assertion_key_env": 9})
        assert signer is None
        assert env_var is None
        assert error is not None
        assert "client_assertion_key_env" in error

        signer, env_var, error = cli_module._resolve_oauth_private_key_jwt_signer({"client_assertion_key_file": 9})
        assert signer is None
        assert env_var is None
        assert error is not None
        assert "client_assertion_key_file" in error

        signer, env_var, error = cli_module._resolve_oauth_private_key_jwt_signer(
            {"client_assertion_key_env": "KEY_ENV", "client_assertion_kid": 12}
        )
        assert signer is None
        assert env_var == "KEY_ENV"
        assert error is not None
        assert "client_assertion_kid" in error

        monkeypatch.delenv("MCP_ASSERTION_KEY", raising=False)
        signer, env_var, error = cli_module._resolve_oauth_private_key_jwt_signer(
            {"client_assertion_key_env": "MCP_ASSERTION_KEY"}
        )
        assert signer is None
        assert env_var == "MCP_ASSERTION_KEY"
        assert error is not None
        assert "MCP_ASSERTION_KEY" in error

        signer, env_var, error = cli_module._resolve_oauth_private_key_jwt_signer(
            {"client_assertion_key_file": str(tmp_path / "missing.key")}
        )
        assert signer is None
        assert env_var is None
        assert error == "auth.client_assertion_key_file path does not exist or is not a file."

        invalid_file = tmp_path / "invalid.key"
        invalid_file.write_text("not-a-private-key", encoding="utf-8")
        signer, env_var, error = cli_module._resolve_oauth_private_key_jwt_signer(
            {"client_assertion_key_file": str(invalid_file)}
        )
        assert signer is None
        assert env_var is None
        assert error == "Unable to parse auth client assertion private key."

        monkeypatch.setenv("MCP_ASSERTION_KEY", _generate_test_rsa_private_key_pem())
        signer, env_var, error = cli_module._resolve_oauth_private_key_jwt_signer(
            {"client_assertion_key_env": "MCP_ASSERTION_KEY", "client_assertion_kid": "kid-1"}
        )
        assert error is None
        assert env_var == "MCP_ASSERTION_KEY"
        assert signer is not None
        assert signer.kid == "kid-1"

        signer, env_var, error = cli_module._resolve_oauth_private_key_jwt_signer(
            {"client_assertion_key_file": str(key_file)}
        )
        assert error is None
        assert env_var is None
        assert signer is not None
        assert signer.signing_source == "pem"

        signer, env_var, error = cli_module._resolve_oauth_private_key_jwt_signer(
            {"client_assertion_kms_key_id": "arn:aws:kms:eu-west-1:111122223333:key/abcd"}
        )
        assert error is None
        assert env_var is None
        assert signer is not None
        assert signer.signing_source == "aws_kms"
        assert signer.kms_key_id == "arn:aws:kms:eu-west-1:111122223333:key/abcd"

        signer, env_var, error = cli_module._resolve_oauth_private_key_jwt_signer(
            {
                "client_assertion_kms_key_id": "arn:aws:kms:eu-west-1:111122223333:key/abcd",
                "client_assertion_kms_endpoint_url": "https://kms.eu-west-1.amazonaws.com",
            }
        )
        assert error is None
        assert env_var is None
        assert signer is not None
        assert signer.kms_endpoint_url == "https://kms.eu-west-1.amazonaws.com"

        signer, env_var, error = cli_module._resolve_oauth_private_key_jwt_signer(
            {
                "client_assertion_kms_key_id": "arn:aws:kms:eu-west-1:111122223333:key/abcd",
                "client_assertion_kms_endpoint_url": "ftp://kms.invalid",
            }
        )
        assert signer is None
        assert env_var is None
        assert error == "auth.client_assertion_kms_endpoint_url must be a valid http/https URL."

    def test_validate_private_key_jwt_signing_key_and_assertion(self):
        """Signing-key helper and assertion builder should validate and emit JWT claims."""
        invalid_error = cli_module._validate_private_key_jwt_signing_key("not-a-key")
        assert invalid_error == "Unable to parse auth client assertion private key."

        key_pem = _generate_test_rsa_private_key_pem()
        assert cli_module._validate_private_key_jwt_signing_key(key_pem) is None

        signer = cli_module.OAuthPrivateKeyJWTSigner(private_key_pem=key_pem, kid="kid-abc")
        assertion, assertion_error = cli_module._build_private_key_jwt_client_assertion(
            token_url="https://auth.example.com/token",
            client_id="client-xyz",
            signer=signer,
        )
        assert assertion_error is None
        assert assertion is not None

        header_segment, claims_segment, signature_segment = assertion.split(".")
        assert signature_segment
        padded_header = header_segment + "=" * ((4 - len(header_segment) % 4) % 4)
        padded_claims = claims_segment + "=" * ((4 - len(claims_segment) % 4) % 4)
        header_payload = json.loads(base64.urlsafe_b64decode(padded_header.encode("ascii")).decode("utf-8"))
        claims_payload = json.loads(base64.urlsafe_b64decode(padded_claims.encode("ascii")).decode("utf-8"))

        assert header_payload["alg"] == "RS256"
        assert header_payload["kid"] == "kid-abc"
        assert claims_payload["iss"] == "client-xyz"
        assert claims_payload["sub"] == "client-xyz"
        assert claims_payload["aud"] == "https://auth.example.com/token"
        assert claims_payload["exp"] > claims_payload["iat"]
        assert isinstance(claims_payload["jti"], str) and claims_payload["jti"]

    def test_sign_private_key_jwt_with_aws_kms_paths(self, monkeypatch):
        """AWS KMS signing helper should cover missing-key, import, failure, and success paths."""
        signer = cli_module.OAuthPrivateKeyJWTSigner(signing_source="aws_kms", kms_key_id=None)
        signature, signature_error = cli_module._sign_private_key_jwt_with_aws_kms(b"payload", signer)
        assert signature is None
        assert signature_error == "auth.client_assertion_kms_key_id is required for AWS KMS signing."

        signer = cli_module.OAuthPrivateKeyJWTSigner(
            signing_source="aws_kms",
            kms_key_id="arn:aws:kms:eu-west-1:111122223333:key/abcd",
        )

        monkeypatch.setattr(
            cli_module.importlib, "import_module", lambda name: (_ for _ in ()).throw(ModuleNotFoundError())
        )
        signature, signature_error = cli_module._sign_private_key_jwt_with_aws_kms(b"payload", signer)
        assert signature is None
        assert signature_error is not None
        assert "boto3 is required" in signature_error

        class FakeKMSClient:
            @staticmethod
            def sign(**kwargs: object) -> dict[str, object]:
                del kwargs
                return {"Signature": b"signed-by-kms"}

        class FakeBoto3:
            @staticmethod
            def client(service_name: str, **kwargs: object) -> FakeKMSClient:
                assert service_name == "kms"
                assert kwargs["region_name"] == "eu-west-1"
                return FakeKMSClient()

        monkeypatch.setattr(cli_module.importlib, "import_module", lambda name: FakeBoto3())
        signer = cli_module.OAuthPrivateKeyJWTSigner(
            signing_source="aws_kms",
            kms_key_id="arn:aws:kms:eu-west-1:111122223333:key/abcd",
            kms_region="eu-west-1",
        )
        signature, signature_error = cli_module._sign_private_key_jwt_with_aws_kms(b"payload", signer)
        assert signature_error is None
        assert signature == b"signed-by-kms"

    def test_build_private_key_jwt_client_assertion_with_aws_kms_signer(self, monkeypatch):
        """JWT assertion builder should use AWS KMS helper when signer source is aws_kms."""
        signer = cli_module.OAuthPrivateKeyJWTSigner(
            signing_source="aws_kms",
            kms_key_id="arn:aws:kms:eu-west-1:111122223333:key/abcd",
            kid="kms-key",
        )

        monkeypatch.setattr(
            cli_module,
            "_sign_private_key_jwt_with_aws_kms",
            lambda signing_input, signer: (b"kms-signature", None),
        )
        assertion, assertion_error = cli_module._build_private_key_jwt_client_assertion(
            token_url="https://auth.example.com/token",
            client_id="client-kms",
            signer=signer,
        )

        assert assertion_error is None
        assert assertion is not None
        header_segment, claims_segment, signature_segment = assertion.split(".")
        assert signature_segment
        padded_header = header_segment + "=" * ((4 - len(header_segment) % 4) % 4)
        padded_claims = claims_segment + "=" * ((4 - len(claims_segment) % 4) % 4)
        header_payload = json.loads(base64.urlsafe_b64decode(padded_header.encode("ascii")).decode("utf-8"))
        claims_payload = json.loads(base64.urlsafe_b64decode(padded_claims.encode("ascii")).decode("utf-8"))
        assert header_payload["kid"] == "kms-key"
        assert claims_payload["iss"] == "client-kms"

    def test_request_oauth_form_payload_private_key_jwt_and_mtls_paths(self, monkeypatch):
        """OAuth form helper should handle private_key_jwt requirements and mTLS kwargs."""
        payload, request_error, http_status = cli_module._request_oauth_form_payload(
            endpoint_url="https://auth.example.com/token",
            request_data={"grant_type": "client_credentials"},
            timeout_seconds=5,
            endpoint_name="Token endpoint",
            client_id=None,
            token_endpoint_auth_method="private_key_jwt",
        )
        assert payload is None
        assert request_error == "Token endpoint private_key_jwt requires client_id."
        assert http_status is None

        payload, request_error, http_status = cli_module._request_oauth_form_payload(
            endpoint_url="https://auth.example.com/token",
            request_data={"grant_type": "client_credentials"},
            timeout_seconds=5,
            endpoint_name="Token endpoint",
            client_id="client-a",
            token_endpoint_auth_method="private_key_jwt",
        )
        assert payload is None
        assert request_error == "Token endpoint private_key_jwt requires client assertion signing key."
        assert http_status is None

        signer = cli_module.OAuthPrivateKeyJWTSigner(private_key_pem=_generate_test_rsa_private_key_pem(), kid=None)
        monkeypatch.setattr(
            cli_module,
            "_build_private_key_jwt_client_assertion",
            lambda token_url, client_id, signer: (None, "assertion-failed"),
        )
        payload, request_error, http_status = cli_module._request_oauth_form_payload(
            endpoint_url="https://auth.example.com/token",
            request_data={"grant_type": "client_credentials", "client_secret": "secret-a"},
            timeout_seconds=5,
            endpoint_name="Token endpoint",
            client_id="client-a",
            token_endpoint_auth_method="private_key_jwt",
            client_assertion_signer=signer,
        )
        assert payload is None
        assert request_error == "assertion-failed"
        assert http_status is None

        captured: dict[str, object] = {}

        class FakeResponse:
            status_code = 200
            text = ""

            @staticmethod
            def json() -> dict[str, object]:
                return {"access_token": "token-ok"}

        def fake_post(
            url: str,
            data: dict[str, str],
            headers: dict[str, str],
            timeout: int,
            **kwargs: object,
        ) -> FakeResponse:
            captured["url"] = url
            captured["data"] = data
            captured["headers"] = headers
            captured["timeout"] = timeout
            captured["kwargs"] = kwargs
            return FakeResponse()

        monkeypatch.setattr(
            cli_module,
            "_build_private_key_jwt_client_assertion",
            lambda token_url, client_id, signer: ("jwt-assertion", None),
        )
        monkeypatch.setattr(cli_module.httpx, "post", fake_post)

        mtls_config = cli_module.OAuthMTLSConfig(
            cert_file="/tmp/client.crt",
            key_file="/tmp/client.key",
            ca_bundle_file="/tmp/ca.pem",
        )
        payload, request_error, http_status = cli_module._request_oauth_form_payload(
            endpoint_url="https://auth.example.com/token",
            request_data={"grant_type": "client_credentials", "client_id": "client-a", "client_secret": "secret-a"},
            timeout_seconds=6,
            endpoint_name="Token endpoint",
            client_id="client-a",
            token_endpoint_auth_method="private_key_jwt",
            client_assertion_signer=signer,
            mtls_config=mtls_config,
        )

        assert request_error is None
        assert http_status == 200
        assert payload == {"access_token": "token-ok"}
        request_data = captured["data"]
        assert isinstance(request_data, dict)
        assert request_data["client_assertion_type"] == cli_module._OAUTH_CLIENT_ASSERTION_TYPE
        assert request_data["client_assertion"] == "jwt-assertion"
        assert "client_secret" not in request_data
        kwargs = captured["kwargs"]
        assert isinstance(kwargs, dict)
        assert kwargs["cert"] == ("/tmp/client.crt", "/tmp/client.key")
        assert kwargs["verify"] == "/tmp/ca.pem"

    @pytest.mark.parametrize(
        ("with_signer", "with_mtls"),
        [
            (True, False),
            (False, True),
            (True, True),
        ],
    )
    def test_resolve_oauth_client_credentials_token_passes_signer_mtls_matrix(
        self, monkeypatch, with_signer: bool, with_mtls: bool
    ):
        """Client-credentials resolver should forward signer/mTLS combinations to request helper."""
        cli_module._clear_oauth_token_cache()
        calls: list[dict[str, object]] = []

        def fake_request(**kwargs: object) -> tuple[str | None, float | None, str | None, int | None, str | None]:
            calls.append(kwargs)
            return "access-token", 120.0, None, 200, "Bearer"

        monkeypatch.setattr(cli_module, "_request_oauth_client_credentials_token", fake_request)
        monkeypatch.setattr(cli_module, "_hydrate_oauth_cache_from_persistent", lambda cache_key, cache_settings: None)

        signer = (
            cli_module.OAuthPrivateKeyJWTSigner(private_key_pem=_generate_test_rsa_private_key_pem(), kid=None)
            if with_signer
            else None
        )
        mtls = (
            cli_module.OAuthMTLSConfig(cert_file="/tmp/cert.pem", key_file="/tmp/key.pem", ca_bundle_file=None)
            if with_mtls
            else None
        )
        method = "private_key_jwt" if with_signer else "client_secret_post"
        client_secret = None if with_signer else "secret-a"

        token, token_type, finding = cli_module._resolve_oauth_client_credentials_token(
            server_name="oauth-server",
            transport="sse",
            auth_type="oauth_client_credentials",
            token_url="https://auth.example.com/token",
            client_id="client-a",
            client_secret=client_secret,
            scope=None,
            audience=None,
            token_endpoint_auth_method=method,
            client_assertion_signer=signer,
            mtls_config=mtls,
            timeout_seconds=6,
            env_var="MCP_OAUTH_CLIENT_ID",
            cache_settings=cli_module.OAuthCacheSettings(persistent=False, namespace="test-ns"),
        )

        assert finding is None
        assert token == "access-token"
        assert token_type == "Bearer"
        assert len(calls) == 1
        assert ("client_assertion_signer" in calls[0]) is with_signer
        assert ("mtls_config" in calls[0]) is with_mtls

    @pytest.mark.parametrize(
        ("with_signer", "with_mtls"),
        [
            (True, False),
            (False, True),
            (True, True),
        ],
    )
    def test_resolve_oauth_device_code_refresh_paths_with_signer_mtls_matrix(
        self,
        monkeypatch,
        with_signer: bool,
        with_mtls: bool,
    ):
        """Device-code refresh path should forward signer/mTLS combinations to refresh helper."""
        cli_module._clear_oauth_token_cache()
        calls: list[dict[str, object]] = []

        monkeypatch.setattr(cli_module, "_hydrate_oauth_cache_from_persistent", lambda cache_key, cache_settings: None)
        monkeypatch.setattr(cli_module, "_get_cached_oauth_token", lambda cache_key: None)
        monkeypatch.setattr(cli_module, "_get_cached_oauth_token_type", lambda cache_key: None)
        monkeypatch.setattr(cli_module, "_get_cached_oauth_refresh_token", lambda cache_key: "refresh-1")

        def fake_refresh(
            **kwargs: object,
        ) -> tuple[str | None, float | None, str | None, str | None, int | None, str | None]:
            calls.append(kwargs)
            return "refreshed-token", 90.0, "refresh-2", None, 200, "DPoP"

        monkeypatch.setattr(cli_module, "_request_oauth_refresh_token", fake_refresh)

        signer = (
            cli_module.OAuthPrivateKeyJWTSigner(private_key_pem=_generate_test_rsa_private_key_pem(), kid=None)
            if with_signer
            else None
        )
        mtls = (
            cli_module.OAuthMTLSConfig(cert_file="/tmp/cert.pem", key_file="/tmp/key.pem", ca_bundle_file=None)
            if with_mtls
            else None
        )
        method = "private_key_jwt" if with_signer else "client_secret_post"
        client_secret = None if with_signer else "secret-a"

        token, token_type, finding = cli_module._resolve_oauth_device_code_token(
            server_name="device-server",
            transport="sse",
            auth_type="oauth_device_code",
            device_authorization_url="https://auth.example.com/device",
            token_url="https://auth.example.com/token",
            client_id="client-a",
            client_secret=client_secret,
            scope=None,
            audience=None,
            token_endpoint_auth_method=method,
            client_assertion_signer=signer,
            mtls_config=mtls,
            timeout_seconds=7,
            is_interactive_tty=True,
            env_var="MCP_DEVICE_CLIENT_ID",
            cache_settings=cli_module.OAuthCacheSettings(persistent=False, namespace="test-ns"),
        )

        assert finding is None
        assert token == "refreshed-token"
        assert token_type == "DPoP"
        assert len(calls) == 1
        assert ("client_assertion_signer" in calls[0]) is with_signer
        assert ("mtls_config" in calls[0]) is with_mtls

    @pytest.mark.parametrize(
        ("with_signer", "with_mtls"),
        [
            (True, False),
            (False, True),
            (True, True),
        ],
    )
    def test_resolve_oauth_device_code_poll_paths_with_signer_mtls_matrix(
        self,
        monkeypatch,
        with_signer: bool,
        with_mtls: bool,
    ):
        """Device-code primary poll path should forward signer/mTLS combinations."""
        cli_module._clear_oauth_token_cache()
        poll_calls: list[dict[str, object]] = []

        monkeypatch.setattr(cli_module, "_hydrate_oauth_cache_from_persistent", lambda cache_key, cache_settings: None)
        monkeypatch.setattr(cli_module, "_get_cached_oauth_token", lambda cache_key: None)
        monkeypatch.setattr(cli_module, "_get_cached_oauth_token_type", lambda cache_key: None)
        monkeypatch.setattr(cli_module, "_get_cached_oauth_refresh_token", lambda cache_key: None)
        monkeypatch.setattr(
            cli_module,
            "_request_oauth_device_authorization",
            lambda **kwargs: (
                {"device_code": "device-1", "verification_uri": "https://auth.example.com/verify"},
                None,
                200,
            ),
        )
        monkeypatch.setattr(
            cli_module,
            "_emit_oauth_device_code_instructions",
            lambda server_name, verification_uri, verification_uri_complete, user_code: None,
        )

        def fake_poll(
            **kwargs: object,
        ) -> tuple[str | None, float | None, str | None, str | None, int | None, str | None]:
            poll_calls.append(kwargs)
            return "polled-token", 120.0, "refresh-2", None, 200, "Bearer"

        monkeypatch.setattr(cli_module, "_poll_oauth_device_code_token", fake_poll)

        signer = (
            cli_module.OAuthPrivateKeyJWTSigner(private_key_pem=_generate_test_rsa_private_key_pem(), kid=None)
            if with_signer
            else None
        )
        mtls = (
            cli_module.OAuthMTLSConfig(cert_file="/tmp/cert.pem", key_file="/tmp/key.pem", ca_bundle_file=None)
            if with_mtls
            else None
        )
        method = "private_key_jwt" if with_signer else "client_secret_post"
        client_secret = None if with_signer else "secret-a"

        token, token_type, finding = cli_module._resolve_oauth_device_code_token(
            server_name="device-server",
            transport="sse",
            auth_type="oauth_device_code",
            device_authorization_url="https://auth.example.com/device",
            token_url="https://auth.example.com/token",
            client_id="client-a",
            client_secret=client_secret,
            scope=None,
            audience=None,
            token_endpoint_auth_method=method,
            client_assertion_signer=signer,
            mtls_config=mtls,
            timeout_seconds=7,
            is_interactive_tty=True,
            env_var="MCP_DEVICE_CLIENT_ID",
            cache_settings=cli_module.OAuthCacheSettings(persistent=False, namespace="test-ns"),
        )

        assert finding is None
        assert token == "polled-token"
        assert token_type == "Bearer"
        assert len(poll_calls) == 1
        assert ("client_assertion_signer" in poll_calls[0]) is with_signer
        assert ("mtls_config" in poll_calls[0]) is with_mtls

    @pytest.mark.parametrize(
        ("with_signer", "with_mtls"),
        [
            (True, False),
            (False, True),
            (True, True),
        ],
    )
    def test_poll_oauth_device_code_token_forwards_signer_mtls_matrix(
        self, monkeypatch, with_signer: bool, with_mtls: bool
    ):
        """Device-code poll helper should forward signer/mTLS combinations to form request helper."""
        captured: list[dict[str, object]] = []

        def fake_request_form_payload(**kwargs: object) -> tuple[dict[str, object] | None, str | None, int | None]:
            captured.append(kwargs)
            return {"access_token": "token-1", "expires_in": 60}, None, 200

        monkeypatch.setattr(cli_module, "_request_oauth_form_payload", fake_request_form_payload)

        signer = (
            cli_module.OAuthPrivateKeyJWTSigner(private_key_pem=_generate_test_rsa_private_key_pem(), kid=None)
            if with_signer
            else None
        )
        mtls = (
            cli_module.OAuthMTLSConfig(cert_file="/tmp/cert.pem", key_file="/tmp/key.pem", ca_bundle_file=None)
            if with_mtls
            else None
        )
        method = "private_key_jwt" if with_signer else "client_secret_post"
        client_secret = None if with_signer else "secret-a"

        token, expires_in, refresh_token, token_error, http_status, token_type = (
            cli_module._poll_oauth_device_code_token(
                token_url="https://auth.example.com/token",
                device_code="device-code",
                client_id="client-a",
                client_secret=client_secret,
                token_endpoint_auth_method=method,
                timeout_seconds=5,
                poll_interval_seconds=1,
                device_expires_in=30,
                client_assertion_signer=signer,
                mtls_config=mtls,
            )
        )

        assert token_error is None
        assert http_status == 200
        assert token == "token-1"
        assert expires_in == 60.0
        assert refresh_token is None
        assert token_type is None
        assert len(captured) == 1
        assert ("client_assertion_signer" in captured[0]) is with_signer
        assert ("mtls_config" in captured[0]) is with_mtls

    def test_build_connector_config_oauth_client_credentials_private_key_jwt_with_mtls(
        self, monkeypatch, tmp_path: Path
    ):
        """Config auth should support private_key_jwt and mTLS for client-credentials flow."""
        cli_module._clear_oauth_token_cache()
        monkeypatch.setenv("MCP_OAUTH_CLIENT_ID", "client-jwt")
        monkeypatch.setenv("MCP_ASSERTION_KEY", _generate_test_rsa_private_key_pem())

        cert_file = tmp_path / "client.crt"
        key_file = tmp_path / "client.key"
        ca_file = tmp_path / "ca.pem"
        cert_file.write_text("cert", encoding="utf-8")
        key_file.write_text("key", encoding="utf-8")
        ca_file.write_text("ca", encoding="utf-8")

        def fake_request(
            *,
            token_url: str,
            client_id: str,
            client_secret: str | None,
            scope: str | None,
            audience: str | None,
            token_endpoint_auth_method: str,
            timeout_seconds: int,
            client_assertion_signer: cli_module.OAuthPrivateKeyJWTSigner | None,
            mtls_config: cli_module.OAuthMTLSConfig | None = None,
        ) -> tuple[str | None, float | None, str | None, int | None]:
            del scope, audience, timeout_seconds
            assert token_url == "https://auth.example.com/token"
            assert client_id == "client-jwt"
            assert client_secret is None
            assert token_endpoint_auth_method == "private_key_jwt"
            assert client_assertion_signer is not None
            assert mtls_config is not None
            assert mtls_config.cert_file == str(cert_file)
            assert mtls_config.key_file == str(key_file)
            assert mtls_config.ca_bundle_file == str(ca_file)
            return "jwt-token", 300.0, None, 200

        monkeypatch.setattr(cli_module, "_request_oauth_client_credentials_token", fake_request)

        connector_config, finding = _build_connector_config_from_config_entry(
            server_name="oauth_pkjwt_server",
            raw_server_config={
                "transport": "streamable-http",
                "url": "https://example.com/mcp",
                "auth": {
                    "type": "oauth_client_credentials",
                    "token_url": "https://auth.example.com/token",
                    "client_id_env": "MCP_OAUTH_CLIENT_ID",
                    "token_endpoint_auth_method": "private_key_jwt",
                    "client_assertion_key_env": "MCP_ASSERTION_KEY",
                    "client_assertion_kid": "kid-123",
                    "mtls_cert_file": str(cert_file),
                    "mtls_key_file": str(key_file),
                    "mtls_ca_bundle_file": str(ca_file),
                },
            },
            timeout=9,
        )

        assert finding is None
        assert connector_config is not None
        assert connector_config["headers"]["Authorization"] == "Bearer jwt-token"

    def test_build_connector_config_oauth_device_code_private_key_jwt_with_mtls(self, monkeypatch, tmp_path: Path):
        """Config auth should support private_key_jwt and mTLS for device-code flow."""
        cli_module._clear_oauth_token_cache()
        monkeypatch.setenv("MCP_DEVICE_CLIENT_ID", "device-jwt")
        monkeypatch.setenv("MCP_ASSERTION_KEY", _generate_test_rsa_private_key_pem())
        monkeypatch.setattr(cli_module, "_is_interactive_tty", lambda: True)

        cert_file = tmp_path / "client.crt"
        key_file = tmp_path / "client.key"
        cert_file.write_text("cert", encoding="utf-8")
        key_file.write_text("key", encoding="utf-8")

        monkeypatch.setattr(
            cli_module,
            "_request_oauth_device_authorization",
            lambda **kwargs: (
                {"device_code": "device-code", "verification_uri": "https://auth.example.com/verify"},
                None,
                200,
            ),
        )
        monkeypatch.setattr(
            cli_module,
            "_emit_oauth_device_code_instructions",
            lambda server_name, verification_uri, verification_uri_complete, user_code: None,
        )

        def fake_poll(
            *,
            token_url: str,
            device_code: str,
            client_id: str,
            client_secret: str | None,
            token_endpoint_auth_method: str,
            timeout_seconds: int,
            poll_interval_seconds: int,
            device_expires_in: float | None,
            client_assertion_signer: cli_module.OAuthPrivateKeyJWTSigner | None,
            mtls_config: cli_module.OAuthMTLSConfig | None,
        ) -> tuple[str | None, float | None, str | None, str | None, int | None, str | None]:
            del timeout_seconds, poll_interval_seconds, device_expires_in
            assert token_url == "https://auth.example.com/token"
            assert device_code == "device-code"
            assert client_id == "device-jwt"
            assert client_secret is None
            assert token_endpoint_auth_method == "private_key_jwt"
            assert client_assertion_signer is not None
            assert mtls_config is not None
            assert mtls_config.cert_file == str(cert_file)
            assert mtls_config.key_file == str(key_file)
            return "device-token", 120.0, "refresh-1", None, 200, "Bearer"

        monkeypatch.setattr(cli_module, "_poll_oauth_device_code_token", fake_poll)

        connector_config, finding = _build_connector_config_from_config_entry(
            server_name="oauth_device_pkjwt_server",
            raw_server_config={
                "transport": "sse",
                "url": "https://example.com/sse",
                "auth": {
                    "type": "oauth_device_code",
                    "device_authorization_url": "https://auth.example.com/device",
                    "token_url": "https://auth.example.com/token",
                    "client_id_env": "MCP_DEVICE_CLIENT_ID",
                    "token_endpoint_auth_method": "private_key_jwt",
                    "client_assertion_key_env": "MCP_ASSERTION_KEY",
                    "mtls_cert_file": str(cert_file),
                    "mtls_key_file": str(key_file),
                },
            },
            timeout=9,
        )

        assert finding is None
        assert connector_config is not None
        assert connector_config["headers"]["Authorization"] == "Bearer device-token"

    def test_build_connector_config_oauth_private_key_jwt_with_aws_kms(self, monkeypatch):
        """Config auth should support private_key_jwt signer source from AWS KMS."""
        cli_module._clear_oauth_token_cache()
        monkeypatch.setenv("MCP_OAUTH_CLIENT_ID", "client-kms")

        def fake_request(
            *,
            token_url: str,
            client_id: str,
            client_secret: str | None,
            scope: str | None,
            audience: str | None,
            token_endpoint_auth_method: str,
            timeout_seconds: int,
            client_assertion_signer: cli_module.OAuthPrivateKeyJWTSigner | None,
            mtls_config: cli_module.OAuthMTLSConfig | None = None,
        ) -> tuple[str | None, float | None, str | None, int | None]:
            del scope, audience, timeout_seconds
            assert token_url == "https://auth.example.com/token"
            assert client_id == "client-kms"
            assert client_secret is None
            assert token_endpoint_auth_method == "private_key_jwt"
            assert client_assertion_signer is not None
            assert client_assertion_signer.signing_source == "aws_kms"
            assert client_assertion_signer.kms_key_id == "arn:aws:kms:eu-west-1:111122223333:key/abcd"
            assert client_assertion_signer.kms_region == "eu-west-1"
            assert client_assertion_signer.kms_endpoint_url == "https://kms.eu-west-1.amazonaws.com"
            assert mtls_config is None
            return "kms-token", 300.0, None, 200

        monkeypatch.setattr(cli_module, "_request_oauth_client_credentials_token", fake_request)

        connector_config, finding = _build_connector_config_from_config_entry(
            server_name="oauth_kms_server",
            raw_server_config={
                "transport": "streamable-http",
                "url": "https://example.com/mcp",
                "auth": {
                    "type": "oauth_client_credentials",
                    "token_url": "https://auth.example.com/token",
                    "client_id_env": "MCP_OAUTH_CLIENT_ID",
                    "token_endpoint_auth_method": "private_key_jwt",
                    "client_assertion_kms_key_id": "arn:aws:kms:eu-west-1:111122223333:key/abcd",
                    "client_assertion_kms_region": "eu-west-1",
                    "client_assertion_kms_endpoint_url": "https://kms.eu-west-1.amazonaws.com",
                },
            },
            timeout=9,
        )

        assert finding is None
        assert connector_config is not None
        assert connector_config["headers"]["Authorization"] == "Bearer kms-token"

    def test_build_connector_config_network_transport_top_level_mtls(self, tmp_path: Path):
        """Network transport entry should pass validated top-level mTLS fields into connector config."""
        cert_file = tmp_path / "transport-client.crt"
        key_file = tmp_path / "transport-client.key"
        ca_file = tmp_path / "transport-ca.pem"
        cert_file.write_text("cert", encoding="utf-8")
        key_file.write_text("key", encoding="utf-8")
        ca_file.write_text("ca", encoding="utf-8")

        connector_config, finding = _build_connector_config_from_config_entry(
            server_name="sse_mtls_server",
            raw_server_config={
                "transport": "sse",
                "url": "https://example.com/sse",
                "headers": {"X-Trace": "abc"},
                "mtls_cert_file": str(cert_file),
                "mtls_key_file": str(key_file),
                "mtls_ca_bundle_file": str(ca_file),
            },
            timeout=11,
        )

        assert finding is None
        assert connector_config is not None
        assert connector_config["mtls_cert_file"] == str(cert_file)
        assert connector_config["mtls_key_file"] == str(key_file)
        assert connector_config["mtls_ca_bundle_file"] == str(ca_file)
        assert connector_config["headers"]["X-Trace"] == "abc"

    def test_build_connector_config_network_transport_invalid_top_level_mtls(self):
        """Invalid top-level mTLS fields should produce invalid_config_entry findings."""
        connector_config, finding = _build_connector_config_from_config_entry(
            server_name="sse_bad_mtls_server",
            raw_server_config={
                "transport": "sse",
                "url": "https://example.com/sse",
                "mtls_cert_file": "/tmp/client.crt",
            },
            timeout=11,
        )

        assert connector_config is None
        assert finding is not None
        assert finding.category == "invalid_config_entry"
        assert "mtls_cert_file and mtls_key_file must be provided together." in finding.description

    def test_build_connector_config_oauth_private_key_jwt_and_mtls_config_errors(self, monkeypatch):
        """Config auth should emit auth_config_error for private_key_jwt and mTLS validation issues."""
        monkeypatch.setenv("MCP_OAUTH_CLIENT_ID", "client-jwt")
        monkeypatch.setenv("MCP_OAUTH_CLIENT_SECRET", "secret-jwt")
        monkeypatch.setenv("MCP_DEVICE_CLIENT_ID", "device-jwt")

        connector_config, finding = _build_connector_config_from_config_entry(
            server_name="oauth_client_secret_env_error",
            raw_server_config={
                "transport": "sse",
                "url": "https://example.com/sse",
                "auth": {
                    "type": "oauth_client_credentials",
                    "token_url": "https://auth.example.com/token",
                    "client_id_env": "MCP_OAUTH_CLIENT_ID",
                },
            },
            timeout=7,
        )
        assert connector_config is None
        assert finding is not None
        assert finding.category == "auth_config_error"
        assert "client_secret_env" in finding.evidence

        connector_config, finding = _build_connector_config_from_config_entry(
            server_name="oauth_client_error",
            raw_server_config={
                "transport": "sse",
                "url": "https://example.com/sse",
                "auth": {
                    "type": "oauth_client_credentials",
                    "token_url": "https://auth.example.com/token",
                    "client_id_env": "MCP_OAUTH_CLIENT_ID",
                    "token_endpoint_auth_method": "private_key_jwt",
                },
            },
            timeout=7,
        )
        assert connector_config is None
        assert finding is not None
        assert finding.category == "auth_config_error"
        assert "client_assertion_key_env" in finding.evidence

        connector_config, finding = _build_connector_config_from_config_entry(
            server_name="oauth_client_kms_endpoint_error",
            raw_server_config={
                "transport": "sse",
                "url": "https://example.com/sse",
                "auth": {
                    "type": "oauth_client_credentials",
                    "token_url": "https://auth.example.com/token",
                    "client_id_env": "MCP_OAUTH_CLIENT_ID",
                    "token_endpoint_auth_method": "private_key_jwt",
                    "client_assertion_kms_key_id": "arn:aws:kms:eu-west-1:111122223333:key/abcd",
                    "client_assertion_kms_endpoint_url": "ftp://kms.invalid",
                },
            },
            timeout=7,
        )
        assert connector_config is None
        assert finding is not None
        assert finding.category == "auth_config_error"
        assert "client_assertion_kms_endpoint_url" in finding.evidence

        connector_config, finding = _build_connector_config_from_config_entry(
            server_name="oauth_client_mtls_error",
            raw_server_config={
                "transport": "sse",
                "url": "https://example.com/sse",
                "auth": {
                    "type": "oauth_client_credentials",
                    "token_url": "https://auth.example.com/token",
                    "client_id_env": "MCP_OAUTH_CLIENT_ID",
                    "client_secret_env": "MCP_OAUTH_CLIENT_SECRET",
                    "mtls_cert_file": "/tmp/client.crt",
                },
            },
            timeout=7,
        )
        assert connector_config is None
        assert finding is not None
        assert finding.category == "auth_config_error"
        assert "mtls_cert_file and auth.mtls_key_file" in finding.evidence

        connector_config, finding = _build_connector_config_from_config_entry(
            server_name="oauth_device_error",
            raw_server_config={
                "transport": "sse",
                "url": "https://example.com/sse",
                "auth": {
                    "type": "oauth_device_code",
                    "device_authorization_url": "https://auth.example.com/device",
                    "token_url": "https://auth.example.com/token",
                    "client_id_env": "MCP_DEVICE_CLIENT_ID",
                    "token_endpoint_auth_method": "private_key_jwt",
                },
            },
            timeout=7,
        )
        assert connector_config is None
        assert finding is not None
        assert finding.category == "auth_config_error"
        assert "client_assertion_key_env" in finding.evidence

        connector_config, finding = _build_connector_config_from_config_entry(
            server_name="oauth_device_mtls_error",
            raw_server_config={
                "transport": "sse",
                "url": "https://example.com/sse",
                "auth": {
                    "type": "oauth_device_code",
                    "device_authorization_url": "https://auth.example.com/device",
                    "token_url": "https://auth.example.com/token",
                    "client_id_env": "MCP_DEVICE_CLIENT_ID",
                    "mtls_cert_file": "/tmp/client.crt",
                },
            },
            timeout=7,
        )
        assert connector_config is None
        assert finding is not None
        assert finding.category == "auth_config_error"
        assert "mtls_cert_file and auth.mtls_key_file" in finding.evidence
