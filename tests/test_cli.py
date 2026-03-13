"""CLI tests for server/config/baseline/compare commands."""

import asyncio
import base64
import json
import shlex
import socket
import sys
import threading
import time
from pathlib import Path
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
