"""CLI tests for server/config/baseline/compare commands."""

import asyncio
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
        monkeypatch.setattr(cli_module, "_read_oauth_cache_key_material_from_keyring", lambda: None)
        monkeypatch.setattr(cli_module, "_write_oauth_cache_key_material_to_keyring", lambda key_material: False)

        runner = CliRunner()
        result = runner.invoke(main, ["cache", "rotate"])

        assert result.exit_code == 0
        assert "source=file" in result.output
        key_payload = json.loads((tmp_path / "cache.key").read_text(encoding="utf-8"))
        assert "key_id" in key_payload
        assert "fernet_key" in key_payload

    def test_cache_rotate_command_success_with_keyring(self, monkeypatch, tmp_path: Path):
        """Cache rotate should report keyring source when keyring write succeeds."""
        monkeypatch.setattr(cli_module, "_OAUTH_PERSISTENT_CACHE_FILE", tmp_path / "oauth-cache-v1.json.enc")
        monkeypatch.setattr(cli_module, "_OAUTH_PERSISTENT_CACHE_LOCK_FILE", tmp_path / "oauth-cache-v1.lock")
        monkeypatch.setattr(cli_module, "_OAUTH_PERSISTENT_KEY_FILE", tmp_path / "cache.key")
        monkeypatch.setattr(cli_module, "_read_oauth_cache_key_material_from_keyring", lambda: None)

        wrote: list[str] = []

        def fake_write_to_keyring(key_material: cli_module.OAuthCacheKeyMaterial) -> bool:
            wrote.append(key_material.key_id)
            return True

        monkeypatch.setattr(cli_module, "_write_oauth_cache_key_material_to_keyring", fake_write_to_keyring)
        monkeypatch.setattr(cli_module, "_write_oauth_cache_key_material_to_file", lambda key_material: False)

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

    def test_resolve_oauth_cache_key_material_prefers_keyring(self, monkeypatch):
        """Key material resolver should prefer keyring over fallback key file."""
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

        def fake_keyring() -> cli_module.OAuthCacheKeyMaterial | None:
            keyring_calls["value"] += 1
            return keyring_material

        def fake_file() -> cli_module.OAuthCacheKeyMaterial | None:
            file_calls["value"] += 1
            return file_material

        monkeypatch.setattr(cli_module, "_read_oauth_cache_key_material_from_keyring", fake_keyring)
        monkeypatch.setattr(cli_module, "_read_oauth_cache_key_material_from_file", fake_file)

        resolved_material = cli_module._resolve_oauth_cache_key_material(create_if_missing=False)

        assert resolved_material == keyring_material
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
        monkeypatch.setattr(cli_module, "_read_oauth_cache_key_material_from_keyring", lambda: None)

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
        monkeypatch.setattr(cli_module, "_resolve_oauth_cache_key_material", lambda create_if_missing: None)

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
        monkeypatch.setattr(cli_module, "_store_oauth_cache_key_material", lambda key_material: None)

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
