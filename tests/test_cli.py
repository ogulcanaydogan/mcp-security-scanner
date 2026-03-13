"""CLI tests for server/config/baseline/compare commands."""

import json
import shlex
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

import mcp_security_scanner.cli as cli_module
from mcp_security_scanner.analyzers.base import Finding, Severity
from mcp_security_scanner.cli import (
    _build_connector_config_from_config_entry,
    _build_target_connector_config,
    _compose_stdio_command,
    _derive_server_name,
    _extract_config_server_entries,
    _filter_findings,
    _mutation_to_finding,
    _parse_severity_threshold,
    _safe_json_dump,
    main,
)
from mcp_security_scanner.discovery import ServerCapabilities
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

    def test_server_url_target_uses_sse_connector(self, monkeypatch):
        """Server command should route HTTP(S) target to SSE connector config."""
        captured: dict[str, object] = {}

        async def fake_discover(server_name: str, connector_config: dict[str, object]) -> ServerCapabilities:
            captured["server_name"] = server_name
            captured["connector_config"] = connector_config
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
        connector_config = captured["connector_config"]
        assert isinstance(connector_config, dict)
        assert connector_config["type"] == "sse"
        assert connector_config["url"] == "https://example.com/sse"

    def test_baseline_url_target_uses_sse_connector(self, monkeypatch, tmp_path: Path):
        """Baseline command should use SSE connector when target is URL."""
        captured: dict[str, object] = {}

        async def fake_discover(server_name: str, connector_config: dict[str, object]) -> ServerCapabilities:
            captured["connector_config"] = connector_config
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
        connector_config = captured["connector_config"]
        assert isinstance(connector_config, dict)
        assert connector_config["type"] == "sse"
        assert connector_config["url"] == "https://example.com/sse"

    def test_compare_url_target_uses_sse_connector(self, monkeypatch, tmp_path: Path):
        """Compare command should route URL target through SSE connector config."""
        captured: dict[str, object] = {}

        async def fake_discover(server_name: str, connector_config: dict[str, object]) -> ServerCapabilities:
            captured["connector_config"] = connector_config
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
        connector_config = captured["connector_config"]
        assert isinstance(connector_config, dict)
        assert connector_config["type"] == "sse"
        assert connector_config["url"] == "https://example.com/sse"

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

        scan_failures = [item for item in payload["findings"] if item["category"] == "scan_failure"]
        assert any(item["metadata"].get("server_name") == "failing" for item in scan_failures)
        assert any(item["metadata"].get("server_name") == "sse_failing" for item in scan_failures)
        assert any(item["metadata"].get("transport") == "sse" for item in scan_failures)

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

        assert "tool_added" in categories
        assert "tool_removed" in categories
        assert "tool_changed" in categories
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

    @pytest.mark.parametrize(
        ("raw_server_config", "expected_category"),
        [
            (42, "invalid_config_entry"),
            ({"transport": 7, "command": "python"}, "invalid_transport"),
            ({"transport": "grpc", "command": "python"}, "unsupported_transport"),
            ({"transport": "sse"}, "invalid_config_entry"),
            ({"transport": "sse", "url": "ftp://example.com/sse"}, "invalid_url"),
            ({"transport": "sse", "url": "https://example.com/sse", "headers": "bad"}, "invalid_headers"),
            ({"transport": "stdio"}, "invalid_config_entry"),
            ({"transport": "stdio", "command": "python", "args": "--bad"}, "invalid_args"),
            ({"transport": "stdio", "command": "python", "env": "--bad"}, "invalid_env"),
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

    def test_build_target_connector_config_for_url_and_stdio(self):
        """CLI target parser should infer SSE from URL targets."""
        sse_config = _build_target_connector_config("https://example.com/sse", timeout=9)
        stdio_config = _build_target_connector_config("python -m my_server", timeout=9)

        assert sse_config == {"type": "sse", "url": "https://example.com/sse", "timeout": 9}
        assert stdio_config == {"type": "stdio", "command": "python -m my_server", "timeout": 9}

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
