"""Tests for dynamic analyzer runtime probe behavior."""

import pytest

from mcp_security_scanner.analyzers.base import Severity
from mcp_security_scanner.analyzers.dynamic import DynamicAnalyzer
from mcp_security_scanner.discovery import ToolDefinition


class TestDynamicAnalyzer:
    """Dynamic analyzer test suite."""

    @pytest.mark.asyncio
    async def test_analyze_returns_empty_without_execute_tool_callback(self):
        """Dynamic analyzer should no-op when execute callback is not provided."""
        analyzer = DynamicAnalyzer()
        tool = ToolDefinition(
            name="status_tool",
            description="Returns status.",
            input_schema={"type": "object"},
        )

        findings = await analyzer.analyze(tools=[tool])
        assert findings == []

    @pytest.mark.asyncio
    async def test_detects_runtime_execution_error(self):
        """Execution failures during probe should emit medium finding."""
        analyzer = DynamicAnalyzer()
        tool = ToolDefinition(
            name="unstable_tool",
            description="Tool that may fail at runtime.",
            input_schema={"type": "object", "properties": {"input": {"type": "string"}}},
        )

        async def fake_execute(tool_name: str, args: dict[str, object]) -> dict[str, object]:
            del tool_name, args
            raise RuntimeError("probe failed")

        findings = await analyzer.analyze(tools=[tool], execute_tool=fake_execute)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.category == "dynamic_tool_execution_error"
        assert finding.severity == Severity.MEDIUM
        assert finding.owasp_id == "LLM07"
        assert finding.tool_name == "unstable_tool"

    @pytest.mark.asyncio
    async def test_detects_sensitive_output_signal(self):
        """Secret-like output markers should emit high severity sensitive-output finding."""
        analyzer = DynamicAnalyzer()
        tool = ToolDefinition(
            name="secret_tool",
            description="Returns potentially sensitive output.",
            input_schema={"type": "object", "properties": {"query": {"type": "string"}}},
        )

        async def fake_execute(tool_name: str, args: dict[str, object]) -> dict[str, object]:
            del tool_name, args
            return {"result": "-----BEGIN PRIVATE KEY-----\\nabc\\n-----END PRIVATE KEY-----"}

        findings = await analyzer.analyze(tools=[tool], execute_tool=fake_execute)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.category == "dynamic_sensitive_output"
        assert finding.severity == Severity.HIGH
        assert finding.owasp_id == "LLM06"
        assert finding.tool_name == "secret_tool"

    @pytest.mark.asyncio
    async def test_detects_command_execution_signal(self):
        """Command-execution output markers should emit high severity runtime finding."""
        analyzer = DynamicAnalyzer()
        tool = ToolDefinition(
            name="exec_tool",
            description="Executes shell commands.",
            input_schema={"type": "object", "properties": {"command": {"type": "string"}}},
        )

        async def fake_execute(tool_name: str, args: dict[str, object]) -> str:
            del tool_name, args
            return "uid=0(root) gid=0(root) groups=0(root)"

        findings = await analyzer.analyze(tools=[tool], execute_tool=fake_execute)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.category == "dynamic_command_execution_signal"
        assert finding.severity == Severity.HIGH
        assert finding.owasp_id == "LLM07"

    def test_probe_payload_builder_uses_schema_types(self):
        """Probe payload generation should be deterministic and type-aware."""
        analyzer = DynamicAnalyzer()
        payloads = analyzer._build_probe_payloads(
            {
                "type": "object",
                "properties": {
                    "count": {"type": "integer"},
                    "enabled": {"type": "boolean"},
                    "name": {"type": "string"},
                },
            }
        )

        assert payloads
        first = payloads[0]
        assert first["count"] == 1
        assert first["enabled"] is False
        assert first["name"] == "security_probe"
