"""Tests for dynamic analyzer runtime probe behavior."""

import asyncio

import pytest

from mcp_security_scanner.analyzers.base import Severity
from mcp_security_scanner.analyzers.dynamic import DynamicAnalyzer, DynamicProbePolicy
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
        assert first["count"] == 0
        assert first["enabled"] is False
        assert first["name"] == "security_probe"

    def test_probe_payload_builder_is_bounded_and_deterministic(self):
        """Payload builder should cap fields and keep deterministic ordering."""
        analyzer = DynamicAnalyzer(policy=DynamicProbePolicy(max_payload_fields=2, max_probe_payloads=1))
        payloads = analyzer._build_probe_payloads(
            {
                "type": "object",
                "required": ["zeta", "beta"],
                "properties": {
                    "beta": {"type": "string"},
                    "alpha": {"type": "integer"},
                    "zeta": {"type": "boolean"},
                },
            }
        )

        assert payloads == [{"zeta": False, "beta": "security_probe"}]

    def test_probe_payload_builder_adds_semantic_variants(self):
        """Semantic field-name probes should produce deterministic additional payloads."""
        analyzer = DynamicAnalyzer(policy=DynamicProbePolicy(max_payload_fields=4, max_probe_payloads=3))
        payloads = analyzer._build_probe_payloads(
            {
                "type": "object",
                "required": ["url", "query", "command"],
                "properties": {
                    "command": {"type": "string"},
                    "query": {"type": "string"},
                    "url": {"type": "string"},
                },
            }
        )

        assert payloads[0] == {
            "url": "security_probe",
            "query": "security_probe",
            "command": "security_probe",
        }
        assert payloads[1] == {
            "url": "https://example.com/health",
            "query": "status check",
            "command": "echo security_probe",
        }
        assert payloads[2]["probe"] == "mcp-security-scanner"

    def test_probe_payload_builder_semantic_variants_respect_probe_limit(self):
        """Semantic probe variants must still obey configured max probe payload count."""
        analyzer = DynamicAnalyzer(policy=DynamicProbePolicy(max_payload_fields=4, max_probe_payloads=2))
        payloads = analyzer._build_probe_payloads(
            {
                "type": "object",
                "required": ["url", "query", "command"],
                "properties": {
                    "command": {"type": "string"},
                    "query": {"type": "string"},
                    "url": {"type": "string"},
                },
            }
        )

        assert len(payloads) == 2
        assert payloads[0]["url"] == "security_probe"
        assert payloads[1]["url"] == "https://example.com/health"

    @pytest.mark.asyncio
    async def test_sensitive_placeholder_output_is_suppressed(self):
        """Placeholder secret text should not raise sensitive-output finding."""
        analyzer = DynamicAnalyzer()
        tool = ToolDefinition(
            name="placeholder_tool",
            description="Returns placeholder credentials.",
            input_schema={"type": "object", "properties": {"query": {"type": "string"}}},
        )

        async def fake_execute(tool_name: str, args: dict[str, object]) -> str:
            del tool_name, args
            return "api_key: REDACTED (example only)"

        findings = await analyzer.analyze(tools=[tool], execute_tool=fake_execute)
        assert findings == []

    @pytest.mark.asyncio
    async def test_sensitive_bearer_placeholder_output_is_suppressed(self):
        """Placeholder bearer token snippets in example context should be suppressed."""
        analyzer = DynamicAnalyzer()
        tool = ToolDefinition(
            name="bearer_example_tool",
            description="Returns example auth header output.",
            input_schema={"type": "object", "properties": {"query": {"type": "string"}}},
        )

        async def fake_execute(tool_name: str, args: dict[str, object]) -> str:
            del tool_name, args
            return "Authorization: Bearer <token> (example output)"

        findings = await analyzer.analyze(tools=[tool], execute_tool=fake_execute)
        assert findings == []

    @pytest.mark.asyncio
    async def test_command_signal_in_blocked_context_is_suppressed(self):
        """Blocked/simulated execution text should not raise command-execution finding."""
        analyzer = DynamicAnalyzer()
        tool = ToolDefinition(
            name="blocked_exec_tool",
            description="Tool with blocked execution policy.",
            input_schema={"type": "object", "properties": {"command": {"type": "string"}}},
        )

        async def fake_execute(tool_name: str, args: dict[str, object]) -> str:
            del tool_name, args
            return "uid=0(root) gid=0(root) execution blocked by policy"

        findings = await analyzer.analyze(tools=[tool], execute_tool=fake_execute)
        assert findings == []

    @pytest.mark.asyncio
    async def test_command_signal_in_documentation_context_is_suppressed(self):
        """Documentation/sample command output should be suppressed as benign context."""
        analyzer = DynamicAnalyzer()
        tool = ToolDefinition(
            name="docs_exec_tool",
            description="Returns documentation snippets.",
            input_schema={"type": "object", "properties": {"command": {"type": "string"}}},
        )

        async def fake_execute(tool_name: str, args: dict[str, object]) -> str:
            del tool_name, args
            return "uid=0(root) gid=0(root) documentation example output only"

        findings = await analyzer.analyze(tools=[tool], execute_tool=fake_execute)
        assert findings == []

    @pytest.mark.asyncio
    async def test_timeout_is_non_fatal_and_scan_continues(self):
        """Timeout should produce execution-error finding and continue with next tool."""
        analyzer = DynamicAnalyzer(
            policy=DynamicProbePolicy(
                max_tools=2,
                max_payload_fields=1,
                max_probe_payloads=1,
                per_probe_timeout_seconds=0.01,
            )
        )
        tools = [
            ToolDefinition(
                name="slow_tool",
                description="Sleeps too long.",
                input_schema={"type": "object", "properties": {"input": {"type": "string"}}},
            ),
            ToolDefinition(
                name="secret_tool",
                description="Returns sensitive output.",
                input_schema={"type": "object", "properties": {"query": {"type": "string"}}},
            ),
        ]

        async def fake_execute(tool_name: str, args: dict[str, object]) -> str:
            del args
            if tool_name == "slow_tool":
                await asyncio.sleep(0.05)
                return "done"
            return "-----BEGIN PRIVATE KEY-----abc"

        findings = await analyzer.analyze(tools=tools, execute_tool=fake_execute)
        categories = [finding.category for finding in findings]

        assert categories == ["dynamic_sensitive_output", "dynamic_tool_execution_error"]
        timeout_findings = [item for item in findings if item.category == "dynamic_tool_execution_error"]
        assert timeout_findings
        assert timeout_findings[0].metadata["error_type"] == "TimeoutError"

    @pytest.mark.asyncio
    async def test_findings_are_sorted_deterministically(self):
        """Findings should be returned in stable order regardless of input tool order."""
        analyzer = DynamicAnalyzer()
        tools = [
            ToolDefinition(
                name="z_tool",
                description="Returns secret output.",
                input_schema={"type": "object", "properties": {"query": {"type": "string"}}},
            ),
            ToolDefinition(
                name="a_tool",
                description="Returns secret output.",
                input_schema={"type": "object", "properties": {"query": {"type": "string"}}},
            ),
        ]

        async def fake_execute(tool_name: str, args: dict[str, object]) -> str:
            del tool_name, args
            return "-----BEGIN PRIVATE KEY-----abc"

        findings = await analyzer.analyze(tools=tools, execute_tool=fake_execute)
        assert [finding.tool_name for finding in findings] == ["a_tool", "z_tool"]
