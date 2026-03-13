"""Dynamic analyzer for safe runtime probing of MCP tools."""

import json
import re
from collections.abc import Awaitable, Callable
from typing import Any

from mcp_security_scanner.analyzers.base import BaseAnalyzer, Finding, Severity
from mcp_security_scanner.discovery import ToolDefinition

ExecuteToolCallable = Callable[[str, dict[str, Any]], Awaitable[Any]]


class DynamicAnalyzer(BaseAnalyzer):
    """Run bounded runtime probes against tools when explicitly enabled."""

    def __init__(self: "DynamicAnalyzer") -> None:
        super().__init__(
            name="dynamic_analyzer",
            description="Performs safe runtime probes and inspects tool responses for risky behavior.",
        )
        self._max_tools = 8
        self._sensitive_output_patterns = [
            re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", re.IGNORECASE),
            re.compile(r"\b(aws_secret_access_key|api[_-]?key|secret[_-]?key|password)\b", re.IGNORECASE),
            re.compile(r"authorization:\s*bearer\s+[A-Za-z0-9._\-]+", re.IGNORECASE),
            re.compile(r"root:x:0:0:", re.IGNORECASE),
        ]
        self._command_signal_patterns = [
            re.compile(r"\b(uid=\d+|gid=\d+|command executed|subprocess|shell)\b", re.IGNORECASE),
            re.compile(r"/etc/passwd", re.IGNORECASE),
            re.compile(r"\b(sh|bash|powershell)\s+-c\b", re.IGNORECASE),
        ]

    async def analyze(self: "DynamicAnalyzer", **kwargs: Any) -> list[Finding]:
        """Execute runtime probes against tools via execute_tool callback."""
        self.clear_findings()

        tools = kwargs.get("tools", [])
        execute_tool = kwargs.get("execute_tool")
        if not isinstance(tools, list) or not callable(execute_tool):
            return self.get_findings()

        execute_tool_fn = execute_tool
        for tool in tools[: self._max_tools]:
            if not isinstance(tool, ToolDefinition):
                continue

            probe_payloads = self._build_probe_payloads(tool.input_schema)
            for payload in probe_payloads:
                try:
                    result = await execute_tool_fn(tool.name, payload)
                except Exception as exc:
                    self.add_finding(
                        severity=Severity.MEDIUM,
                        category="dynamic_tool_execution_error",
                        title="Dynamic probe failed",
                        description="Tool execution failed during bounded dynamic probe.",
                        evidence=json.dumps(
                            {
                                "tool": tool.name,
                                "error_type": exc.__class__.__name__,
                                "probe_keys": sorted(payload.keys()),
                            },
                            ensure_ascii=False,
                            sort_keys=True,
                        ),
                        owasp_id="LLM07",
                        remediation="Review runtime safety controls and guardrails for this tool.",
                        tool_name=tool.name,
                        metadata={"probe_keys": sorted(payload.keys()), "probe_mode": "safe_runtime_v1"},
                    )
                    break

                normalized_result = self._normalize_result(result)
                if self._matches_any(self._sensitive_output_patterns, normalized_result):
                    self.add_finding(
                        severity=Severity.HIGH,
                        category="dynamic_sensitive_output",
                        title="Sensitive output observed during runtime probe",
                        description="Runtime response appears to expose secret material or sensitive data.",
                        evidence=self._trim_evidence(normalized_result),
                        owasp_id="LLM06",
                        remediation="Sanitize tool outputs and enforce redaction for sensitive values.",
                        tool_name=tool.name,
                        metadata={"probe_keys": sorted(payload.keys()), "probe_mode": "safe_runtime_v1"},
                    )
                    break

                if self._matches_any(self._command_signal_patterns, normalized_result):
                    self.add_finding(
                        severity=Severity.HIGH,
                        category="dynamic_command_execution_signal",
                        title="Command-execution signal observed during runtime probe",
                        description="Runtime response indicates possible command execution behavior.",
                        evidence=self._trim_evidence(normalized_result),
                        owasp_id="LLM07",
                        remediation="Restrict command execution surfaces and enforce strict allowlists.",
                        tool_name=tool.name,
                        metadata={"probe_keys": sorted(payload.keys()), "probe_mode": "safe_runtime_v1"},
                    )
                    break

        return self.get_findings()

    def _build_probe_payloads(self: "DynamicAnalyzer", input_schema: dict[str, Any]) -> list[dict[str, Any]]:
        """Build deterministic low-risk probe payloads from JSON schema."""
        base_payload = self._payload_from_schema(input_schema)
        probes = [base_payload]
        if "probe" not in base_payload:
            probe_payload = dict(base_payload)
            probe_payload["probe"] = "mcp-security-scanner"
            probes.append(probe_payload)
        return probes

    def _payload_from_schema(self: "DynamicAnalyzer", input_schema: dict[str, Any]) -> dict[str, Any]:
        """Build a bounded payload from tool schema fields."""
        properties = input_schema.get("properties")
        if not isinstance(properties, dict) or not properties:
            return {"probe": "mcp-security-scanner"}

        payload: dict[str, Any] = {}
        for key in sorted(properties.keys())[:3]:
            value_schema = properties.get(key)
            payload[key] = self._value_for_schema(value_schema)

        if not payload:
            payload["probe"] = "mcp-security-scanner"
        return payload

    @staticmethod
    def _value_for_schema(value_schema: Any) -> Any:
        """Generate deterministic safe probe values based on schema type."""
        if isinstance(value_schema, dict):
            schema_type = value_schema.get("type")
            if schema_type == "string":
                return "security_probe"
            if schema_type in {"number", "integer"}:
                return 1
            if schema_type == "boolean":
                return False
            if schema_type == "array":
                return ["security_probe"]
            if schema_type == "object":
                return {}
        return "security_probe"

    @staticmethod
    def _normalize_result(result: Any) -> str:
        """Convert tool response into deterministic text for pattern matching."""
        if isinstance(result, str):
            return result
        if isinstance(result, (dict, list)):
            return json.dumps(result, ensure_ascii=False, sort_keys=True)
        return str(result)

    @staticmethod
    def _matches_any(patterns: list[re.Pattern[str]], text: str) -> bool:
        """Return True if any pattern matches the result text."""
        for pattern in patterns:
            if pattern.search(text):
                return True
        return False

    @staticmethod
    def _trim_evidence(text: str, max_length: int = 400) -> str:
        """Trim result text for finding evidence payloads."""
        if len(text) <= max_length:
            return text
        return f"{text[:max_length].rstrip()}..."
