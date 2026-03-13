"""Dynamic analyzer for safe runtime probing of MCP tools."""

import asyncio
import json
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from mcp_security_scanner.analyzers.base import BaseAnalyzer, Finding, Severity
from mcp_security_scanner.discovery import ToolDefinition

ExecuteToolCallable = Callable[[str, dict[str, Any]], Awaitable[Any]]


@dataclass(frozen=True)
class DynamicProbePolicy:
    """Single control point for bounded dynamic probing behavior."""

    max_tools: int = 8
    max_payload_fields: int = 3
    max_probe_payloads: int = 2
    per_probe_timeout_seconds: float = 4.0
    max_evidence_length: int = 400


class DynamicAnalyzer(BaseAnalyzer):
    """Run bounded runtime probes against tools when explicitly enabled."""

    def __init__(self: "DynamicAnalyzer", policy: DynamicProbePolicy | None = None) -> None:
        super().__init__(
            name="dynamic_analyzer",
            description="Performs safe runtime probes and inspects tool responses for risky behavior.",
        )
        self._policy = policy or DynamicProbePolicy()
        self._probe_mode = "safe_runtime_v2"
        self._sensitive_output_signals = [
            ("private_key_material", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", re.IGNORECASE)),
            (
                "credential_assignment",
                re.compile(
                    r"\b(?:aws_secret_access_key|api[_-]?key|secret[_-]?key|password)\b\s*[:=]\s*[\"']?[A-Za-z0-9/+._\-]{8,}",
                    re.IGNORECASE,
                ),
            ),
            (
                "bearer_token_header",
                re.compile(r"\bauthorization\s*:\s*bearer\s+[A-Za-z0-9._\-]{20,}\b", re.IGNORECASE),
            ),
            ("passwd_dump", re.compile(r"root:x:0:0:[^\n]*:/root:/", re.IGNORECASE)),
        ]
        self._command_signal_patterns = [
            ("uid_gid_output", re.compile(r"\buid=\d+\([^)]+\)\s+gid=\d+\([^)]+\)", re.IGNORECASE)),
            ("passwd_path_access", re.compile(r"/etc/passwd", re.IGNORECASE)),
            ("shell_invocation", re.compile(r"\b(?:sh|bash|zsh|powershell)\s+-c\b", re.IGNORECASE)),
        ]

    async def analyze(self: "DynamicAnalyzer", **kwargs: Any) -> list[Finding]:
        """Execute runtime probes against tools via execute_tool callback."""
        self.clear_findings()

        tools = kwargs.get("tools", [])
        execute_tool = kwargs.get("execute_tool")
        if not isinstance(tools, list) or not callable(execute_tool):
            return self.get_findings()

        execute_tool_fn: ExecuteToolCallable = execute_tool
        normalized_tools = sorted(
            (tool for tool in tools if isinstance(tool, ToolDefinition)),
            key=lambda candidate: (candidate.name.lower(), candidate.name),
        )
        for tool_index, tool in enumerate(normalized_tools[: self._policy.max_tools]):
            probe_payloads = self._build_probe_payloads(tool.input_schema)
            for probe_index, payload in enumerate(probe_payloads):
                probe_keys = sorted(payload.keys())
                try:
                    result = await asyncio.wait_for(
                        execute_tool_fn(tool.name, payload),
                        timeout=self._policy.per_probe_timeout_seconds,
                    )
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
                                "probe_keys": probe_keys,
                                "probe_index": probe_index,
                            },
                            ensure_ascii=False,
                            sort_keys=True,
                        ),
                        owasp_id="LLM07",
                        remediation="Review runtime safety controls and guardrails for this tool.",
                        tool_name=tool.name,
                        metadata=self._build_probe_metadata(
                            probe_keys=probe_keys,
                            tool_index=tool_index,
                            probe_index=probe_index,
                            error_type=exc.__class__.__name__,
                        ),
                    )
                    break

                normalized_result = self._normalize_result(result)
                sensitive_signal = self._match_signal(self._sensitive_output_signals, normalized_result)
                if sensitive_signal is not None and not self._is_benign_sensitive_context(
                    normalized_result, sensitive_signal
                ):
                    self.add_finding(
                        severity=Severity.HIGH,
                        category="dynamic_sensitive_output",
                        title="Sensitive output observed during runtime probe",
                        description="Runtime response appears to expose secret material or sensitive data.",
                        evidence=self._trim_evidence(normalized_result),
                        owasp_id="LLM06",
                        remediation="Sanitize tool outputs and enforce redaction for sensitive values.",
                        tool_name=tool.name,
                        metadata=self._build_probe_metadata(
                            probe_keys=probe_keys,
                            tool_index=tool_index,
                            probe_index=probe_index,
                            matched_signal=sensitive_signal,
                        ),
                    )
                    break

                command_signal = self._match_signal(self._command_signal_patterns, normalized_result)
                if command_signal is not None and not self._is_benign_command_context(normalized_result):
                    self.add_finding(
                        severity=Severity.HIGH,
                        category="dynamic_command_execution_signal",
                        title="Command-execution signal observed during runtime probe",
                        description="Runtime response indicates possible command execution behavior.",
                        evidence=self._trim_evidence(normalized_result),
                        owasp_id="LLM07",
                        remediation="Restrict command execution surfaces and enforce strict allowlists.",
                        tool_name=tool.name,
                        metadata=self._build_probe_metadata(
                            probe_keys=probe_keys,
                            tool_index=tool_index,
                            probe_index=probe_index,
                            matched_signal=command_signal,
                        ),
                    )
                    break

        return self._sorted_findings(self.get_findings())

    def _build_probe_payloads(self: "DynamicAnalyzer", input_schema: dict[str, Any]) -> list[dict[str, Any]]:
        """Build deterministic low-risk probe payloads from JSON schema."""
        base_payload = self._payload_from_schema(input_schema)
        probes = [base_payload]
        if (
            "probe" not in base_payload
            and len(base_payload) < self._policy.max_payload_fields
            and self._policy.max_probe_payloads > 1
        ):
            probe_payload = dict(base_payload)
            probe_payload["probe"] = "mcp-security-scanner"
            probes.append(probe_payload)
        return probes[: self._policy.max_probe_payloads]

    def _payload_from_schema(self: "DynamicAnalyzer", input_schema: dict[str, Any]) -> dict[str, Any]:
        """Build a bounded payload from tool schema fields."""
        properties = input_schema.get("properties")
        if not isinstance(properties, dict) or not properties:
            return {"probe": "mcp-security-scanner"}

        required_values = input_schema.get("required", [])
        prioritized: list[str] = []
        if isinstance(required_values, list):
            for value in required_values:
                if isinstance(value, str) and value in properties and value not in prioritized:
                    prioritized.append(value)

        for key in sorted(properties.keys()):
            if key not in prioritized:
                prioritized.append(key)

        payload: dict[str, Any] = {}
        for key in prioritized[: self._policy.max_payload_fields]:
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
                return 0
            if schema_type == "boolean":
                return False
            if schema_type == "array":
                return []
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
    def _match_signal(patterns: list[tuple[str, re.Pattern[str]]], text: str) -> str | None:
        """Return matching signal label for a text, if any."""
        for signal_name, pattern in patterns:
            if pattern.search(text):
                return signal_name
        return None

    @staticmethod
    def _is_benign_sensitive_context(text: str, signal_name: str) -> bool:
        """Suppress low-confidence credential keywords in clearly benign placeholder context."""
        if signal_name != "credential_assignment":
            return False
        lowered = text.lower()
        benign_markers = (
            "redacted",
            "masked",
            "placeholder",
            "example",
            "sample",
            "dummy",
            "<token>",
            "<api_key>",
            "******",
        )
        return any(marker in lowered for marker in benign_markers)

    @staticmethod
    def _is_benign_command_context(text: str) -> bool:
        """Suppress command signals that are explicitly blocked, simulated, or documentation-only."""
        lowered = text.lower()
        benign_markers = (
            "not executed",
            "execution blocked",
            "blocked by policy",
            "dry run",
            "simulation",
            "example output",
            "forbidden",
            "permission denied",
            "disallowed",
        )
        return any(marker in lowered for marker in benign_markers)

    def _build_probe_metadata(
        self: "DynamicAnalyzer",
        probe_keys: list[str],
        tool_index: int,
        probe_index: int,
        matched_signal: str | None = None,
        error_type: str | None = None,
    ) -> dict[str, Any]:
        """Build deterministic metadata payload for dynamic findings."""
        metadata: dict[str, Any] = {
            "probe_mode": self._probe_mode,
            "probe_keys": probe_keys,
            "tool_index": tool_index,
            "probe_index": probe_index,
            "max_tools": self._policy.max_tools,
            "max_probe_payloads": self._policy.max_probe_payloads,
            "probe_timeout_seconds": self._policy.per_probe_timeout_seconds,
        }
        if matched_signal is not None:
            metadata["matched_signal"] = matched_signal
        if error_type is not None:
            metadata["error_type"] = error_type
        return metadata

    @staticmethod
    def _sorted_findings(findings: list[Finding]) -> list[Finding]:
        """Ensure stable ordering for report diff friendliness."""
        return sorted(
            findings,
            key=lambda finding: (
                finding.tool_name or "",
                finding.category,
                finding.title,
            ),
        )

    def _trim_evidence(self: "DynamicAnalyzer", text: str) -> str:
        """Trim result text for finding evidence payloads."""
        if len(text) <= self._policy.max_evidence_length:
            return text
        return f"{text[: self._policy.max_evidence_length].rstrip()}..."
