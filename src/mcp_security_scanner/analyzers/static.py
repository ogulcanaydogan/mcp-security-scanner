"""Static security analyzer for MCP tool definitions."""

import json
import re
from typing import Any

from mcp_security_scanner.analyzers.base import BaseAnalyzer, Finding, Severity
from mcp_security_scanner.discovery import ToolDefinition


class StaticAnalyzer(BaseAnalyzer):
    """Detect dangerous patterns in MCP tool metadata and schemas."""

    def __init__(self: "StaticAnalyzer") -> None:
        super().__init__(
            name="static_analyzer",
            description="Pattern matching for dangerous code, shell, and data-access hints.",
        )

        self._rules: list[tuple[re.Pattern[str], Severity, str, str, str, str, str]] = [
            (
                re.compile(r"\b(eval|exec|__import__)\b", re.IGNORECASE),
                Severity.HIGH,
                "Dynamic Code Execution Pattern",
                "Tool description references dynamic code execution primitives.",
                "LLM02",
                "Avoid dynamic code execution and use explicit safe allowlists.",
                "unsafe_code_execution",
            ),
            (
                re.compile(r"\b(os\.system|subprocess\.|shell\s+command|`.+`|\$\(.+\))", re.IGNORECASE),
                Severity.HIGH,
                "Shell Execution Pattern",
                "Tool metadata suggests shell command execution behavior.",
                "LLM07",
                "Replace shell execution with safe command wrappers and input validation.",
                "shell_injection_risk",
            ),
            (
                re.compile(r"(open\(|/etc/|/root/|pathlib\.Path|filesystem)", re.IGNORECASE),
                Severity.MEDIUM,
                "Sensitive Filesystem Access Pattern",
                "Tool metadata suggests direct filesystem access.",
                "LLM06",
                "Restrict filesystem scope to explicit safe directories.",
                "filesystem_access",
            ),
            (
                re.compile(r"\b(requests|socket|http[s]?://|dns|outbound)\b", re.IGNORECASE),
                Severity.MEDIUM,
                "Network Egress Pattern",
                "Tool metadata indicates outbound network capabilities.",
                "LLM07",
                "Add egress allowlists and redact sensitive values before transmission.",
                "network_egress",
            ),
            (
                re.compile(r"\b(os\.getenv|os\.environ|api[_-]?key|secret[_-]?key|private[_-]?key)\b", re.IGNORECASE),
                Severity.HIGH,
                "Credential Access Pattern",
                "Tool metadata references secrets or environment credential reads.",
                "LLM06",
                "Use scoped credentials and avoid exposing secrets through tool outputs.",
                "credential_access",
            ),
            (
                re.compile(r"\b(select|insert|update|delete|drop\s+table|union\s+select)\b", re.IGNORECASE),
                Severity.MEDIUM,
                "SQL Injection Surface Pattern",
                "Tool metadata references raw SQL-like operations.",
                "LLM02",
                "Use parameterized queries and strict query templates.",
                "sql_risk",
            ),
        ]

    async def analyze(self: "StaticAnalyzer", **kwargs: Any) -> list[Finding]:
        """Analyze tool definitions and return static findings."""
        self.clear_findings()

        tools = kwargs.get("tools", [])
        if not isinstance(tools, list):
            return self.get_findings()

        for tool in tools:
            if not isinstance(tool, ToolDefinition):
                continue

            searchable_text = self._build_searchable_text(tool)
            for pattern, severity, title, description, owasp_id, remediation, category in self._rules:
                match = pattern.search(searchable_text)
                if not match:
                    continue

                evidence = self._extract_evidence(searchable_text, match.start(), match.end())
                self.add_finding(
                    severity=severity,
                    category=category,
                    title=title,
                    description=description,
                    evidence=evidence,
                    owasp_id=owasp_id,
                    remediation=remediation,
                    tool_name=tool.name,
                )

        return self.get_findings()

    @staticmethod
    def _build_searchable_text(tool: ToolDefinition) -> str:
        """Concatenate tool fields for static pattern matching."""
        parts = [
            tool.name,
            tool.description,
            json.dumps(tool.input_schema, ensure_ascii=False, sort_keys=True),
        ]
        if tool.output_schema is not None:
            parts.append(json.dumps(tool.output_schema, ensure_ascii=False, sort_keys=True))
        return "\n".join(parts)

    @staticmethod
    def _extract_evidence(text: str, start: int, end: int, window: int = 80) -> str:
        """Extract a short evidence snippet around a regex match."""
        snippet_start = max(0, start - window)
        snippet_end = min(len(text), end + window)
        return text[snippet_start:snippet_end].strip()
