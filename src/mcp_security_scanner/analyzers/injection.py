"""Prompt injection analyzer for MCP tool and resource metadata."""

import re
from typing import Any

from mcp_security_scanner.analyzers.base import BaseAnalyzer, Finding, Severity
from mcp_security_scanner.discovery import ResourceDefinition, ToolDefinition


class PromptInjectionAnalyzer(BaseAnalyzer):
    """Detect prompt injection and instruction override patterns."""

    def __init__(self: "PromptInjectionAnalyzer") -> None:
        super().__init__(
            name="prompt_injection_analyzer",
            description="Detects instruction override and jailbreak patterns in MCP metadata.",
        )

        self._tool_patterns: list[tuple[re.Pattern[str], Severity, str, str, str]] = [
            (
                re.compile(r"\b(ignore\s+previous|ignore\s+all\s+previous)\b", re.IGNORECASE),
                Severity.HIGH,
                "Instruction Override Phrase",
                "Tool description contains explicit instruction override wording.",
                "prompt_instruction_override",
            ),
            (
                re.compile(r"\b(system:|administrator:|you\s+are\s+now)\b", re.IGNORECASE),
                Severity.HIGH,
                "Role Escalation Phrase",
                "Tool description attempts to redefine system or administrator role context.",
                "role_context_escalation",
            ),
            (
                re.compile(r"\b(forget\s+your\s+instructions|bypass\s+security|disable\s+safety)\b", re.IGNORECASE),
                Severity.CRITICAL,
                "Jailbreak Phrase",
                "Tool description contains jailbreak-style bypass language.",
                "jailbreak_pattern",
            ),
        ]

        self._resource_patterns: list[tuple[re.Pattern[str], Severity, str, str, str]] = [
            (
                re.compile(r"\b(ignore_previous|ignore previous|system prompt|developer message)\b", re.IGNORECASE),
                Severity.HIGH,
                "Resource Prompt Poisoning Phrase",
                "Resource content contains phrases commonly used for prompt poisoning.",
                "resource_prompt_poisoning",
            ),
            (
                re.compile(r"\{\{.*\}\}|<\/?(system|assistant|user)>", re.IGNORECASE | re.DOTALL),
                Severity.MEDIUM,
                "Context Boundary Confusion Pattern",
                "Resource content contains template or pseudo-chat tags that can blur context boundaries.",
                "context_boundary_confusion",
            ),
        ]

    async def analyze(self: "PromptInjectionAnalyzer", **kwargs: Any) -> list[Finding]:
        """Analyze tools/resources for prompt injection patterns."""
        self.clear_findings()

        tools = kwargs.get("tools", [])
        resources = kwargs.get("resources", [])

        if isinstance(tools, list):
            for tool in tools:
                if isinstance(tool, ToolDefinition):
                    self._analyze_tool(tool)

        if isinstance(resources, list):
            for resource in resources:
                if isinstance(resource, ResourceDefinition):
                    self._analyze_resource(resource)

        return self.get_findings()

    def _analyze_tool(self: "PromptInjectionAnalyzer", tool: ToolDefinition) -> None:
        """Evaluate tool metadata for injection indicators."""
        text = f"{tool.name}\n{tool.description}".strip()
        for pattern, severity, title, description, category in self._tool_patterns:
            match = pattern.search(text)
            if not match:
                continue
            self.add_finding(
                severity=severity,
                category=category,
                title=title,
                description=description,
                evidence=self._extract_evidence(text, match.start(), match.end()),
                owasp_id="LLM01",
                remediation="Remove instruction-override language and keep descriptions task-scoped.",
                tool_name=tool.name,
            )

        if self._has_token_smuggling_signal(text):
            self.add_finding(
                severity=Severity.MEDIUM,
                category="token_smuggling_pattern",
                title="Potential Token Smuggling Signal",
                description="Tool description has unusually high symbolic density, which can hide instruction payloads.",
                evidence=text[:240],
                owasp_id="LLM01",
                remediation="Normalize tool descriptions and reject opaque special-character payloads.",
                tool_name=tool.name,
            )

    def _analyze_resource(self: "PromptInjectionAnalyzer", resource: ResourceDefinition) -> None:
        """Evaluate resource content for poisoning indicators."""
        content = resource.content or ""
        if not content:
            return

        searchable = f"{resource.name}\n{resource.description}\n{content}"
        for pattern, severity, title, description, category in self._resource_patterns:
            match = pattern.search(searchable)
            if not match:
                continue
            self.add_finding(
                severity=severity,
                category=category,
                title=title,
                description=description,
                evidence=self._extract_evidence(searchable, match.start(), match.end()),
                owasp_id="LLM01",
                remediation="Treat untrusted resource text as data and avoid direct prompt interpolation.",
                resource_name=resource.name,
            )

    @staticmethod
    def _has_token_smuggling_signal(text: str) -> bool:
        """Heuristic: detect suspicious density of non-alphanumeric symbols."""
        if len(text) < 40:
            return False

        symbol_count = sum(1 for char in text if not char.isalnum() and not char.isspace())
        ratio = symbol_count / len(text)
        return ratio >= 0.35

    @staticmethod
    def _extract_evidence(text: str, start: int, end: int, window: int = 80) -> str:
        """Extract a short evidence snippet around a regex match."""
        snippet_start = max(0, start - window)
        snippet_end = min(len(text), end + window)
        return text[snippet_start:snippet_end].strip()
