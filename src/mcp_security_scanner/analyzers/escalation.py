"""Capability escalation analyzer for MCP tools."""

import json
import re
from enum import Enum
from typing import Any

from mcp_security_scanner.analyzers.base import BaseAnalyzer, Finding, Severity
from mcp_security_scanner.discovery import ToolDefinition


class CapabilityRiskProfile(str, Enum):
    """Capability risk taxonomy for MCP tools."""

    ADMIN = "admin"
    PRIVILEGED = "privileged"
    SENSITIVE = "sensitive"
    STANDARD = "standard"
    BENIGN = "benign"


_PROFILE_RANK = {
    CapabilityRiskProfile.BENIGN: 0,
    CapabilityRiskProfile.STANDARD: 1,
    CapabilityRiskProfile.SENSITIVE: 2,
    CapabilityRiskProfile.PRIVILEGED: 3,
    CapabilityRiskProfile.ADMIN: 4,
}

_PROFILE_BASE_SCORE = {
    CapabilityRiskProfile.BENIGN: 0.0,
    CapabilityRiskProfile.STANDARD: 0.2,
    CapabilityRiskProfile.SENSITIVE: 0.45,
    CapabilityRiskProfile.PRIVILEGED: 0.7,
    CapabilityRiskProfile.ADMIN: 0.9,
}

_PROFILE_SEVERITY = {
    CapabilityRiskProfile.ADMIN: Severity.HIGH,
    CapabilityRiskProfile.PRIVILEGED: Severity.MEDIUM,
    CapabilityRiskProfile.SENSITIVE: Severity.LOW,
}

_PROFILE_CATEGORY = {
    CapabilityRiskProfile.ADMIN: "capability_admin",
    CapabilityRiskProfile.PRIVILEGED: "capability_privileged",
    CapabilityRiskProfile.SENSITIVE: "capability_sensitive",
}

_PROFILE_OWASP = {
    CapabilityRiskProfile.ADMIN: "LLM08",
    CapabilityRiskProfile.PRIVILEGED: "LLM06",
    CapabilityRiskProfile.SENSITIVE: "LLM06",
}


class EscalationAnalyzer(BaseAnalyzer):
    """Detect excessive agency and sensitive capability exposure in tool metadata."""

    def __init__(self: "EscalationAnalyzer") -> None:
        super().__init__(
            name="escalation_analyzer",
            description="Classifies tools by capability risk profile and flags excessive permissions.",
        )

        self._admin_patterns: list[tuple[re.Pattern[str], str]] = [
            (re.compile(r"\b(sudo|root\s+access|administrator|admin\s+mode)\b", re.IGNORECASE), "admin_keywords"),
            (
                re.compile(
                    r"\b(shutdown|reboot|terminate\s+process|kill\s+process|systemctl|service\s+stop)\b", re.IGNORECASE
                ),
                "system_control",
            ),
            (
                re.compile(
                    r"\b(create\s+user|delete\s+user|user\s+management|permission\s+change|chmod|chown)\b",
                    re.IGNORECASE,
                ),
                "identity_permission_management",
            ),
        ]
        self._privileged_patterns: list[tuple[re.Pattern[str], str]] = [
            (
                re.compile(
                    r"\b(os\.system|subprocess|exec(?:ute|ution)?|shell\s+command|command\s+runner)\b", re.IGNORECASE
                ),
                "command_execution",
            ),
            (
                re.compile(
                    r"\b(write\s+file|filesystem\s+write|rm\s+-rf|delete\s+file|create\s+file|pathlib\.Path)\b",
                    re.IGNORECASE,
                ),
                "filesystem_write",
            ),
            (
                re.compile(r"\b(outbound|http[s]?://|requests\.|socket\.|dns|network\s+call)\b", re.IGNORECASE),
                "network_egress",
            ),
            (
                re.compile(
                    r"\b(drop\s+table|insert\s+into|update\s+\w+|delete\s+from|database\s+mutation)\b", re.IGNORECASE
                ),
                "database_mutation",
            ),
            (
                re.compile(r"\b(secret|api[_-]?key|private[_-]?key|credential|token)\b", re.IGNORECASE),
                "credential_access",
            ),
        ]
        self._sensitive_patterns: list[tuple[re.Pattern[str], str]] = [
            (
                re.compile(r"\b(read\s+file|filesystem\s+read|/etc/|/root/|cat\s+/etc)\b", re.IGNORECASE),
                "filesystem_read",
            ),
            (
                re.compile(r"\b(os\.getenv|os\.environ|environment\s+variable|env\s+read)\b", re.IGNORECASE),
                "environment_read",
            ),
            (
                re.compile(r"\b(list\s+resources|enumerate\s+resources|resource\s+discovery)\b", re.IGNORECASE),
                "resource_enumeration",
            ),
        ]

    async def analyze(self: "EscalationAnalyzer", **kwargs: Any) -> list[Finding]:
        """Analyze tools and emit one highest-risk capability finding per tool."""
        self.clear_findings()

        tools = kwargs.get("tools", [])
        if not isinstance(tools, list):
            return self.get_findings()

        return self.flag_excessive_permissions([tool for tool in tools if isinstance(tool, ToolDefinition)])

    def assess_tool_risk(
        self: "EscalationAnalyzer",
        tool: ToolDefinition,
    ) -> tuple[CapabilityRiskProfile, list[str]]:
        """Classify one tool into a risk profile with matched signal names."""
        searchable_text = self._build_searchable_text(tool)

        admin_signals = self._collect_signals(searchable_text, self._admin_patterns)
        if admin_signals:
            return CapabilityRiskProfile.ADMIN, admin_signals

        privileged_signals = self._collect_signals(searchable_text, self._privileged_patterns)
        if privileged_signals:
            return CapabilityRiskProfile.PRIVILEGED, privileged_signals

        sensitive_signals = self._collect_signals(searchable_text, self._sensitive_patterns)
        if sensitive_signals:
            return CapabilityRiskProfile.SENSITIVE, sensitive_signals

        if self._looks_action_oriented(tool):
            return CapabilityRiskProfile.STANDARD, []

        return CapabilityRiskProfile.BENIGN, []

    def score_tool_permissions(
        self: "EscalationAnalyzer",
        profile: CapabilityRiskProfile,
        matched_signals: list[str],
    ) -> float:
        """Produce a stable risk score in [0.0, 1.0] for metadata/reporting."""
        base_score = _PROFILE_BASE_SCORE[profile]
        signal_boost = min(0.08, 0.02 * len(matched_signals))
        return round(min(1.0, base_score + signal_boost), 2)

    def flag_excessive_permissions(self: "EscalationAnalyzer", tools: list[ToolDefinition]) -> list[Finding]:
        """Generate one capability finding per risky tool (sensitive+)."""
        for tool in tools:
            profile, matched_signals = self.assess_tool_risk(tool)
            if profile not in _PROFILE_SEVERITY:
                continue

            risk_score = self.score_tool_permissions(profile, matched_signals)
            self.add_finding(
                severity=_PROFILE_SEVERITY[profile],
                category=_PROFILE_CATEGORY[profile],
                title=f"{profile.value.capitalize()} capability exposure",
                description=f"Tool exposes {profile.value} capabilities that may enable excessive agency.",
                evidence=self._build_evidence(tool, profile, matched_signals),
                owasp_id=_PROFILE_OWASP[profile],
                remediation=(
                    "Apply least-privilege controls, require explicit approvals, "
                    "and limit tool scope to approved operations."
                ),
                tool_name=tool.name,
                metadata={
                    "risk_profile": profile.value,
                    "risk_score": risk_score,
                    "matched_signals": matched_signals,
                },
            )

        return self.get_findings()

    @staticmethod
    def _collect_signals(text: str, rules: list[tuple[re.Pattern[str], str]]) -> list[str]:
        """Collect unique signal names matched by regex rules."""
        signals: list[str] = []
        for pattern, signal_name in rules:
            if pattern.search(text) and signal_name not in signals:
                signals.append(signal_name)
        return signals

    @staticmethod
    def _build_searchable_text(tool: ToolDefinition) -> str:
        """Build deterministic text corpus from tool metadata."""
        parts = [
            tool.name,
            tool.description,
            json.dumps(tool.input_schema, ensure_ascii=False, sort_keys=True),
        ]
        if tool.output_schema is not None:
            parts.append(json.dumps(tool.output_schema, ensure_ascii=False, sort_keys=True))
        return "\n".join(parts)

    @staticmethod
    def _looks_action_oriented(tool: ToolDefinition) -> bool:
        """Heuristic to distinguish benign tools from generic action tools."""
        combined = f"{tool.name} {tool.description}".lower()
        action_terms = ("run", "execute", "manage", "update", "write", "modify", "call")
        return any(term in combined for term in action_terms)

    @staticmethod
    def _build_evidence(tool: ToolDefinition, profile: CapabilityRiskProfile, matched_signals: list[str]) -> str:
        """Build concise, structured evidence payload for report outputs."""
        payload = {
            "tool": tool.name,
            "profile": profile.value,
            "signals": matched_signals,
            "description_preview": tool.description[:240],
        }
        return json.dumps(payload, ensure_ascii=False, sort_keys=True)

    @staticmethod
    def profile_rank(profile: CapabilityRiskProfile) -> int:
        """Expose deterministic profile order for tests and downstream use."""
        return _PROFILE_RANK[profile]
