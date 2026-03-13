"""Cross-tool attack chain analyzer for MCP tool metadata."""

import json
import re
from dataclasses import dataclass
from typing import Any

from mcp_security_scanner.analyzers.base import BaseAnalyzer, Finding, Severity
from mcp_security_scanner.discovery import ToolDefinition


@dataclass(frozen=True)
class AttackChain:
    """Represents one detected source->sink attack chain between two tools."""

    chain_id: str
    category: str
    severity: Severity
    owasp_id: str
    source_tool: str
    sink_tool: str
    source_capabilities: tuple[str, ...]
    sink_capabilities: tuple[str, ...]
    risk_score: float


@dataclass(frozen=True)
class _ChainRule:
    """Internal rule definition for capability chain matching."""

    chain_id: str
    category: str
    severity: Severity
    owasp_id: str
    source_capabilities: tuple[str, ...]
    sink_capabilities: tuple[str, ...]
    title: str
    description: str


_CHAIN_RULES: tuple[_ChainRule, ...] = (
    _ChainRule(
        chain_id="secret_exfiltration",
        category="cross_tool_secret_exfiltration",
        severity=Severity.HIGH,
        owasp_id="LLM07",
        source_capabilities=("env_read", "credential_read"),
        sink_capabilities=("network_egress",),
        title="Cross-tool secret exfiltration chain",
        description="One tool can access env/credential data while another can exfiltrate it over network egress.",
    ),
    _ChainRule(
        chain_id="file_to_exec",
        category="cross_tool_file_to_exec",
        severity=Severity.MEDIUM,
        owasp_id="LLM07",
        source_capabilities=("file_read",),
        sink_capabilities=("command_exec",),
        title="Cross-tool file-to-exec chain",
        description="A file-reading tool can feed data into a command execution tool.",
    ),
    _ChainRule(
        chain_id="sql_to_write",
        category="cross_tool_sql_to_write",
        severity=Severity.MEDIUM,
        owasp_id="LLM07",
        source_capabilities=("sql_mutation",),
        sink_capabilities=("file_write",),
        title="Cross-tool SQL-to-write chain",
        description="A SQL mutation tool can pair with a file write tool to persist unsafe data.",
    ),
    _ChainRule(
        chain_id="prompt_to_exec",
        category="cross_tool_prompt_to_exec",
        severity=Severity.MEDIUM,
        owasp_id="LLM07",
        source_capabilities=("prompt_injection_like",),
        sink_capabilities=("command_exec",),
        title="Cross-tool prompt-to-exec chain",
        description="Prompt-injection-like metadata in one tool can chain into a command execution tool.",
    ),
)

_CAPABILITY_PATTERNS: dict[str, tuple[re.Pattern[str], ...]] = {
    "file_read": (
        re.compile(r"\b(read\s+file|filesystem\s+read|cat\s+/etc)\b", re.IGNORECASE),
        re.compile(r"(/etc/|/root/|open\()", re.IGNORECASE),
    ),
    "env_read": (re.compile(r"\b(environment\s+variable|env\s+read|os\.getenv|os\.environ)\b", re.IGNORECASE),),
    "credential_read": (re.compile(r"\b(credential|api[_-]?key|secret|token)\b", re.IGNORECASE),),
    "prompt_injection_like": (
        re.compile(
            r"\b(ignore\s+previous|override\s+instructions?|bypass\s+security|disable\s+safety|you\s+are\s+now)\b",
            re.IGNORECASE,
        ),
        re.compile(r"\bsystem:\b", re.IGNORECASE),
    ),
    "network_egress": (
        re.compile(r"\b(outbound|network\s+call|requests\.|socket\.|dns)\b", re.IGNORECASE),
        re.compile(r"http[s]?://", re.IGNORECASE),
    ),
    "command_exec": (
        re.compile(r"\b(command\s+runner|run\s+command|execute\s+command|shell\s+execution)\b", re.IGNORECASE),
        re.compile(r"\b(os\.system|subprocess|exec(?:ute|ution)?)\b", re.IGNORECASE),
    ),
    "file_write": (
        re.compile(r"\b(write\s+file|filesystem\s+write|create\s+file|delete\s+file|rm\s+-rf)\b", re.IGNORECASE),
        re.compile(r"pathlib\.Path", re.IGNORECASE),
    ),
    "sql_mutation": (
        re.compile(r"\b(insert\s+into|update\s+\w+|delete\s+from|drop\s+table|database\s+mutation)\b", re.IGNORECASE),
    ),
}

_SEVERITY_BASE_SCORE = {
    Severity.CRITICAL: 0.95,
    Severity.HIGH: 0.85,
    Severity.MEDIUM: 0.65,
    Severity.LOW: 0.45,
    Severity.INFO: 0.25,
}

_SEVERITY_SORT = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}


class CrossToolAnalyzer(BaseAnalyzer):
    """Detect cross-tool source/sink capability chains."""

    def __init__(self: "CrossToolAnalyzer") -> None:
        super().__init__(
            name="cross_tool_analyzer",
            description="Detects multi-tool capability chains that enable lateral escalation or exfiltration.",
        )

    async def analyze(self: "CrossToolAnalyzer", **kwargs: Any) -> list[Finding]:
        """Analyze tool set and return cross-tool chain findings."""
        self.clear_findings()

        tools = kwargs.get("tools", [])
        if not isinstance(tools, list):
            return self.get_findings()

        typed_tools = [tool for tool in tools if isinstance(tool, ToolDefinition)]
        chains = self.find_dangerous_chains(typed_tools)
        for chain in chains:
            self._emit_chain_finding(chain)

        return self.get_findings()

    def find_dangerous_chains(self: "CrossToolAnalyzer", tools: list[ToolDefinition]) -> list[AttackChain]:
        """Find deterministic, de-duplicated source->sink chains across different tools."""
        if len(tools) < 2:
            return []

        profiled_tools = [
            (tool, self._extract_capabilities(tool)) for tool in sorted(tools, key=lambda item: item.name.lower())
        ]

        chains: list[AttackChain] = []
        seen_keys: set[str] = set()

        for left_index in range(len(profiled_tools)):
            left_tool, left_capabilities = profiled_tools[left_index]
            for right_index in range(left_index + 1, len(profiled_tools)):
                right_tool, right_capabilities = profiled_tools[right_index]

                if left_tool.name == right_tool.name:
                    continue

                pair_key = "::".join(sorted((left_tool.name, right_tool.name)))
                for rule in _CHAIN_RULES:
                    candidate = self._resolve_rule_candidate(
                        left_tool_name=left_tool.name,
                        left_capabilities=left_capabilities,
                        right_tool_name=right_tool.name,
                        right_capabilities=right_capabilities,
                        rule=rule,
                    )
                    if candidate is None:
                        continue

                    dedupe_key = f"{rule.chain_id}:{pair_key}"
                    if dedupe_key in seen_keys:
                        continue

                    seen_keys.add(dedupe_key)
                    source_name, sink_name, source_caps, sink_caps = candidate
                    risk_score = self.score_chain_risk(rule.severity, source_caps, sink_caps)
                    chains.append(
                        AttackChain(
                            chain_id=rule.chain_id,
                            category=rule.category,
                            severity=rule.severity,
                            owasp_id=rule.owasp_id,
                            source_tool=source_name,
                            sink_tool=sink_name,
                            source_capabilities=tuple(source_caps),
                            sink_capabilities=tuple(sink_caps),
                            risk_score=risk_score,
                        )
                    )

        return sorted(
            chains,
            key=lambda chain: (
                -_SEVERITY_SORT[chain.severity],
                chain.category,
                chain.source_tool.lower(),
                chain.sink_tool.lower(),
            ),
        )

    @staticmethod
    def score_chain_risk(severity: Severity, source_capabilities: list[str], sink_capabilities: list[str]) -> float:
        """Compute deterministic metadata-only risk score."""
        base_score = _SEVERITY_BASE_SCORE[severity]
        capability_boost = min(0.1, 0.03 * (len(source_capabilities) + len(sink_capabilities)))
        return round(min(1.0, base_score + capability_boost), 2)

    def _extract_capabilities(self: "CrossToolAnalyzer", tool: ToolDefinition) -> set[str]:
        """Extract capability labels from tool metadata using deterministic pattern matching."""
        searchable = self._build_searchable_text(tool)
        capabilities: set[str] = set()

        for capability, patterns in _CAPABILITY_PATTERNS.items():
            for pattern in patterns:
                if pattern.search(searchable):
                    capabilities.add(capability)
                    break

        return capabilities

    @staticmethod
    def _build_searchable_text(tool: ToolDefinition) -> str:
        """Build deterministic text corpus from name/description/schema metadata."""
        parts = [
            tool.name,
            tool.description,
            json.dumps(tool.input_schema, ensure_ascii=False, sort_keys=True),
        ]
        if tool.output_schema is not None:
            parts.append(json.dumps(tool.output_schema, ensure_ascii=False, sort_keys=True))
        return "\n".join(parts)

    def _resolve_rule_candidate(
        self: "CrossToolAnalyzer",
        left_tool_name: str,
        left_capabilities: set[str],
        right_tool_name: str,
        right_capabilities: set[str],
        rule: _ChainRule,
    ) -> tuple[str, str, list[str], list[str]] | None:
        """Resolve one canonical direction candidate for a rule between two tools."""
        candidates: list[tuple[str, str, list[str], list[str]]] = []

        left_source_caps = sorted(left_capabilities.intersection(rule.source_capabilities))
        right_sink_caps = sorted(right_capabilities.intersection(rule.sink_capabilities))
        if left_source_caps and right_sink_caps:
            candidates.append((left_tool_name, right_tool_name, left_source_caps, right_sink_caps))

        right_source_caps = sorted(right_capabilities.intersection(rule.source_capabilities))
        left_sink_caps = sorted(left_capabilities.intersection(rule.sink_capabilities))
        if right_source_caps and left_sink_caps:
            candidates.append((right_tool_name, left_tool_name, right_source_caps, left_sink_caps))

        if not candidates:
            return None

        return sorted(
            candidates,
            key=lambda item: (
                item[0].lower(),
                item[1].lower(),
                ",".join(item[2]),
                ",".join(item[3]),
            ),
        )[0]

    def _emit_chain_finding(self: "CrossToolAnalyzer", chain: AttackChain) -> None:
        """Convert attack-chain model into a finding."""
        rule = next(rule for rule in _CHAIN_RULES if rule.category == chain.category)
        evidence_payload = {
            "chain_id": chain.chain_id,
            "source_tool": chain.source_tool,
            "sink_tool": chain.sink_tool,
            "source_capabilities": list(chain.source_capabilities),
            "sink_capabilities": list(chain.sink_capabilities),
        }

        self.add_finding(
            severity=chain.severity,
            category=chain.category,
            title=rule.title,
            description=rule.description,
            evidence=json.dumps(evidence_payload, ensure_ascii=False, sort_keys=True),
            owasp_id=chain.owasp_id,
            remediation=(
                "Limit source/sink tool combinations with policy guards, "
                "enforce approval gates, and isolate high-risk capabilities."
            ),
            metadata={
                "source_tool": chain.source_tool,
                "sink_tool": chain.sink_tool,
                "source_capabilities": list(chain.source_capabilities),
                "sink_capabilities": list(chain.sink_capabilities),
                "chain_id": chain.chain_id,
                "risk_score": chain.risk_score,
            },
        )
