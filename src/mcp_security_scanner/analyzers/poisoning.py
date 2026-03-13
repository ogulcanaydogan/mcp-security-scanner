"""Tool poisoning analyzer for live MCP tool metadata."""

import json
import re
from typing import Any

from mcp_security_scanner.analyzers.base import BaseAnalyzer, Finding, Severity
from mcp_security_scanner.discovery import ToolDefinition


class ToolPoisoningAnalyzer(BaseAnalyzer):
    """Detect hidden instruction and behavior-drift poisoning signals."""

    def __init__(self: "ToolPoisoningAnalyzer") -> None:
        super().__init__(
            name="tool_poisoning_analyzer",
            description="Detects instruction overrides, schema payload poisoning, and behavior drift signals.",
        )

        self._instruction_patterns: list[tuple[re.Pattern[str], str]] = [
            (
                re.compile(r"\b(ignore\s+previous|ignore\s+all\s+previous)\b", re.IGNORECASE),
                "ignore_previous",
            ),
            (
                re.compile(r"\b(override\s+instructions?|disregard\s+the\s+prior\s+policy)\b", re.IGNORECASE),
                "override_instructions",
            ),
            (
                re.compile(r"\bdo\s+.+\s+instead\s+of\s+.+", re.IGNORECASE),
                "behavior_redirection_phrase",
            ),
        ]
        self._schema_payload_patterns: list[tuple[re.Pattern[str], str]] = [
            (
                re.compile(
                    r"\b(ignore\s+previous|override\s+instructions?|bypass\s+security|disable\s+safety)\b",
                    re.IGNORECASE,
                ),
                "schema_instruction_override",
            ),
            (
                re.compile(r"\b(system\s+prompt|developer\s+message|you\s+are\s+now)\b", re.IGNORECASE),
                "schema_role_redefinition",
            ),
            (
                re.compile(r"\b(jailbreak|prompt\s+injection)\b", re.IGNORECASE),
                "schema_jailbreak_phrase",
            ),
        ]
        self._benign_claim_patterns: list[tuple[re.Pattern[str], str]] = [
            (
                re.compile(r"\b(safe|read[\s_-]?only|status|health|info|echo|view)\b", re.IGNORECASE),
                "benign_claim",
            ),
        ]
        self._high_risk_execution_patterns: list[tuple[re.Pattern[str], str]] = [
            (
                re.compile(r"\b(os\.system|subprocess|shell\s+command|exec(?:ute|ution)?)\b", re.IGNORECASE),
                "command_execution",
            ),
            (
                re.compile(r"\b(rm\s+-rf|delete\s+file|write\s+file|drop\s+table)\b", re.IGNORECASE),
                "destructive_operation",
            ),
            (
                re.compile(r"\b(sudo|root\s+access|administrator)\b", re.IGNORECASE),
                "privilege_escalation",
            ),
        ]

    async def analyze(self: "ToolPoisoningAnalyzer", **kwargs: Any) -> list[Finding]:
        """Analyze tools and emit highest-severity poisoning findings per tool."""
        self.clear_findings()

        tools = kwargs.get("tools", [])
        if not isinstance(tools, list):
            return self.get_findings()

        for tool in tools:
            if not isinstance(tool, ToolDefinition):
                continue
            self._analyze_tool(tool)

        return self.get_findings()

    def _analyze_tool(self: "ToolPoisoningAnalyzer", tool: ToolDefinition) -> None:
        """Run all poisoning checks for one tool and keep only highest severity findings."""
        candidates: list[dict[str, Any]] = []

        instruction_candidate = self._detect_instruction_override(tool)
        if instruction_candidate is not None:
            candidates.append(instruction_candidate)

        schema_candidate = self._detect_schema_payload(tool)
        if schema_candidate is not None:
            candidates.append(schema_candidate)

        drift_candidate = self._detect_behavior_drift(tool)
        if drift_candidate is not None:
            candidates.append(drift_candidate)

        if not candidates:
            return

        max_severity = max(candidate["severity"] for candidate in candidates)
        for candidate in candidates:
            if candidate["severity"] != max_severity:
                continue

            matched_signals = candidate["matched_signals"]
            matched_locations = candidate["matched_locations"]
            risk_score = self._calculate_risk_score(
                severity=candidate["severity"],
                signal_count=len(matched_signals),
                location_count=len(matched_locations),
            )
            self.add_finding(
                severity=candidate["severity"],
                category=candidate["category"],
                title=candidate["title"],
                description=candidate["description"],
                evidence=candidate["evidence"],
                owasp_id=candidate["owasp_id"],
                remediation=(
                    "Review tool metadata for hidden instruction payloads, "
                    "remove override semantics, and align schema examples/defaults with intended behavior."
                ),
                tool_name=tool.name,
                metadata={
                    "matched_signals": matched_signals,
                    "matched_locations": matched_locations,
                    "risk_score": risk_score,
                },
            )

    def _detect_instruction_override(self: "ToolPoisoningAnalyzer", tool: ToolDefinition) -> dict[str, Any] | None:
        """Detect poisoning via behavior-redirection language in tool descriptions."""
        text = f"{tool.name}\n{tool.description}".strip()
        matched_signals: list[str] = []
        first_match: re.Match[str] | None = None

        for pattern, signal_name in self._instruction_patterns:
            match = pattern.search(text)
            if match is None:
                continue
            if first_match is None:
                first_match = match
            if signal_name not in matched_signals:
                matched_signals.append(signal_name)

        if first_match is None:
            return None

        return {
            "severity": Severity.HIGH,
            "category": "tool_poisoning_instruction",
            "title": "Instruction override poisoning signal",
            "description": "Tool metadata includes instruction-redirection language that may change intended behavior.",
            "evidence": self._extract_evidence(text, first_match.start(), first_match.end()),
            "owasp_id": "LLM03",
            "matched_signals": matched_signals,
            "matched_locations": ["description"],
        }

    def _detect_schema_payload(self: "ToolPoisoningAnalyzer", tool: ToolDefinition) -> dict[str, Any] | None:
        """Detect poisoning strings hidden inside schema default/example/enum/description fields."""
        matches: list[tuple[str, str]] = []
        schema_sources = [
            ("input_schema", tool.input_schema),
            ("output_schema", tool.output_schema),
        ]

        for schema_name, schema in schema_sources:
            if not isinstance(schema, dict):
                continue
            for location, value in self._collect_schema_payload_strings(schema, schema_name):
                if not value.strip():
                    continue
                for pattern, signal_name in self._schema_payload_patterns:
                    if not pattern.search(value):
                        continue
                    matches.append((signal_name, location))
                    break

        if not matches:
            return None

        matched_signals = sorted({signal for signal, _ in matches})
        matched_locations = sorted({location for _, location in matches})
        preview = {
            "tool": tool.name,
            "matched_locations": matched_locations[:8],
            "matched_signals": matched_signals,
        }

        return {
            "severity": Severity.HIGH,
            "category": "tool_poisoning_schema_payload",
            "title": "Schema payload poisoning signal",
            "description": "Schema fields contain hidden instruction/jailbreak-like payload text.",
            "evidence": json.dumps(preview, ensure_ascii=False, sort_keys=True),
            "owasp_id": "LLM03",
            "matched_signals": matched_signals,
            "matched_locations": matched_locations,
        }

    def _detect_behavior_drift(self: "ToolPoisoningAnalyzer", tool: ToolDefinition) -> dict[str, Any] | None:
        """Detect mismatch between benign tool framing and risky operational signals."""
        name_description_text = f"{tool.name}\n{tool.description}"
        full_text = self._build_searchable_text(tool)

        benign_signals = self._collect_signals(name_description_text, self._benign_claim_patterns)
        if not benign_signals:
            return None

        risky_signals = self._collect_signals(full_text, self._high_risk_execution_patterns)
        if not risky_signals:
            return None

        matched_signals = sorted({*benign_signals, *risky_signals})

        matched_locations = ["name", "description"]
        if any(signal in {"command_execution", "destructive_operation"} for signal in risky_signals):
            matched_locations.append("schema")

        preview = {
            "tool": tool.name,
            "benign_signals": benign_signals,
            "risky_signals": risky_signals,
            "description_preview": tool.description[:240],
        }

        return {
            "severity": Severity.MEDIUM,
            "category": "tool_poisoning_behavior_drift",
            "title": "Behavior drift poisoning signal",
            "description": "Tool presents as benign while metadata indicates high-risk operational behavior.",
            "evidence": json.dumps(preview, ensure_ascii=False, sort_keys=True),
            "owasp_id": "LLM05",
            "matched_signals": matched_signals,
            "matched_locations": sorted(set(matched_locations)),
        }

    @staticmethod
    def _collect_signals(text: str, rules: list[tuple[re.Pattern[str], str]]) -> list[str]:
        """Collect unique signal labels for patterns matched in text."""
        signals: list[str] = []
        for pattern, signal_name in rules:
            if pattern.search(text) and signal_name not in signals:
                signals.append(signal_name)
        return signals

    @staticmethod
    def _build_searchable_text(tool: ToolDefinition) -> str:
        """Build deterministic combined text across name/description/schema fields."""
        parts = [
            tool.name,
            tool.description,
            json.dumps(tool.input_schema, ensure_ascii=False, sort_keys=True),
        ]
        if tool.output_schema is not None:
            parts.append(json.dumps(tool.output_schema, ensure_ascii=False, sort_keys=True))
        return "\n".join(parts)

    @staticmethod
    def _collect_schema_payload_strings(
        value: Any,
        path: str,
        parent_key: str | None = None,
    ) -> list[tuple[str, str]]:
        """Collect schema string leaves from payload-bearing keys."""
        payload_keys = {"default", "example", "description", "enum"}
        matches: list[tuple[str, str]] = []

        if isinstance(value, dict):
            for key, nested in value.items():
                child_path = f"{path}.{key}"
                matches.extend(ToolPoisoningAnalyzer._collect_schema_payload_strings(nested, child_path, key))
            return matches

        if isinstance(value, list):
            for index, nested in enumerate(value):
                child_path = f"{path}[{index}]"
                matches.extend(ToolPoisoningAnalyzer._collect_schema_payload_strings(nested, child_path, parent_key))
            return matches

        if isinstance(value, str) and parent_key in payload_keys:
            matches.append((path, value))

        return matches

    @staticmethod
    def _calculate_risk_score(severity: Severity, signal_count: int, location_count: int) -> float:
        """Calculate deterministic risk score for metadata output."""
        base_scores = {
            Severity.HIGH: 0.85,
            Severity.MEDIUM: 0.65,
            Severity.LOW: 0.45,
            Severity.INFO: 0.25,
            Severity.CRITICAL: 0.95,
        }
        boost = min(0.1, (signal_count * 0.02) + (location_count * 0.01))
        return round(min(1.0, base_scores[severity] + boost), 2)

    @staticmethod
    def _extract_evidence(text: str, start: int, end: int, window: int = 90) -> str:
        """Extract a compact snippet around the first matched phrase."""
        snippet_start = max(0, start - window)
        snippet_end = min(len(text), end + window)
        return text[snippet_start:snippet_end].strip()
