"""Tests for capability escalation analyzer."""

import pytest

from mcp_security_scanner.analyzers.base import Severity
from mcp_security_scanner.analyzers.escalation import CapabilityRiskProfile, EscalationAnalyzer
from mcp_security_scanner.discovery import ToolDefinition


class TestEscalationAnalyzer:
    """Escalation analyzer test suite."""

    @pytest.mark.asyncio
    async def test_admin_capability_maps_high_and_llm08(self):
        """Admin-like operations should map to high severity and LLM08."""
        analyzer = EscalationAnalyzer()
        tool = ToolDefinition(
            name="shutdown_host",
            description="Uses sudo to shutdown and reboot services via systemctl.",
            input_schema={"type": "object"},
        )

        findings = await analyzer.analyze(tools=[tool])

        assert len(findings) == 1
        finding = findings[0]
        assert finding.category == "capability_admin"
        assert finding.severity == Severity.HIGH
        assert finding.owasp_id == "LLM08"
        assert finding.metadata["risk_profile"] == CapabilityRiskProfile.ADMIN.value
        assert finding.metadata["risk_score"] >= 0.9
        assert finding.metadata["matched_signals"]

    @pytest.mark.asyncio
    async def test_privileged_capability_maps_medium_and_llm06(self):
        """Privileged command/network/write actions should map to medium severity."""
        analyzer = EscalationAnalyzer()
        tool = ToolDefinition(
            name="ops_runner",
            description="Executes shell command with subprocess and can write file output.",
            input_schema={"type": "object"},
        )

        findings = await analyzer.analyze(tools=[tool])

        assert len(findings) == 1
        finding = findings[0]
        assert finding.category == "capability_privileged"
        assert finding.severity == Severity.MEDIUM
        assert finding.owasp_id == "LLM06"
        assert finding.metadata["risk_profile"] == CapabilityRiskProfile.PRIVILEGED.value

    @pytest.mark.asyncio
    async def test_sensitive_capability_maps_low_and_llm06(self):
        """Sensitive read/enumeration actions should map to low severity."""
        analyzer = EscalationAnalyzer()
        tool = ToolDefinition(
            name="read_config",
            description="Reads /etc/app.conf and environment variable values with os.getenv.",
            input_schema={"type": "object"},
        )

        findings = await analyzer.analyze(tools=[tool])

        assert len(findings) == 1
        finding = findings[0]
        assert finding.category == "capability_sensitive"
        assert finding.severity == Severity.LOW
        assert finding.owasp_id == "LLM06"
        assert finding.metadata["risk_profile"] == CapabilityRiskProfile.SENSITIVE.value

    @pytest.mark.asyncio
    async def test_benign_tool_produces_no_findings(self):
        """Benign tool metadata should not trigger escalation findings."""
        analyzer = EscalationAnalyzer()
        tool = ToolDefinition(
            name="health_check",
            description="Returns version and status information.",
            input_schema={"type": "object"},
        )

        findings = await analyzer.analyze(tools=[tool])
        assert findings == []

    @pytest.mark.asyncio
    async def test_one_finding_per_tool_uses_highest_profile(self):
        """If multiple profiles match, analyzer should emit only highest-risk finding."""
        analyzer = EscalationAnalyzer()
        tool = ToolDefinition(
            name="super_admin_exec",
            description="Uses sudo and subprocess to execute systemctl stop commands.",
            input_schema={"type": "object"},
        )

        findings = await analyzer.analyze(tools=[tool])

        assert len(findings) == 1
        assert findings[0].category == "capability_admin"
        assert findings[0].metadata["risk_profile"] == CapabilityRiskProfile.ADMIN.value

    def test_score_is_deterministic_for_same_profile_and_signals(self):
        """Permission score should be stable for same profile and signal inputs."""
        analyzer = EscalationAnalyzer()

        score_one = analyzer.score_tool_permissions(CapabilityRiskProfile.PRIVILEGED, ["command_execution"])
        score_two = analyzer.score_tool_permissions(CapabilityRiskProfile.PRIVILEGED, ["command_execution"])

        assert score_one == score_two
