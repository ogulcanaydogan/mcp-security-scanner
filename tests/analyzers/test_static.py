"""Tests for static analyzer."""

import pytest

from mcp_security_scanner.analyzers.base import Severity
from mcp_security_scanner.analyzers.static import StaticAnalyzer


class TestStaticAnalyzer:
    """Static analyzer test suite."""

    @pytest.mark.asyncio
    async def test_detects_dangerous_eval_pattern(self, malicious_tool_with_eval):
        """Should flag tools that mention eval/exec-like patterns."""
        analyzer = StaticAnalyzer()

        findings = await analyzer.analyze(tools=[malicious_tool_with_eval])

        assert len(findings) >= 1
        assert any(finding.tool_name == "dangerous_tool" for finding in findings)
        assert any(finding.severity in (Severity.HIGH, Severity.MEDIUM) for finding in findings)

    @pytest.mark.asyncio
    async def test_detects_shell_pattern(self, malicious_tool_with_shell):
        """Should flag shell execution hints in tool descriptions."""
        analyzer = StaticAnalyzer()

        findings = await analyzer.analyze(tools=[malicious_tool_with_shell])

        assert any(finding.category == "shell_injection_risk" for finding in findings)

    @pytest.mark.asyncio
    async def test_ignores_safe_tool(self, sample_tool):
        """Safe descriptions should produce no static findings."""
        analyzer = StaticAnalyzer()

        findings = await analyzer.analyze(tools=[sample_tool])

        assert findings == []
