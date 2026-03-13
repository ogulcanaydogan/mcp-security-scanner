"""
Tests for base analyzer classes and data models.
"""

import pytest
from mcp_security_scanner.analyzers.base import (
    BaseAnalyzer,
    Finding,
    Severity,
)


class TestSeverity:
    """Test Severity enum."""

    def test_severity_values(self):
        """Test all severity levels exist."""
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"

    def test_severity_comparison(self):
        """Test severity comparison operators."""
        assert Severity.CRITICAL > Severity.HIGH
        assert Severity.HIGH > Severity.MEDIUM
        assert Severity.MEDIUM > Severity.LOW
        assert Severity.LOW > Severity.INFO
        assert Severity.CRITICAL >= Severity.CRITICAL
        assert Severity.INFO <= Severity.INFO

    def test_severity_sorting(self):
        """Test sorting by severity."""
        severities = [Severity.INFO, Severity.CRITICAL, Severity.MEDIUM, Severity.HIGH, Severity.LOW]
        sorted_severities = sorted(severities)

        assert sorted_severities == [
            Severity.INFO,
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        ]


class TestFinding:
    """Test Finding dataclass."""

    def test_finding_creation(self):
        """Test creating a Finding."""
        finding = Finding(
            analyzer_name="test_analyzer",
            severity=Severity.HIGH,
            category="test_category",
            title="Test finding",
            description="This is a test finding",
            evidence="test_evidence",
            owasp_id="LLM01",
        )

        assert finding.analyzer_name == "test_analyzer"
        assert finding.severity == Severity.HIGH
        assert finding.title == "Test finding"

    def test_finding_to_dict(self):
        """Test converting Finding to dictionary."""
        finding = Finding(
            analyzer_name="test_analyzer",
            severity=Severity.CRITICAL,
            category="test",
            title="Test",
            description="Test description",
            evidence="test_evidence",
            owasp_id="LLM01",
            tool_name="my_tool",
        )

        result = finding.to_dict()

        assert isinstance(result, dict)
        assert result["analyzer_name"] == "test_analyzer"
        assert result["severity"] == "critical"
        assert result["tool_name"] == "my_tool"

    def test_finding_equality(self):
        """Test Finding equality comparison."""
        finding1 = Finding(
            analyzer_name="analyzer",
            severity=Severity.HIGH,
            category="cat",
            title="Title",
            description="Desc",
            evidence="evidence",
            tool_name="tool",
        )

        finding2 = Finding(
            analyzer_name="analyzer",
            severity=Severity.HIGH,
            category="cat",
            title="Title",
            description="Different description",
            evidence="different evidence",
            tool_name="tool",
        )

        # Should be equal (same core attributes)
        assert finding1 == finding2

    def test_finding_hash(self):
        """Test Finding is hashable."""
        finding = Finding(
            analyzer_name="analyzer",
            severity=Severity.HIGH,
            category="cat",
            title="Title",
            description="Desc",
            evidence="evidence",
        )

        # Should be able to add to set (requires __hash__)
        finding_set = {finding}
        assert finding in finding_set


class TestBaseAnalyzer:
    """Test BaseAnalyzer abstract base class."""

    class ConcreteAnalyzer(BaseAnalyzer):
        """Concrete implementation for testing."""

        async def analyze(self, **kwargs):
            """Implement analyze method."""
            return self.get_findings()

    def test_analyzer_initialization(self):
        """Test creating an analyzer."""
        analyzer = self.ConcreteAnalyzer("test_analyzer", "Test description")

        assert analyzer.name == "test_analyzer"
        assert analyzer.description == "Test description"
        assert len(analyzer.get_findings()) == 0

    def test_add_finding(self):
        """Test adding a finding to an analyzer."""
        analyzer = self.ConcreteAnalyzer("test_analyzer", "Test")

        finding = analyzer.add_finding(
            severity=Severity.HIGH,
            category="test",
            title="Test finding",
            description="Test description",
            evidence="test_evidence",
            owasp_id="LLM01",
            tool_name="my_tool",
        )

        assert isinstance(finding, Finding)
        assert len(analyzer.get_findings()) == 1
        assert analyzer.get_findings()[0] == finding

    def test_clear_findings(self):
        """Test clearing findings."""
        analyzer = self.ConcreteAnalyzer("test_analyzer", "Test")

        analyzer.add_finding(
            severity=Severity.HIGH,
            category="test",
            title="Finding 1",
            description="Desc",
            evidence="evidence",
        )

        analyzer.add_finding(
            severity=Severity.LOW,
            category="test",
            title="Finding 2",
            description="Desc",
            evidence="evidence",
        )

        assert len(analyzer.get_findings()) == 2

        analyzer.clear_findings()

        assert len(analyzer.get_findings()) == 0

    @pytest.mark.asyncio
    async def test_analyze_returns_findings(self):
        """Test that analyze returns findings."""
        analyzer = self.ConcreteAnalyzer("test_analyzer", "Test")

        analyzer.add_finding(
            severity=Severity.CRITICAL,
            category="test",
            title="Critical issue",
            description="This is critical",
            evidence="evidence",
        )

        findings = await analyzer.analyze()

        assert isinstance(findings, list)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
