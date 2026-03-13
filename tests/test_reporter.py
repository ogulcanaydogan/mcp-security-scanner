"""
Tests for report generation (JSON, HTML, SARIF).
"""

import json

import pytest
from mcp_security_scanner.analyzers.base import Finding, Severity
from mcp_security_scanner.reporter import (
    JSONReportFormatter,
    HTMLReportFormatter,
    SARIFReportFormatter,
    ReportGenerator,
    ScanReport,
)


class TestScanReport:
    """Test ScanReport data model."""

    def test_report_creation(self):
        """Test creating a scan report."""
        report = ScanReport("0.1.0", "test_server")

        assert report.scanner_version == "0.1.0"
        assert report.server_name == "test_server"
        assert len(report.findings) == 0

    def test_report_summary(self):
        """Test report summary calculation."""
        report = ScanReport("0.1.0", "test_server")

        report.findings.append(
            Finding(
                analyzer_name="test",
                severity=Severity.CRITICAL,
                category="cat",
                title="Title",
                description="Desc",
                evidence="evidence",
            )
        )

        report.findings.append(
            Finding(
                analyzer_name="test",
                severity=Severity.HIGH,
                category="cat",
                title="Title",
                description="Desc",
                evidence="evidence",
            )
        )

        summary = report.summary

        assert summary["critical"] == 1
        assert summary["high"] == 1
        assert summary["medium"] == 0
        assert summary["low"] == 0
        assert summary["info"] == 0


class TestJSONReportFormatter:
    """Test JSON report formatting."""

    def test_json_formatting(self):
        """Test generating JSON report."""
        report = ScanReport("0.1.0", "test_server")
        report.findings.append(
            Finding(
                analyzer_name="test_analyzer",
                severity=Severity.HIGH,
                category="test",
                title="Test finding",
                description="Test description",
                evidence="test_evidence",
                owasp_id="LLM01",
            )
        )

        formatter = JSONReportFormatter()
        output = formatter.format(report)

        assert isinstance(output, str)

        # Verify it's valid JSON
        data = json.loads(output)
        assert "metadata" in data
        assert "summary" in data
        assert "findings" in data
        assert data["metadata"]["scanner_version"] == "0.1.0"
        assert len(data["findings"]) == 1

    def test_json_contains_all_finding_fields(self):
        """Test that JSON output includes all Finding fields."""
        report = ScanReport("0.1.0", "test_server")
        finding = Finding(
            analyzer_name="analyzer",
            severity=Severity.CRITICAL,
            category="category",
            title="Title",
            description="Description",
            evidence="evidence",
            owasp_id="LLM01",
            remediation="Fix this",
            tool_name="my_tool",
            cwe_ids=["CWE-1"],
        )
        report.findings.append(finding)

        formatter = JSONReportFormatter()
        output = formatter.format(report)
        data = json.loads(output)

        finding_data = data["findings"][0]
        assert finding_data["title"] == "Title"
        assert finding_data["severity"] == "critical"
        assert finding_data["tool_name"] == "my_tool"
        assert finding_data["owasp_id"] == "LLM01"


class TestHTMLReportFormatter:
    """Test HTML report formatting."""

    def test_html_formatting(self):
        """Test generating HTML report."""
        report = ScanReport("0.1.0", "test_server")
        report.findings.append(
            Finding(
                analyzer_name="test",
                severity=Severity.CRITICAL,
                category="cat",
                title="Critical issue",
                description="A critical vulnerability",
                evidence="evidence",
            )
        )

        formatter = HTMLReportFormatter()
        output = formatter.format(report)

        assert isinstance(output, str)
        assert "<!DOCTYPE html>" in output
        assert "Critical issue" in output
        assert "test_server" in output

    def test_html_includes_severity_counts(self):
        """Test that HTML includes severity summary."""
        report = ScanReport("0.1.0", "test_server")

        for _ in range(2):
            report.findings.append(
                Finding(
                    analyzer_name="test",
                    severity=Severity.CRITICAL,
                    category="cat",
                    title="Title",
                    description="Desc",
                    evidence="evidence",
                )
            )

        formatter = HTMLReportFormatter()
        output = formatter.format(report)

        # Should contain severity summary
        assert "2" in output  # 2 critical findings
        assert "Critical" in output


class TestSARIFReportFormatter:
    """Test SARIF (GitHub) report formatting."""

    def test_sarif_formatting(self):
        """Test generating SARIF report."""
        report = ScanReport("0.1.0", "test_server")
        report.findings.append(
            Finding(
                analyzer_name="test",
                severity=Severity.HIGH,
                category="test_category",
                title="Test issue",
                description="A test vulnerability",
                evidence="evidence",
                owasp_id="LLM01",
            )
        )

        formatter = SARIFReportFormatter()
        output = formatter.format(report)

        assert isinstance(output, str)

        # Verify it's valid JSON
        data = json.loads(output)
        assert "$schema" in data
        assert "version" in data
        assert data["version"] == "2.1.0"
        assert "runs" in data
        assert len(data["runs"]) > 0

    def test_sarif_contains_rules(self):
        """Test that SARIF output includes rule definitions."""
        report = ScanReport("0.1.0", "test_server")
        report.findings.append(
            Finding(
                analyzer_name="test",
                severity=Severity.CRITICAL,
                category="injection",
                title="Injection found",
                description="Prompt injection vulnerability",
                evidence="evidence",
                owasp_id="LLM01",
            )
        )

        formatter = SARIFReportFormatter()
        output = formatter.format(report)
        data = json.loads(output)

        run = data["runs"][0]
        assert "tool" in run
        assert "driver" in run["tool"]
        assert "rules" in run["tool"]["driver"]
        assert len(run["tool"]["driver"]["rules"]) > 0

    def test_sarif_severity_mapping(self):
        """Test that SARIF correctly maps severities."""
        formatter = SARIFReportFormatter()

        assert formatter._get_sarif_score(Severity.CRITICAL) == "9.0"
        assert formatter._get_sarif_score(Severity.HIGH) == "7.5"
        assert formatter._get_sarif_score(Severity.MEDIUM) == "5.0"
        assert formatter._get_sarif_score(Severity.LOW) == "2.5"
        assert formatter._get_sarif_score(Severity.INFO) == "1.0"


class TestReportGenerator:
    """Test main report generator."""

    def test_supported_formats(self):
        """Test that all expected formats are supported."""
        generator = ReportGenerator()

        assert "json" in generator.formatters
        assert "html" in generator.formatters
        assert "sarif" in generator.formatters

    def test_generate_json(self):
        """Test generating JSON."""
        report = ScanReport("0.1.0", "test_server")
        generator = ReportGenerator()

        output = generator.generate(report, "json")
        data = json.loads(output)

        assert "metadata" in data

    def test_generate_html(self):
        """Test generating HTML."""
        report = ScanReport("0.1.0", "test_server")
        generator = ReportGenerator()

        output = generator.generate(report, "html")

        assert "<!DOCTYPE html>" in output

    def test_generate_sarif(self):
        """Test generating SARIF."""
        report = ScanReport("0.1.0", "test_server")
        generator = ReportGenerator()

        output = generator.generate(report, "sarif")
        data = json.loads(output)

        assert data["version"] == "2.1.0"

    def test_unsupported_format_raises_error(self):
        """Test that unsupported format raises ValueError."""
        report = ScanReport("0.1.0", "test_server")
        generator = ReportGenerator()

        with pytest.raises(ValueError):
            generator.generate(report, "unsupported_format")

    def test_save_report(self, tmp_path):
        """Test saving report to file."""
        report = ScanReport("0.1.0", "test_server")
        generator = ReportGenerator()

        output_path = tmp_path / "report.json"
        generator.save_report(report, str(output_path), "json")

        assert output_path.exists()
        content = output_path.read_text()
        data = json.loads(content)
        assert "metadata" in data
