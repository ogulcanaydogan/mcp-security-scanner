"""
Multi-format report generation for security scan results.

Generates JSON, HTML, and SARIF (GitHub-compatible) reports.
"""

import json
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcp_security_scanner.analyzers.base import Finding, Severity


class ScanReport:
    """
    Container for all scan results and metadata.

    Attributes:
        scanner_version: Version of the scanner that produced this report.
        scan_timestamp: When the scan was performed.
        server_name: Name of the scanned MCP server.
        findings: List of Finding objects.
        summary: Dictionary with counts (critical, high, medium, low, info).
    """

    def __init__(
        self: "ScanReport",
        scanner_version: str,
        server_name: str,
        findings: list[Finding] | None = None,
    ) -> None:
        """Initialize a scan report."""
        self.scanner_version = scanner_version
        self.scan_timestamp = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        self.server_name = server_name
        self.findings = findings or []

    @property
    def summary(self: "ScanReport") -> dict[str, int]:
        """Calculate severity summary."""
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in self.findings:
            summary[finding.severity.value] += 1
        return summary


class ReportFormatter(ABC):
    """Base class for report formatters."""

    @abstractmethod
    def format(self: "ReportFormatter", report: ScanReport) -> str:
        """
        Format a scan report.

        Args:
            report: ScanReport object to format.

        Returns:
            Formatted report as a string.
        """
        pass


class JSONReportFormatter(ReportFormatter):
    """Formats scan results as structured JSON."""

    def format(self: "JSONReportFormatter", report: ScanReport) -> str:
        """
        Generate JSON report.

        Args:
            report: ScanReport object.

        Returns:
            JSON string with findings, summary, and metadata.
        """
        output = {
            "metadata": {
                "scanner_version": report.scanner_version,
                "scan_timestamp": report.scan_timestamp,
                "server_name": report.server_name,
            },
            "summary": report.summary,
            "findings": [finding.to_dict() for finding in report.findings],
        }
        return json.dumps(output, indent=2)


class HTMLReportFormatter(ReportFormatter):
    """Formats scan results as an interactive HTML report."""

    def format(self: "HTMLReportFormatter", report: ScanReport) -> str:
        """
        Generate HTML report.

        Args:
            report: ScanReport object.

        Returns:
            HTML string with styled findings, filters, and OWASP mapping.
        """
        # TODO (Phase 3.1): Implement HTML generation with Jinja2
        # 1. Load template from src/mcp_security_scanner/templates/report.html
        # 2. Render with findings, summary, colors by severity
        # 3. Include JavaScript for filtering, sorting
        # 4. Return rendered HTML

        summary = report.summary
        critical_count = summary["critical"]
        high_count = summary["high"]
        medium_count = summary["medium"]
        low_count = summary["low"]
        info_count = summary["info"]

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>MCP Security Scan Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 20px; }}
        .header {{ background: #f5f5f5; padding: 20px; border-radius: 4px; }}
        .summary {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin: 20px 0; }}
        .severity-critical {{ background: #dc3545; color: white; padding: 10px; border-radius: 4px; text-align: center; font-weight: bold; }}
        .severity-high {{ background: #fd7e14; color: white; padding: 10px; border-radius: 4px; text-align: center; font-weight: bold; }}
        .severity-medium {{ background: #ffc107; color: black; padding: 10px; border-radius: 4px; text-align: center; font-weight: bold; }}
        .severity-low {{ background: #17a2b8; color: white; padding: 10px; border-radius: 4px; text-align: center; font-weight: bold; }}
        .severity-info {{ background: #6c757d; color: white; padding: 10px; border-radius: 4px; text-align: center; font-weight: bold; }}
        .finding {{ border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 4px; }}
        .finding-title {{ font-size: 16px; font-weight: bold; margin-bottom: 5px; }}
        .evidence {{ background: #f8f9fa; padding: 10px; border-radius: 4px; font-family: monospace; overflow-x: auto; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>MCP Security Scan Report</h1>
        <p><strong>Server:</strong> {report.server_name}</p>
        <p><strong>Scanned:</strong> {report.scan_timestamp}</p>
        <p><strong>Scanner:</strong> mcp-security-scanner {report.scanner_version}</p>
    </div>

    <div class="summary">
        <div class="severity-critical">Critical<br>{critical_count}</div>
        <div class="severity-high">High<br>{high_count}</div>
        <div class="severity-medium">Medium<br>{medium_count}</div>
        <div class="severity-low">Low<br>{low_count}</div>
        <div class="severity-info">Info<br>{info_count}</div>
    </div>

    <h2>Findings</h2>
"""

        for finding in report.findings:
            html += f"""    <div class="finding">
        <div class="finding-title">{finding.title}</div>
        <p><strong>Severity:</strong> {finding.severity.value} | <strong>Category:</strong> {finding.category} | <strong>OWASP:</strong> {finding.owasp_id}</p>
        <p>{finding.description}</p>
        <p><strong>Evidence:</strong></p>
        <div class="evidence">{finding.evidence}</div>
        <p><strong>Remediation:</strong> {finding.remediation}</p>
    </div>
"""

        html += """</body>
</html>"""
        return html


class SARIFReportFormatter(ReportFormatter):
    """Formats scan results as SARIF (GitHub-compatible format)."""

    def format(self: "SARIFReportFormatter", report: ScanReport) -> str:
        """
        Generate SARIF 2.1.0 report.

        Args:
            report: ScanReport object.

        Returns:
            SARIF JSON string compatible with GitHub Code Scanning.
        """
        # TODO (Phase 3.1): Implement SARIF 2.1.0 generation
        # 1. Map severity levels to SARIF levels (error, warning, note)
        # 2. Create rules for each finding category
        # 3. Create results array with file/line references if available
        # 4. Return valid SARIF JSON

        severity_to_sarif_level = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "note",
        }

        rules: dict[str, dict[str, Any]] = {}
        results: list[dict[str, Any]] = []

        for finding in report.findings:
            rule_id = f"{finding.category}_{finding.owasp_id}"
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.description},
                    "help": {"text": finding.remediation},
                    "defaultConfiguration": {
                        "level": severity_to_sarif_level[finding.severity],
                    },
                    "properties": {
                        "security-severity": self._get_sarif_score(finding.severity),
                    },
                }

            result: dict[str, Any] = {
                "ruleId": rule_id,
                "level": severity_to_sarif_level[finding.severity],
                "message": {"text": finding.description},
                "properties": {
                    "tool_name": finding.tool_name,
                    "owasp_id": finding.owasp_id,
                    "cwe_ids": finding.cwe_ids,
                },
            }

            results.append(result)

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "mcp-security-scanner",
                            "version": report.scanner_version,
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }

        return json.dumps(sarif, indent=2)

    @staticmethod
    def _get_sarif_score(severity: Severity) -> str:
        """Map severity to CVSS-style score for SARIF."""
        scores = {
            Severity.CRITICAL: "9.0",
            Severity.HIGH: "7.5",
            Severity.MEDIUM: "5.0",
            Severity.LOW: "2.5",
            Severity.INFO: "1.0",
        }
        return scores[severity]


class ReportGenerator:
    """Main report generation class."""

    def __init__(self: "ReportGenerator") -> None:
        """Initialize report generator."""
        self.formatters: dict[str, ReportFormatter] = {
            "json": JSONReportFormatter(),
            "html": HTMLReportFormatter(),
            "sarif": SARIFReportFormatter(),
        }

    def generate(
        self: "ReportGenerator",
        report: ScanReport,
        format: str,
    ) -> str:
        """
        Generate a report in the requested format.

        Args:
            report: ScanReport object.
            format: Output format (json, html, sarif).

        Returns:
            Formatted report as a string.

        Raises:
            ValueError: If format is not supported.
        """
        if format not in self.formatters:
            raise ValueError(f"Unsupported format: {format}. Supported: {list(self.formatters.keys())}")

        return self.formatters[format].format(report)

    def save_report(
        self: "ReportGenerator",
        report: ScanReport,
        path: str | Path,
        format: str,
    ) -> None:
        """
        Generate and save a report to a file.

        Args:
            report: ScanReport object.
            path: File path to save to.
            format: Output format.

        Raises:
            ValueError: If format is unsupported.
            IOError: If file write fails.
        """
        output = self.generate(report, format)
        Path(path).write_text(output)
