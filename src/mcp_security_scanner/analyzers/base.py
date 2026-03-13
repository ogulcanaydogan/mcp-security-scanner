"""
Base classes and data models for security analyzers.

Defines the analyzer interface and Finding dataclass for all security checks.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

_SEVERITY_RANKS = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


class Severity(str, Enum):
    """Finding severity levels, aligned with CVSS/OWASP standards."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def _rank(self: "Severity") -> int:
        """Return a numeric rank for severity ordering."""
        return _SEVERITY_RANKS[self.value]

    def __lt__(self: "Severity", other: object) -> bool:
        """Allow severity comparison. CRITICAL > HIGH > MEDIUM > LOW > INFO."""
        if not isinstance(other, Severity):
            return NotImplemented
        return self._rank() < other._rank()

    def __le__(self: "Severity", other: object) -> bool:
        """Allow severity comparison."""
        if not isinstance(other, Severity):
            return NotImplemented
        return self._rank() <= other._rank()

    def __gt__(self: "Severity", other: object) -> bool:
        """Allow severity comparison."""
        if not isinstance(other, Severity):
            return NotImplemented
        return self._rank() > other._rank()

    def __ge__(self: "Severity", other: object) -> bool:
        """Allow severity comparison."""
        if not isinstance(other, Severity):
            return NotImplemented
        return self._rank() >= other._rank()


@dataclass
class Finding:
    """
    Represents a single security finding from an analyzer.

    Attributes:
        analyzer_name: Name of the analyzer that produced this finding.
        severity: How severe the finding is (CRITICAL to INFO).
        category: Type of issue (e.g., "prompt_injection", "tool_poisoning").
        title: Short human-readable title.
        description: Detailed explanation of the vulnerability.
        evidence: Code snippet or configuration that triggered the finding.
        owasp_id: OWASP LLM Top 10 category (e.g., "LLM01", "LLM05").
        remediation: Recommended fix or mitigation.
        tool_name: Name of the affected MCP tool (if applicable).
        resource_name: Name of the affected resource (if applicable).
        cwe_ids: CWE (Common Weakness Enumeration) identifiers, if applicable.
        references: URLs to relevant security resources.
        metadata: Additional context as key-value pairs (for custom data).
    """

    analyzer_name: str
    severity: Severity
    category: str
    title: str
    description: str
    evidence: str
    owasp_id: str = "LLM10"  # Default to Insecure Model Retrieval
    remediation: str = "Review and remediate according to OWASP guidance."
    tool_name: str | None = None
    resource_name: str | None = None
    cwe_ids: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __eq__(self: "Finding", other: object) -> bool:
        """Two findings are equal if they have the same core attributes."""
        if not isinstance(other, Finding):
            return NotImplemented
        return (
            self.analyzer_name == other.analyzer_name
            and self.severity == other.severity
            and self.category == other.category
            and self.title == other.title
            and self.tool_name == other.tool_name
        )

    def __hash__(self: "Finding") -> int:
        """Make Finding hashable (for deduplication)."""
        return hash((self.analyzer_name, self.severity, self.category, self.title, self.tool_name))

    def to_dict(self: "Finding") -> dict[str, Any]:
        """Convert Finding to dictionary for JSON serialization."""
        return {
            "analyzer_name": self.analyzer_name,
            "severity": self.severity.value,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "owasp_id": self.owasp_id,
            "remediation": self.remediation,
            "tool_name": self.tool_name,
            "resource_name": self.resource_name,
            "cwe_ids": self.cwe_ids,
            "references": self.references,
            "metadata": self.metadata,
        }


class BaseAnalyzer(ABC):
    """
    Abstract base class for all security analyzers.

    Subclasses implement specific detection logic for different attack types.
    """

    def __init__(self: "BaseAnalyzer", name: str, description: str) -> None:
        """
        Initialize the analyzer.

        Args:
            name: Unique identifier for this analyzer (e.g., "static_analysis").
            description: Human-readable description of what this analyzer detects.
        """
        self.name = name
        self.description = description
        self._findings: list[Finding] = []

    @abstractmethod
    async def analyze(self: "BaseAnalyzer", **kwargs: Any) -> list[Finding]:
        """
        Run the security analysis.

        Should be implemented by subclasses to perform specific checks.

        Args:
            **kwargs: Analyzer-specific parameters (e.g., tool definitions, payloads).

        Returns:
            List of Finding objects for any detected vulnerabilities.
        """
        pass

    def add_finding(
        self: "BaseAnalyzer",
        severity: Severity,
        category: str,
        title: str,
        description: str,
        evidence: str,
        owasp_id: str = "LLM10",
        remediation: str | None = None,
        tool_name: str | None = None,
        **kwargs: Any,
    ) -> Finding:
        """
        Create and register a security finding.

        Args:
            severity: Severity level of the finding.
            category: Category of the vulnerability.
            title: Short title.
            description: Detailed description.
            evidence: Code or config that triggered the finding.
            owasp_id: OWASP LLM Top 10 ID.
            remediation: Recommended fix.
            tool_name: Affected tool name (if applicable).
            **kwargs: Additional Finding attributes.

        Returns:
            The created Finding object.
        """
        finding = Finding(
            analyzer_name=self.name,
            severity=severity,
            category=category,
            title=title,
            description=description,
            evidence=evidence,
            owasp_id=owasp_id,
            remediation=remediation or "Review and address according to OWASP LLM guidance.",
            tool_name=tool_name,
            **kwargs,
        )
        self._findings.append(finding)
        return finding

    def get_findings(self: "BaseAnalyzer") -> list[Finding]:
        """Return all findings collected during analysis."""
        return self._findings

    def clear_findings(self: "BaseAnalyzer") -> None:
        """Clear all findings (useful between scans)."""
        self._findings.clear()
