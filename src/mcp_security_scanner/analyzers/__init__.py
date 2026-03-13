"""
Analyzers package for MCP security scanning.

Contains specialized analyzers for:
- Static analysis (pattern matching in descriptions)
- Dynamic analysis (runtime behavior testing)
- Prompt injection detection
- Tool poisoning / rug-pull detection
- Capability escalation assessment
- Cross-tool attack chains
"""

from mcp_security_scanner.analyzers.base import BaseAnalyzer, Finding, Severity
from mcp_security_scanner.analyzers.injection import PromptInjectionAnalyzer
from mcp_security_scanner.analyzers.static import StaticAnalyzer

__all__ = [
    "BaseAnalyzer",
    "Finding",
    "Severity",
    "PromptInjectionAnalyzer",
    "StaticAnalyzer",
]
