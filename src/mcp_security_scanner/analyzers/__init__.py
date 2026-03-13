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
from mcp_security_scanner.analyzers.cross_tool import AttackChain, CrossToolAnalyzer
from mcp_security_scanner.analyzers.dynamic import DynamicAnalyzer
from mcp_security_scanner.analyzers.escalation import CapabilityRiskProfile, EscalationAnalyzer
from mcp_security_scanner.analyzers.injection import PromptInjectionAnalyzer
from mcp_security_scanner.analyzers.poisoning import ToolPoisoningAnalyzer
from mcp_security_scanner.analyzers.static import StaticAnalyzer

__all__ = [
    "AttackChain",
    "BaseAnalyzer",
    "CapabilityRiskProfile",
    "CrossToolAnalyzer",
    "DynamicAnalyzer",
    "EscalationAnalyzer",
    "Finding",
    "PromptInjectionAnalyzer",
    "Severity",
    "StaticAnalyzer",
    "ToolPoisoningAnalyzer",
]
