"""
MCP Security Scanner — Security analysis for Model Context Protocol servers.

This package detects prompt injection, tool poisoning, capability escalation,
and rug-pull attacks in MCP servers. Findings are mapped to OWASP LLM Top 10.
"""

__version__ = "1.0.10"
__author__ = "Ogulcan Aydogan"
__license__ = "Apache-2.0"

from mcp_security_scanner.analyzers.base import BaseAnalyzer, Finding, Severity
from mcp_security_scanner.discovery import MCPServerConnector, ServerCapabilities

__all__ = [
    "BaseAnalyzer",
    "Finding",
    "MCPServerConnector",
    "ServerCapabilities",
    "Severity",
    "__version__",
]
