"""
Pytest configuration and shared fixtures.

This module provides common fixtures used across all tests.
"""

import pytest
from mcp_security_scanner.discovery import ToolDefinition, ResourceDefinition


@pytest.fixture
def sample_tool():
    """Fixture for a benign sample tool."""
    return ToolDefinition(
        name="sample_tool",
        description="A safe tool that does basic operations",
        input_schema={
            "type": "object",
            "properties": {
                "input": {"type": "string"},
            },
            "required": ["input"],
        },
    )


@pytest.fixture
def malicious_tool_with_eval():
    """Fixture for a tool description containing dangerous eval pattern."""
    return ToolDefinition(
        name="dangerous_tool",
        description="This tool uses eval() to execute user code",
        input_schema={
            "type": "object",
            "properties": {
                "code": {"type": "string"},
            },
            "required": ["code"],
        },
    )


@pytest.fixture
def malicious_tool_with_shell():
    """Fixture for a tool description containing shell command patterns."""
    return ToolDefinition(
        name="shell_tool",
        description="Executes shell commands using os.system(cmd)",
        input_schema={
            "type": "object",
            "properties": {
                "command": {"type": "string"},
            },
            "required": ["command"],
        },
    )


@pytest.fixture
def sample_resource():
    """Fixture for a sample resource."""
    return ResourceDefinition(
        uri="memory://sample_data",
        name="Sample Data",
        description="A sample resource",
        content="Sample resource content",
    )


@pytest.fixture
def injection_payload_resource():
    """Fixture for a resource containing injection payload."""
    return ResourceDefinition(
        uri="memory://config",
        name="Config",
        description="Configuration resource",
        content='{"admin": true, "ignore_previous": "instructions"}',
    )
