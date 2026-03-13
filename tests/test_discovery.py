"""Tests for MCP server discovery and capability enumeration."""

import shlex
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import mcp_security_scanner.discovery as discovery_module
from mcp_security_scanner.discovery import (
    MCPServerConnector,
    PromptDefinition,
    ResourceDefinition,
    ServerCapabilities,
    ToolDefinition,
)


FIXTURES_DIR = Path(__file__).parent / "fixtures"
MOCK_SERVER = FIXTURES_DIR / "mock_mcp_server.py"
LINE_SERVER = FIXTURES_DIR / "mock_mcp_server_line.py"
INIT_ERROR_SERVER = FIXTURES_DIR / "mock_mcp_server_init_error.py"
BAD_JSON_SERVER = FIXTURES_DIR / "mock_mcp_server_bad_json.py"
ENV_SERVER = FIXTURES_DIR / "mock_mcp_server_env.py"


def _script_command(script_path: Path) -> str:
    return f"{shlex.quote(sys.executable)} {shlex.quote(str(script_path))}"


MOCK_SERVER_COMMAND = _script_command(MOCK_SERVER)
LINE_SERVER_COMMAND = _script_command(LINE_SERVER)
INIT_ERROR_SERVER_COMMAND = _script_command(INIT_ERROR_SERVER)
BAD_JSON_SERVER_COMMAND = _script_command(BAD_JSON_SERVER)
ENV_SERVER_COMMAND = _script_command(ENV_SERVER)
SLEEP_COMMAND = f"{shlex.quote(sys.executable)} -c {shlex.quote('import time; time.sleep(60)')}"


class TestMCPServerConnector:
    """Test MCPServerConnector class."""

    def test_connector_initialization(self):
        """Test creating a server connector."""
        connector = MCPServerConnector("test_server")

        assert connector.server_name == "test_server"
        assert connector._connected is False

    @pytest.mark.asyncio
    async def test_connect_rejects_unsupported_transport(self):
        """Connector should reject transports other than stdio/sse."""
        connector = MCPServerConnector("test_server")

        with pytest.raises(ValueError, match="stdio and sse"):
            await connector.connect({"type": "grpc", "endpoint": "localhost:5000"})

    @pytest.mark.asyncio
    async def test_connect_rejects_invalid_config(self):
        """Connector should reject missing stdio command."""
        connector = MCPServerConnector("test_server")

        with pytest.raises(ValueError, match="config.command"):
            await connector.connect({"type": "stdio"})

    @pytest.mark.asyncio
    async def test_connect_rejects_non_positive_timeout(self):
        """Connector should reject non-positive timeout values."""
        connector = MCPServerConnector("test_server")

        with pytest.raises(ValueError, match="positive number"):
            await connector.connect({"type": "stdio", "command": f"{sys.executable} -V", "timeout": 0})

    @pytest.mark.asyncio
    async def test_connect_rejects_invalid_env(self):
        """Connector should reject non-object env payload."""
        connector = MCPServerConnector("test_server")

        with pytest.raises(ValueError, match="config.env"):
            await connector.connect({"type": "stdio", "command": f"{sys.executable} -V", "env": "bad"})

    @pytest.mark.asyncio
    async def test_connect_rejects_invalid_sse_config(self):
        """Connector should validate SSE URL and headers payload."""
        connector = MCPServerConnector("test_server")

        with pytest.raises(ValueError, match="config.url"):
            await connector.connect({"type": "sse"})

        with pytest.raises(ValueError, match="http or https"):
            await connector.connect({"type": "sse", "url": "ftp://example.com/sse"})

        with pytest.raises(ValueError, match="config.headers"):
            await connector.connect(
                {
                    "type": "sse",
                    "url": "https://example.com/sse",
                    "headers": "Authorization: Bearer token",
                }
            )

    @pytest.mark.asyncio
    async def test_connect_timeout(self):
        """Connector should timeout when server does not respond."""
        connector = MCPServerConnector("sleepy")

        with pytest.raises(TimeoutError):
            await connector.connect(
                {
                    "type": "stdio",
                    "command": SLEEP_COMMAND,
                    "timeout": 0.1,
                }
            )

        assert connector._connected is False

    @pytest.mark.asyncio
    async def test_connect_sse_and_get_server_capabilities(self, monkeypatch):
        """Connector should use SSE transport session APIs when configured."""
        captured: dict[str, object] = {}

        class FakePayload:
            def __init__(self, payload: dict[str, object]) -> None:
                self._payload = payload

            def model_dump(self, **kwargs: object) -> dict[str, object]:
                del kwargs
                return self._payload

        class FakeSSEContext:
            async def __aenter__(self) -> tuple[object, object]:
                captured["sse_entered"] = True
                return object(), object()

            async def __aexit__(self, exc_type, exc, tb) -> None:
                del exc_type, exc, tb
                captured["sse_closed"] = True

        class FakeClientSession:
            def __init__(self, read_stream: object, write_stream: object) -> None:
                captured["streams"] = (read_stream, write_stream)

            async def __aenter__(self) -> "FakeClientSession":
                captured["session_entered"] = True
                return self

            async def __aexit__(self, exc_type, exc, tb) -> None:
                del exc_type, exc, tb
                captured["session_closed"] = True

            async def initialize(self) -> None:
                captured["initialized"] = True

            async def list_tools(self) -> SimpleNamespace:
                return SimpleNamespace(
                    tools=[
                        FakePayload(
                            {
                                "name": "sse_tool",
                                "description": "Tool from SSE server",
                                "inputSchema": {"type": "object"},
                            }
                        )
                    ]
                )

            async def list_resources(self) -> SimpleNamespace:
                return SimpleNamespace(
                    resources=[
                        FakePayload(
                            {
                                "uri": "memory://sse-resource",
                                "name": "SSE Resource",
                                "description": "Resource from SSE server",
                                "mimeType": "text/plain",
                            }
                        )
                    ]
                )

            async def list_prompts(self) -> SimpleNamespace:
                return SimpleNamespace(
                    prompts=[
                        FakePayload(
                            {
                                "name": "sse_prompt",
                                "description": "Prompt from SSE server",
                                "arguments": [{"name": "text"}],
                            }
                        )
                    ]
                )

            async def read_resource(self, uri) -> SimpleNamespace:
                captured["read_uri"] = str(uri)
                return SimpleNamespace(
                    contents=[
                        FakePayload(
                            {
                                "uri": "memory://sse-resource",
                                "mimeType": "text/plain",
                                "text": "sse content payload",
                            }
                        )
                    ]
                )

            async def call_tool(self, name: str, arguments: dict[str, object]) -> FakePayload:
                return FakePayload({"tool": name, "echo": arguments})

        def fake_sse_client(url: str, **kwargs: object) -> FakeSSEContext:
            captured["url"] = url
            captured["kwargs"] = kwargs
            return FakeSSEContext()

        monkeypatch.setattr(discovery_module, "sse_client", fake_sse_client)
        monkeypatch.setattr(discovery_module, "ClientSession", FakeClientSession)

        connector = MCPServerConnector("sse_server")
        connected = await connector.connect(
            {
                "type": "sse",
                "url": "https://example.com/sse",
                "headers": {"Authorization": "Bearer test-token"},
                "timeout": 3,
            }
        )

        assert connected is True
        assert captured["url"] == "https://example.com/sse"
        assert captured["initialized"] is True

        capabilities = await connector.get_server_capabilities()
        assert capabilities.tools[0].name == "sse_tool"
        assert capabilities.resources[0].uri == "memory://sse-resource"
        assert capabilities.prompts[0].name == "sse_prompt"

        content = await connector.get_resource_content("memory://sse-resource")
        assert content == "sse content payload"
        assert captured["read_uri"] == "memory://sse-resource"

        tool_result = await connector.call_tool("sse_tool", {"value": "hello"})
        assert tool_result["tool"] == "sse_tool"
        assert tool_result["echo"]["value"] == "hello"

        await connector.disconnect()
        assert captured["sse_closed"] is True
        assert captured["session_closed"] is True

    @pytest.mark.asyncio
    async def test_connect_and_get_server_capabilities(self):
        """Test retrieving all capabilities at once."""
        connector = MCPServerConnector("mock_server")

        connected = await connector.connect(
            {
                "type": "stdio",
                "command": MOCK_SERVER_COMMAND,
                "timeout": 2,
            }
        )

        assert connected is True

        capabilities = await connector.get_server_capabilities()

        assert isinstance(capabilities, ServerCapabilities)
        assert capabilities.server_name == "mock_server"
        assert len(capabilities.tools) == 2
        assert len(capabilities.resources) == 1
        assert len(capabilities.prompts) == 1

        await connector.disconnect()

    @pytest.mark.asyncio
    async def test_connect_with_line_delimited_server(self):
        """Connector should accept line-delimited fallback responses."""
        connector = MCPServerConnector("line_server")
        await connector.connect(
            {
                "type": "stdio",
                "command": LINE_SERVER_COMMAND,
                "timeout": 2,
            }
        )

        tools = await connector.enumerate_tools()
        assert len(tools) == 1
        assert tools[0].name == "line_tool"

        await connector.disconnect()

    @pytest.mark.asyncio
    async def test_connect_with_initialize_error(self):
        """Connector should convert initialize RPC errors to ConnectionError."""
        connector = MCPServerConnector("error_server")

        with pytest.raises(ConnectionError, match="init failed"):
            await connector.connect(
                {
                    "type": "stdio",
                    "command": INIT_ERROR_SERVER_COMMAND,
                    "timeout": 2,
                }
            )

    @pytest.mark.asyncio
    async def test_connect_with_invalid_json_payload(self):
        """Connector should fail if initialize response body is invalid JSON."""
        connector = MCPServerConnector("bad_json_server")

        with pytest.raises(ConnectionError, match="invalid JSON payload"):
            await connector.connect(
                {
                    "type": "stdio",
                    "command": BAD_JSON_SERVER_COMMAND,
                    "timeout": 2,
                }
            )

    @pytest.mark.asyncio
    async def test_enumerate_methods_require_connection(self):
        """Enumeration should fail if connector is not connected."""
        connector = MCPServerConnector("test_server")

        with pytest.raises(RuntimeError, match="Not connected"):
            await connector.enumerate_tools()

        with pytest.raises(RuntimeError, match="Not connected"):
            await connector.enumerate_resources()

        with pytest.raises(RuntimeError, match="Not connected"):
            await connector.enumerate_prompts()

    @pytest.mark.asyncio
    async def test_get_resource_content_success(self):
        """Connector should read content for an existing resource URI."""
        connector = MCPServerConnector("mock_server")
        await connector.connect(
            {
                "type": "stdio",
                "command": MOCK_SERVER_COMMAND,
                "timeout": 2,
            }
        )

        content = await connector.get_resource_content("memory://config")

        assert "ignore_previous" in content

        await connector.disconnect()

    @pytest.mark.asyncio
    async def test_get_resource_content_not_found(self):
        """Connector should raise when resource content does not exist."""
        connector = MCPServerConnector("mock_server")
        await connector.connect(
            {
                "type": "stdio",
                "command": MOCK_SERVER_COMMAND,
                "timeout": 2,
            }
        )

        with pytest.raises(ValueError, match="Resource not found"):
            await connector.get_resource_content("memory://missing")

        await connector.disconnect()

    @pytest.mark.asyncio
    async def test_get_resource_content_empty_uri(self):
        """Connector should reject empty resource URI input."""
        connector = MCPServerConnector("mock_server")
        await connector.connect(
            {
                "type": "stdio",
                "command": MOCK_SERVER_COMMAND,
                "timeout": 2,
            }
        )

        with pytest.raises(ValueError, match="non-empty"):
            await connector.get_resource_content("   ")

        await connector.disconnect()

    @pytest.mark.asyncio
    async def test_call_tool(self):
        """Connector should call tools and return structured response."""
        connector = MCPServerConnector("mock_server")
        await connector.connect(
            {
                "type": "stdio",
                "command": MOCK_SERVER_COMMAND,
                "timeout": 2,
            }
        )

        result = await connector.call_tool("safe_echo", {"value": "hello"})

        assert result["tool"] == "safe_echo"
        assert result["echo"]["value"] == "hello"

        await connector.disconnect()

    @pytest.mark.asyncio
    async def test_call_tool_rejects_empty_name(self):
        """Connector should reject empty tool names."""
        connector = MCPServerConnector("mock_server")
        await connector.connect(
            {
                "type": "stdio",
                "command": MOCK_SERVER_COMMAND,
                "timeout": 2,
            }
        )

        with pytest.raises(ValueError, match="non-empty"):
            await connector.call_tool("  ", {})

        await connector.disconnect()

    @pytest.mark.asyncio
    async def test_disconnect(self):
        """Test disconnection from server."""
        connector = MCPServerConnector("mock_server")
        await connector.connect(
            {
                "type": "stdio",
                "command": MOCK_SERVER_COMMAND,
                "timeout": 2,
            }
        )

        await connector.disconnect()

        assert connector._connected is False

    @pytest.mark.asyncio
    async def test_connect_passes_env_to_process(self):
        """Connector should pass configured env values to stdio process."""
        connector = MCPServerConnector("env_server")
        await connector.connect(
            {
                "type": "stdio",
                "command": ENV_SERVER_COMMAND,
                "timeout": 2,
                "env": {"MCP_TEST_ENV": "expected-value"},
            }
        )

        result = await connector.call_tool("read_env", {"name": "MCP_TEST_ENV"})
        assert result["value"] == "expected-value"

        await connector.disconnect()

    def test_format_error_dict_without_code(self):
        """Error formatter should handle dict payloads without a code."""
        assert MCPServerConnector._format_error({"message": "hello"}) == "hello"

    def test_format_error_non_dict(self):
        """Error formatter should stringify non-dict values."""
        assert MCPServerConnector._format_error("boom") == "boom"

    def test_parse_json_message_rejects_non_object(self):
        """Parser should reject non-object JSON values."""
        with pytest.raises(ConnectionError, match="JSON object"):
            MCPServerConnector._parse_json_message(b"[]")

    def test_parse_json_message_rejects_invalid_json(self):
        """Parser should reject invalid JSON bytes."""
        with pytest.raises(ConnectionError, match="invalid JSON payload"):
            MCPServerConnector._parse_json_message(b"{invalid")

    def test_normalize_helpers(self):
        """Normalize helper methods should produce dataclass values."""
        tool = MCPServerConnector._normalize_tool({"name": "t", "description": "d", "inputSchema": "bad"})
        resource = MCPServerConnector._normalize_resource({"uri": "memory://x"})
        prompt = MCPServerConnector._normalize_prompt({"name": "p", "arguments": ["bad", {"name": "ok"}]})

        assert isinstance(tool, ToolDefinition)
        assert tool.input_schema == {}
        assert isinstance(resource, ResourceDefinition)
        assert resource.name == "memory://x"
        assert isinstance(prompt, PromptDefinition)
        assert prompt.arguments == [{"name": "ok"}]
