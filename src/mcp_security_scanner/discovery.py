"""
MCP server discovery and capability enumeration.

Handles connection to MCP servers via stdio/SSE/Streamable HTTP transports and retrieves
all available tools, resources, and prompts for analysis.
"""

import asyncio
import json
import os
import re
from contextlib import AsyncExitStack
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx
from mcp.client.session import ClientSession
from mcp.client.sse import sse_client
from mcp.client.streamable_http import streamable_http_client
from pydantic import AnyUrl


@dataclass
class ToolDefinition:
    """
    Represents an MCP tool definition.

    Attributes:
        name: Unique tool identifier.
        description: Human-readable description.
        input_schema: JSON Schema for tool inputs.
        output_schema: JSON Schema for tool outputs (optional).
    """

    name: str
    description: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any] | None = None
    metadata: dict[str, Any] | None = None


@dataclass
class ResourceDefinition:
    """
    Represents an MCP resource definition.

    Attributes:
        uri: Resource URI (e.g., "memory://important_data").
        name: Human-readable name.
        description: What this resource does.
        mime_type: MIME type of the resource content.
        content: Actual resource content (retrieved on demand).
    """

    uri: str
    name: str
    description: str
    mime_type: str = "text/plain"
    content: str | None = None
    metadata: dict[str, Any] | None = None


@dataclass
class PromptDefinition:
    """
    Represents an MCP prompt template.

    Attributes:
        name: Unique prompt identifier.
        description: What the prompt does.
        arguments: List of argument definitions.
    """

    name: str
    description: str
    arguments: list[dict[str, Any]] | None = None
    metadata: dict[str, Any] | None = None


@dataclass
class ServerCapabilities:
    """
    Container for all capabilities discovered on an MCP server.

    Attributes:
        server_name: Name/version of the MCP server.
        tools: List of available tools.
        resources: List of available resources.
        prompts: List of available prompts.
        metadata: Server-level metadata.
    """

    server_name: str
    tools: list[ToolDefinition]
    resources: list[ResourceDefinition]
    prompts: list[PromptDefinition]
    metadata: dict[str, Any] | None = None


class MCPServerConnector:
    """
    Manages connections to MCP servers and capability discovery.

    Supports stdio, SSE, and Streamable HTTP transports.
    """

    _CONTENT_LENGTH_RE = re.compile(r"Content-Length:\s*(?P<length>\d+)", re.IGNORECASE)

    def __init__(self: "MCPServerConnector", server_name: str) -> None:
        """
        Initialize a server connector.

        Args:
            server_name: Identifier for the server being connected to.
        """
        self.server_name = server_name
        self._connected = False
        self._tools: list[ToolDefinition] = []
        self._resources: list[ResourceDefinition] = []
        self._prompts: list[PromptDefinition] = []
        self._process: asyncio.subprocess.Process | None = None
        self._session: ClientSession | None = None
        self._exit_stack: AsyncExitStack | None = None
        self._transport: str | None = None
        self._timeout = 30.0
        self._request_id = 0

    async def connect(self: "MCPServerConnector", config: dict[str, Any]) -> bool:
        """
        Connect to an MCP server.

        Args:
            config: Connection configuration.
                Required keys:
                    - type: "stdio", "sse", "streamable-http", or "streamable_http"
                stdio keys:
                    - command: shell command to start server process
                    - env: optional environment overrides
                sse/streamable-http keys:
                    - url: http/https endpoint
                    - headers: optional HTTP headers
                Optional keys:
                    - timeout: request timeout in seconds (default 30)

        Returns:
            True if connection successful.

        Raises:
            ValueError: If config is invalid.
            TimeoutError: If connection times out.
            ConnectionError: If connection fails.
        """
        transport_value = config.get("type")
        transport = self._normalize_transport(transport_value)
        if transport is None:
            raise ValueError("config.type must be one of: stdio, sse, streamable-http.")

        timeout_value = config.get("timeout", 30)
        try:
            timeout = float(timeout_value)
        except (TypeError, ValueError) as exc:
            raise ValueError("config.timeout must be a positive number.") from exc

        if timeout <= 0:
            raise ValueError("config.timeout must be a positive number.")

        self._timeout = timeout
        self._request_id = 0

        if transport == "stdio":
            command = config.get("command")
            if not isinstance(command, str) or not command.strip():
                raise ValueError("config.command must be a non-empty string for stdio transport.")

            raw_env = config.get("env")
            env: dict[str, str] | None = None
            if raw_env is not None:
                if not isinstance(raw_env, dict):
                    raise ValueError("config.env must be an object of environment variables.")
                env = os.environ.copy()
                env.update({str(key): str(value) for key, value in raw_env.items()})

            process = await asyncio.create_subprocess_shell(
                command,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
            self._process = process
            self._transport = "stdio"

            if process.stdin is None or process.stdout is None or process.stderr is None:
                await self.disconnect()
                raise ConnectionError("Failed to create stdio pipes for MCP server process.")

            try:
                result = await self._rpc_request(
                    "initialize",
                    {
                        "protocolVersion": "2024-11-05",
                        "clientInfo": {
                            "name": "mcp-security-scanner",
                            "version": "0.1.0",
                        },
                        "capabilities": {},
                    },
                )
                if not isinstance(result, dict):
                    raise ConnectionError("Invalid initialize response received from MCP server.")

                await self._send_notification("notifications/initialized", {})
                self._connected = True
                return True
            except TimeoutError:
                await self.disconnect()
                raise
            except Exception as exc:
                await self.disconnect()
                raise ConnectionError(f"Failed to connect to MCP server: {exc}") from exc

        url_value = config.get("url")
        if not isinstance(url_value, str) or not url_value.strip():
            raise ValueError(f"config.url must be a non-empty string for {transport} transport.")

        parsed_url = urlparse(url_value)
        if parsed_url.scheme not in {"http", "https"}:
            raise ValueError(f"config.url must use http or https scheme for {transport} transport.")

        raw_headers = config.get("headers")
        headers: dict[str, Any] | None = None
        if raw_headers is not None:
            if not isinstance(raw_headers, dict):
                raise ValueError(f"config.headers must be an object for {transport} transport.")
            headers = {str(key): str(value) for key, value in raw_headers.items()}

        self._exit_stack = AsyncExitStack()
        try:
            if transport == "sse":
                transport_context = sse_client(
                    url=url_value,
                    headers=headers,
                    timeout=timeout,
                    sse_read_timeout=timeout,
                )
            else:
                http_client = httpx.AsyncClient(
                    headers=headers,
                    timeout=httpx.Timeout(timeout, read=timeout),
                    follow_redirects=True,
                )
                await self._exit_stack.enter_async_context(http_client)
                transport_context = streamable_http_client(
                    url=url_value,
                    http_client=http_client,
                )

            read_stream, write_stream = await self._exit_stack.enter_async_context(transport_context)
            session = await self._exit_stack.enter_async_context(
                ClientSession(read_stream=read_stream, write_stream=write_stream)
            )
            await session.initialize()

            self._session = session
            self._transport = transport
            self._connected = True
            return True
        except TimeoutError:
            await self.disconnect()
            raise
        except Exception as exc:
            await self.disconnect()
            raise ConnectionError(f"Failed to connect to MCP server: {exc}") from exc

    async def enumerate_tools(self: "MCPServerConnector") -> list[ToolDefinition]:
        """
        Retrieve all available tools from the server.

        Returns:
            List of ToolDefinition objects.

        Raises:
            RuntimeError: If not connected.
        """
        self._ensure_connected()
        raw_tools: list[dict[str, Any]]
        if self._transport in {"sse", "streamable-http"}:
            if self._session is None:
                raise RuntimeError("Not connected to MCP server.")
            sse_result = await self._session.list_tools()
            raw_tools = [self._model_to_dict(item) for item in sse_result.tools]
        else:
            rpc_result = await self._rpc_request("tools/list", {})
            raw_tools = [item for item in rpc_result.get("tools", []) if isinstance(item, dict)]

        tools: list[ToolDefinition] = []
        for item in raw_tools:
            tools.append(self._normalize_tool(item))

        self._tools = tools
        return tools

    async def enumerate_resources(self: "MCPServerConnector") -> list[ResourceDefinition]:
        """
        Retrieve all available resources from the server.

        Returns:
            List of ResourceDefinition objects.

        Raises:
            RuntimeError: If not connected.
        """
        self._ensure_connected()
        raw_resources: list[dict[str, Any]]
        if self._transport in {"sse", "streamable-http"}:
            if self._session is None:
                raise RuntimeError("Not connected to MCP server.")
            sse_result = await self._session.list_resources()
            raw_resources = [self._model_to_dict(item) for item in sse_result.resources]
        else:
            rpc_result = await self._rpc_request("resources/list", {})
            raw_resources = [item for item in rpc_result.get("resources", []) if isinstance(item, dict)]

        resources: list[ResourceDefinition] = []
        for item in raw_resources:
            resources.append(self._normalize_resource(item))

        self._resources = resources
        return resources

    async def enumerate_prompts(self: "MCPServerConnector") -> list[PromptDefinition]:
        """
        Retrieve all available prompt templates from the server.

        Returns:
            List of PromptDefinition objects.

        Raises:
            RuntimeError: If not connected.
        """
        self._ensure_connected()
        raw_prompts: list[dict[str, Any]]
        if self._transport in {"sse", "streamable-http"}:
            if self._session is None:
                raise RuntimeError("Not connected to MCP server.")
            sse_result = await self._session.list_prompts()
            raw_prompts = [self._model_to_dict(item) for item in sse_result.prompts]
        else:
            rpc_result = await self._rpc_request("prompts/list", {})
            raw_prompts = [item for item in rpc_result.get("prompts", []) if isinstance(item, dict)]

        prompts: list[PromptDefinition] = []
        for item in raw_prompts:
            prompts.append(self._normalize_prompt(item))

        self._prompts = prompts
        return prompts

    async def get_resource_content(self: "MCPServerConnector", uri: str) -> str:
        """
        Retrieve the actual content of a resource.

        Args:
            uri: The resource URI to fetch.

        Returns:
            Resource content as string.

        Raises:
            RuntimeError: If not connected.
            ValueError: If resource not found.
        """
        self._ensure_connected()
        if not uri.strip():
            raise ValueError("Resource URI must be non-empty.")

        if self._transport in {"sse", "streamable-http"}:
            if self._session is None:
                raise RuntimeError("Not connected to MCP server.")
            result = await self._session.read_resource(AnyUrl(uri))
            raw_result = {
                "contents": [self._model_to_dict(item) for item in result.contents],
            }
        else:
            raw_result = await self._rpc_request("resources/read", {"uri": uri})

        content = self._extract_resource_content(raw_result, uri)
        if content is not None:
            return content

        raise ValueError(f"Resource not found or unreadable: {uri}")

    async def call_tool(
        self: "MCPServerConnector",
        tool_name: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Execute a tool on the server (for dynamic analysis).

        Args:
            tool_name: Name of the tool to invoke.
            arguments: Tool arguments as a dict.

        Returns:
            Tool result/response.

        Raises:
            RuntimeError: If not connected.
            ValueError: If tool name is invalid.
        """
        self._ensure_connected()
        if not tool_name.strip():
            raise ValueError("tool_name must be a non-empty string.")

        if self._transport in {"sse", "streamable-http"}:
            if self._session is None:
                raise RuntimeError("Not connected to MCP server.")
            result = await self._session.call_tool(tool_name, arguments)
            return self._model_to_dict(result)

        return await self._rpc_request(
            "tools/call",
            {
                "name": tool_name,
                "arguments": arguments,
            },
        )

    async def get_server_capabilities(self: "MCPServerConnector") -> ServerCapabilities:
        """
        Retrieve all capabilities from the server in one call.

        Returns:
            ServerCapabilities object containing tools, resources, prompts.

        Raises:
            RuntimeError: If not connected.
        """
        self._ensure_connected()

        # Requests are executed sequentially because stdio JSON-RPC responses
        # are consumed from a single stream in this sprint implementation.
        tools = await self.enumerate_tools()
        resources = await self.enumerate_resources()
        prompts = await self.enumerate_prompts()

        return ServerCapabilities(
            server_name=self.server_name,
            tools=tools,
            resources=resources,
            prompts=prompts,
        )

    async def disconnect(self: "MCPServerConnector") -> None:
        """
        Cleanly disconnect from the server.

        Closes any open processes or connections.
        """
        process = self._process
        exit_stack = self._exit_stack

        if process is not None and process.stdin is not None:
            process.stdin.close()

        if process is not None and process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=2)
            except TimeoutError:
                process.kill()
                await process.wait()

        if exit_stack is not None:
            await exit_stack.aclose()

        self._process = None
        self._session = None
        self._exit_stack = None
        self._transport = None
        self._connected = False

    def _ensure_connected(self: "MCPServerConnector") -> None:
        """Validate that the connector has an active MCP session."""
        if not self._connected:
            raise RuntimeError("Not connected to MCP server.")

        if self._transport == "stdio":
            if self._process is None:
                self._connected = False
                raise RuntimeError("Not connected to MCP server.")

            if self._process.returncode is not None:
                self._connected = False
                raise RuntimeError("MCP server process is no longer running.")
            return

        if self._transport in {"sse", "streamable-http"}:
            if self._session is None or self._exit_stack is None:
                self._connected = False
                raise RuntimeError("Not connected to MCP server.")
            return

        self._connected = False
        raise RuntimeError("Connector transport state is invalid.")

    async def _rpc_request(self: "MCPServerConnector", method: str, params: dict[str, Any]) -> dict[str, Any]:
        """Send an MCP JSON-RPC request and return the result object."""
        if self._transport != "stdio":
            raise RuntimeError("JSON-RPC subprocess path is available only for stdio transport.")

        if self._process is None or self._process.stdin is None or self._process.stdout is None:
            raise ConnectionError("MCP server process is not available.")

        self._request_id += 1
        request_id = self._request_id

        payload = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params,
        }
        await self._write_message(payload)

        while True:
            message = await self._read_message()
            if message.get("id") != request_id:
                continue

            if "error" in message:
                raise RuntimeError(self._format_error(message["error"]))

            result = message.get("result", {})
            if isinstance(result, dict):
                return result
            return {"value": result}

    async def _send_notification(self: "MCPServerConnector", method: str, params: dict[str, Any]) -> None:
        """Send a fire-and-forget JSON-RPC notification."""
        await self._write_message(
            {
                "jsonrpc": "2.0",
                "method": method,
                "params": params,
            }
        )

    async def _write_message(self: "MCPServerConnector", payload: dict[str, Any]) -> None:
        """Write a framed JSON-RPC message to server stdin."""
        if self._process is None or self._process.stdin is None:
            raise ConnectionError("MCP server stdin is not available.")

        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")

        self._process.stdin.write(header + body)
        try:
            await asyncio.wait_for(self._process.stdin.drain(), timeout=self._timeout)
        except TimeoutError as exc:
            raise TimeoutError("Timed out while sending data to MCP server.") from exc

    async def _read_message(self: "MCPServerConnector") -> dict[str, Any]:
        """Read one JSON-RPC message from stdout (Content-Length framed or line-delimited)."""
        if self._process is None or self._process.stdout is None:
            raise ConnectionError("MCP server stdout is not available.")

        try:
            first = await asyncio.wait_for(self._process.stdout.read(1), timeout=self._timeout)
        except TimeoutError as exc:
            raise TimeoutError("Timed out waiting for MCP server response.") from exc

        if first == b"":
            stderr_output = ""
            if self._process.stderr is not None:
                stderr_bytes = await self._process.stderr.read()
                stderr_output = stderr_bytes.decode("utf-8", errors="replace").strip()

            message = "MCP server closed stdout unexpectedly."
            if stderr_output:
                message = f"{message} stderr: {stderr_output}"
            raise ConnectionError(message)

        if first == b"{":
            line = await self._process.stdout.readline()
            raw = first + line
            return self._parse_json_message(raw)

        try:
            header_rest = await asyncio.wait_for(self._process.stdout.readuntil(b"\r\n\r\n"), timeout=self._timeout)
        except TimeoutError as exc:
            raise TimeoutError("Timed out while reading MCP message headers.") from exc
        except asyncio.IncompleteReadError as exc:
            raise ConnectionError("Incomplete MCP message headers.") from exc

        header = first + header_rest
        header_text = header.decode("ascii", errors="replace")
        match = self._CONTENT_LENGTH_RE.search(header_text)
        if not match:
            raise ConnectionError(f"Invalid MCP frame headers: {header_text!r}")

        content_length = int(match.group("length"))

        try:
            body = await asyncio.wait_for(self._process.stdout.readexactly(content_length), timeout=self._timeout)
        except TimeoutError as exc:
            raise TimeoutError("Timed out while reading MCP message body.") from exc
        except asyncio.IncompleteReadError as exc:
            raise ConnectionError("Incomplete MCP message body.") from exc

        return self._parse_json_message(body)

    @staticmethod
    def _normalize_transport(transport_value: Any) -> str | None:
        """Normalize supported transport identifiers to canonical values."""
        if not isinstance(transport_value, str):
            return None

        transport = transport_value.strip().lower()
        if transport == "streamable_http":
            return "streamable-http"

        if transport in {"stdio", "sse", "streamable-http"}:
            return transport

        return None

    @staticmethod
    def _extract_resource_content(result: dict[str, Any], uri: str) -> str | None:
        """Extract resource text/blob payload from an MCP read response."""
        if "content" in result and result["content"] is not None:
            return str(result["content"])

        contents = result.get("contents", [])
        if isinstance(contents, list):
            for item in contents:
                if not isinstance(item, dict):
                    continue
                if item.get("uri") not in (None, uri):
                    continue
                if "text" in item and item["text"] is not None:
                    return str(item["text"])
                if "blob" in item and item["blob"] is not None:
                    return str(item["blob"])

        return None

    @staticmethod
    def _model_to_dict(value: Any) -> dict[str, Any]:
        """Convert pydantic-like models to dictionaries using aliases."""
        if isinstance(value, dict):
            return value

        if hasattr(value, "model_dump"):
            dumped = value.model_dump(by_alias=True, exclude_none=True)
            if isinstance(dumped, dict):
                return dumped

        return {}

    @staticmethod
    def _parse_json_message(raw: bytes) -> dict[str, Any]:
        """Decode and parse a JSON-RPC payload."""
        try:
            decoded = raw.decode("utf-8").strip()
            parsed = json.loads(decoded)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ConnectionError("Received invalid JSON payload from MCP server.") from exc

        if not isinstance(parsed, dict):
            raise ConnectionError("MCP response payload must be a JSON object.")
        return parsed

    @staticmethod
    def _format_error(error: Any) -> str:
        """Return a compact string representation of a JSON-RPC error payload."""
        if isinstance(error, dict):
            code = error.get("code")
            message = error.get("message", "Unknown RPC error")
            if code is not None:
                return f"RPC error {code}: {message}"
            return str(message)
        return str(error)

    @staticmethod
    def _normalize_tool(data: dict[str, Any]) -> ToolDefinition:
        """Normalize raw MCP tool payload into ToolDefinition."""
        return ToolDefinition(
            name=str(data.get("name", "")),
            description=str(data.get("description", "")),
            input_schema=data.get("inputSchema", {}) if isinstance(data.get("inputSchema"), dict) else {},
            output_schema=data.get("outputSchema") if isinstance(data.get("outputSchema"), dict) else None,
            metadata=data,
        )

    @staticmethod
    def _normalize_resource(data: dict[str, Any]) -> ResourceDefinition:
        """Normalize raw MCP resource payload into ResourceDefinition."""
        uri = str(data.get("uri", ""))
        return ResourceDefinition(
            uri=uri,
            name=str(data.get("name", uri)),
            description=str(data.get("description", "")),
            mime_type=str(data.get("mimeType", "text/plain")),
            metadata=data,
        )

    @staticmethod
    def _normalize_prompt(data: dict[str, Any]) -> PromptDefinition:
        """Normalize raw MCP prompt payload into PromptDefinition."""
        raw_arguments = data.get("arguments")
        arguments: list[dict[str, Any]] | None = None
        if isinstance(raw_arguments, list):
            arguments = [item for item in raw_arguments if isinstance(item, dict)]

        return PromptDefinition(
            name=str(data.get("name", "")),
            description=str(data.get("description", "")),
            arguments=arguments,
            metadata=data,
        )
