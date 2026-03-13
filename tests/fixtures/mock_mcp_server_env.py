"""MCP mock server that exposes env variable values for connector env tests."""

import json
import os
from typing import Any


def read_message() -> dict[str, Any] | None:
    """Read one Content-Length framed JSON-RPC message from stdin."""
    import sys

    header_bytes = b""

    while b"\r\n\r\n" not in header_bytes:
        chunk = sys.stdin.buffer.read(1)
        if chunk == b"":
            return None
        header_bytes += chunk

    header, _ = header_bytes.split(b"\r\n\r\n", maxsplit=1)
    content_length = None
    for line in header.decode("ascii", errors="replace").split("\r\n"):
        if line.lower().startswith("content-length:"):
            content_length = int(line.split(":", maxsplit=1)[1].strip())
            break

    if content_length is None:
        return None

    body = sys.stdin.buffer.read(content_length)
    if len(body) != content_length:
        return None

    payload = json.loads(body.decode("utf-8"))
    if isinstance(payload, dict):
        return payload
    return None


def write_message(payload: dict[str, Any]) -> None:
    """Write one Content-Length framed JSON-RPC message to stdout."""
    import sys

    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
    sys.stdout.buffer.write(header + body)
    sys.stdout.buffer.flush()


def handle_request(message: dict[str, Any]) -> dict[str, Any] | None:
    """Handle one request and return response payload for messages with an id."""
    message_id = message.get("id")
    method = message.get("method")
    params = message.get("params", {})

    if method == "notifications/initialized":
        return None

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": message_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "serverInfo": {
                    "name": "mock-mcp-server-env",
                    "version": "0.1.0",
                },
                "capabilities": {
                    "tools": {},
                    "resources": {},
                    "prompts": {},
                },
            },
        }

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": message_id,
            "result": {
                "tools": [
                    {
                        "name": "read_env",
                        "description": "Returns selected environment value",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string"},
                            },
                        },
                    }
                ]
            },
        }

    if method == "resources/list":
        return {
            "jsonrpc": "2.0",
            "id": message_id,
            "result": {"resources": []},
        }

    if method == "prompts/list":
        return {
            "jsonrpc": "2.0",
            "id": message_id,
            "result": {"prompts": []},
        }

    if method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments", {})

        if name == "read_env":
            env_name = str(arguments.get("name", ""))
            return {
                "jsonrpc": "2.0",
                "id": message_id,
                "result": {
                    "tool": name,
                    "value": os.getenv(env_name),
                },
            }

    return {
        "jsonrpc": "2.0",
        "id": message_id,
        "error": {
            "code": -32601,
            "message": f"Method not found: {method}",
        },
    }


def main() -> None:
    """Main request loop."""
    while True:
        message = read_message()
        if message is None:
            break

        response = handle_request(message)
        if response is not None:
            write_message(response)


if __name__ == "__main__":
    main()
