"""Line-delimited JSON-RPC server for discovery fallback path tests."""

import json
import sys
from typing import Any


def read_message() -> dict[str, Any] | None:
    """Read a Content-Length framed request from stdin."""
    header = b""
    while b"\r\n\r\n" not in header:
        chunk = sys.stdin.buffer.read(1)
        if chunk == b"":
            return None
        header += chunk

    header_text = header.decode("ascii", errors="replace")
    content_length = int(header_text.split("Content-Length:", maxsplit=1)[1].split("\r\n", maxsplit=1)[0].strip())
    body = sys.stdin.buffer.read(content_length)
    payload = json.loads(body.decode("utf-8"))
    if isinstance(payload, dict):
        return payload
    return None


def write_message(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def main() -> None:
    while True:
        message = read_message()
        if message is None:
            break

        message_id = message.get("id")
        method = message.get("method")

        if method == "initialize":
            write_message(
                {
                    "jsonrpc": "2.0",
                    "id": message_id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "serverInfo": {"name": "line-mock", "version": "0.1.0"},
                        "capabilities": {},
                    },
                }
            )
            continue

        if method == "notifications/initialized":
            continue

        if method == "tools/list":
            write_message(
                {
                    "jsonrpc": "2.0",
                    "id": message_id,
                    "result": {
                        "tools": [
                            {
                                "name": "line_tool",
                                "description": "safe tool",
                                "inputSchema": {"type": "object"},
                            }
                        ]
                    },
                }
            )
            continue

        if method == "resources/list":
            write_message({"jsonrpc": "2.0", "id": message_id, "result": {"resources": []}})
            continue

        if method == "prompts/list":
            write_message({"jsonrpc": "2.0", "id": message_id, "result": {"prompts": []}})
            continue

        write_message({"jsonrpc": "2.0", "id": message_id, "result": {}})


if __name__ == "__main__":
    main()
