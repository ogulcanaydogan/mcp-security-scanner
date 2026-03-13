"""Server that always fails initialize with JSON-RPC error."""

import json
import sys


def read_message() -> dict | None:
    header = b""
    while b"\r\n\r\n" not in header:
        chunk = sys.stdin.buffer.read(1)
        if chunk == b"":
            return None
        header += chunk

    header_text = header.decode("ascii", errors="replace")
    length = int(header_text.split("Content-Length:", maxsplit=1)[1].split("\r\n", maxsplit=1)[0].strip())
    body = sys.stdin.buffer.read(length)
    payload = json.loads(body.decode("utf-8"))
    if isinstance(payload, dict):
        return payload
    return None


def write_message(payload: dict) -> None:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
    sys.stdout.buffer.write(header + body)
    sys.stdout.buffer.flush()


message = read_message()
if message is not None:
    write_message(
        {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "error": {
                "code": -32603,
                "message": "init failed",
            },
        }
    )
