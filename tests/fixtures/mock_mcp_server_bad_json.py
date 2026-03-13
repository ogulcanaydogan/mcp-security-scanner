"""Server that returns invalid JSON body for initialize response."""

import sys


def read_request() -> None:
    header = b""
    while b"\r\n\r\n" not in header:
        chunk = sys.stdin.buffer.read(1)
        if chunk == b"":
            return
        header += chunk

    header_text = header.decode("ascii", errors="replace")
    length = int(header_text.split("Content-Length:", maxsplit=1)[1].split("\r\n", maxsplit=1)[0].strip())
    _ = sys.stdin.buffer.read(length)


read_request()
body = b"not-json"
header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
sys.stdout.buffer.write(header + body)
sys.stdout.buffer.flush()
