"""Scan engine: talks to clamd over TCP using its INSTREAM protocol.

This is the only file that knows about ClamAV. Another engine only has to
provide scan(path) and version().
"""

import os
import socket
import struct

CHUNK_SIZE = 1024 * 1024
LIMITS_SIGNATURE = "Heuristics.Limits.Exceeded"


def _connect(timeout):
    host = os.environ.get("CLAMD_HOST", "localhost")
    port = int(os.environ.get("CLAMD_PORT", 3310))
    sock = socket.create_connection((host, port), timeout=10)
    sock.settimeout(timeout)
    return sock


def _read_reply(sock):
    reply = b""
    while not reply.endswith(b"\0"):
        chunk = sock.recv(4096)
        if not chunk:
            break
        reply += chunk
    return reply.rstrip(b"\0\n").decode("utf-8", "replace")


def _command(name):
    with _connect(timeout=10) as sock:
        sock.sendall(b"z" + name + b"\0")
        return _read_reply(sock)


def version():
    if _command(b"PING") != "PONG":
        raise RuntimeError("clamd did not answer PONG")
    return _command(b"VERSION")


def parse_reply(reply):
    """Only an explicit OK is clean. Anything unexpected is an error."""
    if reply == "stream: OK":
        return {"verdict": "clean", "signature": None, "details": None}
    if reply.startswith("stream: ") and reply.endswith(" FOUND"):
        signature = reply[len("stream: ") : -len(" FOUND")]
        if signature.startswith(LIMITS_SIGNATURE):
            # A limit was exceeded: the file was not fully scanned.
            return {"verdict": "error", "signature": None, "details": signature}
        return {"verdict": "infected", "signature": signature, "details": None}
    return {"verdict": "error", "signature": None, "details": reply or "No reply"}


def scan(path):
    timeout = int(os.environ.get("CLAMD_TIMEOUT_SECONDS", 1800))
    engine = version()
    with _connect(timeout) as sock, open(path, "rb") as file:
        sock.sendall(b"zINSTREAM\0")
        try:
            while chunk := file.read(CHUNK_SIZE):
                sock.sendall(struct.pack("!L", len(chunk)) + chunk)
            sock.sendall(struct.pack("!L", 0))
        except BrokenPipeError:
            # clamd closes the socket when a limit is exceeded, after explaining
            # why. The reply below turns that into an error.
            pass
        except ConnectionResetError:
            pass
        reply = _read_reply(sock)
    return {**parse_reply(reply), "engine": engine}
