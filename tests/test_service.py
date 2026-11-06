import io
import socket
import struct
import threading
import time

import pytest

import app as service
import clamd_engine


class FakeEngine:
    def __init__(self, result=None, error=None):
        self.result = result or {
            "verdict": "clean",
            "signature": None,
            "engine": "fake",
            "details": None,
        }
        self.error = error
        self.scanned = []

    def scan(self, path):
        with open(path, "rb") as file:
            self.scanned.append(file.read())
        if self.error:
            raise self.error
        return self.result

    def version(self):
        return "fake 1.0"


def wait_done(client, scan_id):
    for _ in range(100):
        body = client.get(f"/scans/{scan_id}").get_json()
        if body["status"] == "done":
            return body
        time.sleep(0.01)
    raise AssertionError("Scan did not finish")


@pytest.fixture
def engine():
    return FakeEngine()


@pytest.fixture
def client(engine, tmp_path):
    return service.create_app(engine=engine, tmp_dir=str(tmp_path)).test_client()


def test_scan_answers_right_away_and_reports_result(client, engine):
    response = client.post("/scans", data=b"hello")
    assert response.status_code == 202
    body = response.get_json()
    assert body["status"] == "queued"
    assert body["size"] == 5

    result = wait_done(client, body["scan_id"])
    assert result["verdict"] == "clean"
    assert engine.scanned == [b"hello"]


def test_temp_file_is_deleted_after_the_scan(client, tmp_path):
    scan_id = client.post("/scans", data=b"hello").get_json()["scan_id"]
    wait_done(client, scan_id)
    assert list(tmp_path.iterdir()) == []


def test_unknown_scan_is_404(client):
    assert client.get("/scans/nope").status_code == 404


def test_engine_crash_is_an_error_and_never_clean(tmp_path):
    engine = FakeEngine(error=RuntimeError("boom"))
    client = service.create_app(engine=engine, tmp_dir=str(tmp_path)).test_client()
    scan_id = client.post("/scans", data=b"hello").get_json()["scan_id"]
    result = wait_done(client, scan_id)
    assert result["verdict"] == "error"
    assert result["details"] == "boom"


def test_too_large_is_rejected(engine, tmp_path, monkeypatch):
    monkeypatch.setenv("MAX_FILE_SIZE_MB", "1")
    client = service.create_app(engine=engine, tmp_dir=str(tmp_path)).test_client()
    response = client.post("/scans", data=b"x" * (1024 * 1024 + 1))
    assert response.status_code == 413
    assert engine.scanned == []


def test_too_many_active_scans_is_429(tmp_path, monkeypatch):
    monkeypatch.setenv("MAX_ACTIVE_SCANS", "0")
    client = service.create_app(
        engine=FakeEngine(), tmp_dir=str(tmp_path)
    ).test_client()
    assert client.post("/scans", data=b"hello").status_code == 429


def test_incomplete_upload_is_not_scanned(client, engine, tmp_path):
    response = client.post(
        "/scans",
        input_stream=io.BytesIO(b"hello"),
        environ_overrides={"CONTENT_LENGTH": "10"},
    )
    assert response.status_code == 400
    assert engine.scanned == []
    assert list(tmp_path.iterdir()) == []


def test_results_expire(engine, tmp_path, monkeypatch):
    monkeypatch.setenv("RESULT_TTL_SECONDS", "0")
    client = service.create_app(engine=engine, tmp_dir=str(tmp_path)).test_client()
    scan_id = client.post("/scans", data=b"hello").get_json()["scan_id"]
    for _ in range(100):
        if client.get(f"/scans/{scan_id}").status_code == 404:
            return
        time.sleep(0.01)
    raise AssertionError("Result did not expire")


@pytest.mark.parametrize(
    "reply,verdict,signature",
    [
        ("stream: OK", "clean", None),
        ("stream: Win.Test.EICAR_HDB-1 FOUND", "infected", "Win.Test.EICAR_HDB-1"),
        ("stream: Heuristics.Limits.Exceeded.MaxFileSize FOUND", "error", None),
        ("INSTREAM size limit exceeded. ERROR", "error", None),
        ("", "error", None),
        ("something new", "error", None),
    ],
)
def test_only_an_explicit_ok_is_clean(reply, verdict, signature):
    result = clamd_engine.parse_reply(reply)
    assert result["verdict"] == verdict
    assert result["signature"] == signature


def _fake_clamd(reply, received):
    server = socket.create_server(("127.0.0.1", 0))

    def serve():
        for _ in range(3):
            conn, _addr = server.accept()
            with conn, conn.makefile("rb") as stream:
                command = b""
                while not command.endswith(b"\0"):
                    command += stream.read(1)
                if command == b"zPING\0":
                    conn.sendall(b"PONG\0")
                elif command == b"zVERSION\0":
                    conn.sendall(b"ClamAV fake\0")
                else:
                    while size := struct.unpack("!L", stream.read(4))[0]:
                        received.append(stream.read(size))
                    conn.sendall(reply + b"\0")
        server.close()

    threading.Thread(target=serve, daemon=True).start()
    return server.getsockname()[1]


def test_engine_speaks_instream(tmp_path, monkeypatch):
    received = []
    port = _fake_clamd(b"stream: OK", received)
    monkeypatch.setenv("CLAMD_HOST", "127.0.0.1")
    monkeypatch.setenv("CLAMD_PORT", str(port))
    path = tmp_path / "file"
    path.write_bytes(b"hello")

    result = clamd_engine.scan(str(path))

    assert b"".join(received) == b"hello"
    assert result["verdict"] == "clean"
    assert result["engine"] == "ClamAV fake"


def test_engine_connection_lost_without_reply_is_an_error(tmp_path, monkeypatch):
    server = socket.create_server(("127.0.0.1", 0))

    def serve():
        for reply in (b"PONG\0", b"ClamAV fake\0", None):
            conn, _addr = server.accept()
            with conn:
                conn.recv(100)
                if reply:
                    conn.sendall(reply)

    threading.Thread(target=serve, daemon=True).start()
    monkeypatch.setenv("CLAMD_HOST", "127.0.0.1")
    monkeypatch.setenv("CLAMD_PORT", str(server.getsockname()[1]))
    path = tmp_path / "file"
    path.write_bytes(b"hello")

    assert clamd_engine.scan(str(path))["verdict"] == "error"
