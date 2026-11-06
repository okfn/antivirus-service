"""Small HTTP antivirus service.

Receives a file, answers right away with a scan_id, scans it in the background
and lets the client ask for the result. It knows nothing about CKAN.

State lives in memory on purpose: if the process restarts, a known scan_id
becomes a 404 and the client sends the file again.
"""

import hashlib
import logging
import os
import shutil
import tempfile
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from flask import Flask, jsonify, request

import clamd_engine

log = logging.getLogger("antivirus")

CHUNK_SIZE = 1024 * 1024
MB = 1024 * 1024


def _env_int(name, default):
    return int(os.environ.get(name, default))


def create_app(engine=clamd_engine, tmp_dir=None):
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    max_file_size = _env_int("MAX_FILE_SIZE_MB", 1600) * MB
    min_free_disk = _env_int("MIN_FREE_DISK_MB", 500) * MB
    max_active = _env_int("MAX_ACTIVE_SCANS", 5)
    result_ttl = _env_int("RESULT_TTL_SECONDS", 3600)
    tmp_dir = tmp_dir or os.environ.get("TMP_DIR") or tempfile.gettempdir()

    app = Flask(__name__)
    executor = ThreadPoolExecutor(max_workers=_env_int("SCAN_CONCURRENCY", 1))
    scans = {}
    lock = threading.Lock()

    def public(scan):
        return {k: v for k, v in scan.items() if not k.startswith("_")}

    def purge_expired():
        now = time.time()
        for scan_id, scan in list(scans.items()):
            if scan["status"] == "done" and now - scan["_finished"] > result_ttl:
                del scans[scan_id]

    def run_scan(scan_id, path):
        with lock:
            scans[scan_id]["status"] = "scanning"
        started = time.time()
        try:
            result = engine.scan(path)
        except Exception as exc:
            log.exception("Scan %s crashed", scan_id)
            result = {
                "verdict": "error",
                "signature": None,
                "engine": None,
                "details": str(exc),
            }
        finally:
            os.unlink(path)
        with lock:
            scan = scans[scan_id]
            scan.update(result)
            scan["status"] = "done"
            scan["scan_seconds"] = round(time.time() - started, 1)
            scan["_finished"] = time.time()
            log.info("scan_result %s", public(scan))

    # TODO(auth): optional token for networks that are not closed.
    # TODO(remote): document TLS for a service outside the private network.

    @app.post("/scans")
    def create_scan():
        length = request.content_length
        if length is None:
            return jsonify(error="Content-Length is required"), 411
        if length > max_file_size:
            return jsonify(error="File too large", max_bytes=max_file_size), 413
        if shutil.disk_usage(tmp_dir).free < length + min_free_disk:
            return jsonify(error="Not enough disk"), 507

        scan_id = str(uuid.uuid4())
        with lock:
            purge_expired()
            active = sum(1 for s in scans.values() if s["status"] != "done")
            if active >= max_active:
                return jsonify(error="Too many active scans"), 429
            # Takes a slot now, but stays hidden until the file is complete.
            scans[scan_id] = {"status": "receiving"}

        digest = hashlib.sha256()
        size = 0
        complete = False
        tmp = tempfile.NamedTemporaryFile(dir=tmp_dir, delete=False)
        try:
            with tmp:
                while chunk := request.stream.read(CHUNK_SIZE):
                    tmp.write(chunk)
                    digest.update(chunk)
                    size += len(chunk)
            complete = size == length
        finally:
            if not complete:
                os.unlink(tmp.name)
                with lock:
                    del scans[scan_id]
        if not complete:
            # Never scan a partial file: its verdict would say nothing.
            return jsonify(error="Incomplete upload"), 400

        with lock:
            scans[scan_id] = {
                "scan_id": scan_id,
                "status": "queued",
                "size": size,
                "sha256": digest.hexdigest(),
                "verdict": None,
                "signature": None,
                "engine": None,
                "details": None,
            }
            body = public(scans[scan_id])
        executor.submit(run_scan, scan_id, tmp.name)
        return jsonify(body), 202

    @app.get("/scans/<scan_id>")
    def get_scan(scan_id):
        with lock:
            purge_expired()
            scan = scans.get(scan_id)
            if scan is None or scan["status"] == "receiving":
                return jsonify(error="Unknown scan"), 404
            return jsonify(public(scan))

    @app.get("/health")
    def health():
        try:
            return jsonify(status="ok", engine=engine.version())
        except Exception as exc:
            return jsonify(status="unavailable", details=str(exc)), 503

    return app
