#!/usr/bin/env python3
"""What the CKAN job would do: send the file, then ask for the result.

Usage: demo_client.py FILE [http://localhost:8088]
"""

import hashlib
import http.client
import json
import os
import sys
import time
from urllib.parse import urlsplit

POLL_SECONDS = 2


class HashingReader:
    """Calculates the sha256 of what is actually sent, while it is sent."""

    def __init__(self, file):
        self.file = file
        self.digest = hashlib.sha256()

    def read(self, size=-1):
        chunk = self.file.read(size)
        self.digest.update(chunk)
        return chunk


def main(path, base_url="http://localhost:8088"):
    url = urlsplit(base_url)
    size = os.path.getsize(path)
    started = time.time()

    conn = http.client.HTTPConnection(url.hostname, url.port)
    with open(path, "rb") as file:
        reader = HashingReader(file)
        conn.request(
            "POST",
            "/scans",
            body=reader,
            headers={
                "Content-Length": str(size),
                "Content-Type": "application/octet-stream",
            },
        )
        response = conn.getresponse()
        body = json.loads(response.read())
    if response.status != 202:
        sys.exit(f"Rejected: {response.status} {body}")
    scan_id = body["scan_id"]
    print(f"Received in {time.time() - started:.1f}s: scan_id={scan_id}")

    while True:
        time.sleep(POLL_SECONDS)
        conn = http.client.HTTPConnection(url.hostname, url.port)
        conn.request("GET", f"/scans/{scan_id}")
        response = conn.getresponse()
        result = json.loads(response.read())
        conn.close()
        if response.status == 404:
            sys.exit("The service lost this scan: the job would send the file again")
        if result["status"] == "done":
            break
        print(f"  {result['status']}...")

    if result["size"] != size or result["sha256"] != reader.digest.hexdigest():
        sys.exit("The service got different bytes: the job would send the file again")

    print(f"Finished in {time.time() - started:.1f}s")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    main(*sys.argv[1:3])
