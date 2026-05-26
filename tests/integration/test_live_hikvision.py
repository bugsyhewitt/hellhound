"""Optional live integration test (criterion 5 bonus).

Spins up a throwaway container masquerading as a Hikvision DVR with default
credentials, then verifies hellhound makes a live finding against it. Skipped
automatically when Docker is unavailable; only runs under `-m integration`.

    pytest -m integration

The container runs a tiny Python HTTP server (python:3.13-slim, already a
common base image) that emulates:
  GET  /                          -> 200, <title>Hikvision Network Camera</title>
  GET  /ISAPI/Security/userCheck  -> 200 for admin:12345, else 401
"""

from __future__ import annotations

import asyncio
import shutil
import socket
import subprocess
import time

import pytest

from hellhound.fingerprint import load_fingerprint_set
from hellhound.scanner import Scanner

pytestmark = pytest.mark.integration


_SERVER_SCRIPT = r'''
import base64
from http.server import BaseHTTPRequestHandler, HTTPServer

GOOD = "Basic " + base64.b64encode(b"admin:12345").decode()

class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/":
            body = b"<html><head><title>Hikvision Network Camera</title></head><body>ok</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/ISAPI/Security/userCheck"):
            if self.headers.get("Authorization") == GOOD:
                body = b"<userCheck><statusValue>200</statusValue></userCheck>"
                self.send_response(200)
            else:
                body = b"unauthorized"
                self.send_response(401)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()

HTTPServer(("0.0.0.0", 80), H).serve_forever()
'''


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        subprocess.run(
            ["docker", "info"],
            check=True,
            capture_output=True,
            timeout=15,
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return False


@pytest.fixture
def hikvision_container():
    if not _docker_available():
        pytest.skip("docker not available")

    host_port = _free_port()
    name = f"hellhound-it-hikvision-{host_port}"
    proc = subprocess.run(
        [
            "docker", "run", "-d", "--rm",
            "--name", name,
            "-p", f"127.0.0.1:{host_port}:80",
            "python:3.13-slim",
            "python", "-c", _SERVER_SCRIPT,
        ],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        pytest.skip(f"could not start container: {proc.stderr.strip()}")

    # wait for readiness
    deadline = time.time() + 30
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", host_port), timeout=1):
                break
        except OSError:
            time.sleep(0.5)
    else:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        pytest.skip("container did not become ready")

    try:
        yield host_port
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


def test_live_hikvision_default_creds(hikvision_container):
    port = hikvision_container
    fingerprints = load_fingerprint_set("default")
    scanner = Scanner(fingerprints=fingerprints, timeout=5.0)

    findings = asyncio.run(scanner.scan_host("127.0.0.1", ports=[port]))

    flagged = [f for f in findings if f.default_creds]
    assert flagged, "expected a default-creds finding against the live container"
    finding = flagged[0]
    assert finding.vendor == "Hikvision"
    assert finding.matched_credential is not None
    assert finding.matched_credential.username == "admin"
    assert finding.matched_credential.password == "12345"
