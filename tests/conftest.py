import ipaddress
import json
import re
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

PORTAL = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"
sys.path.insert(0, str(PORTAL))

STAGES = ["recon", "initial_access", "execution_persistence", "lateral_movement", "command_and_control", "exfil_impact"]
ALLOWED = {"source", "ts", "category", "src_ip", "dst_ip", "src_host", "dst_host", "user", "dst_port", "severity",
           "confidence", "technique_id", "stage", "summary", "details"}


def load(name):
    return json.loads((FIXTURES / name).read_text())


def check_aiids_alert(a: dict):
    """The rules of ai-ids aiids/ingest.py ExternalAlert, restated so tests catch drift."""
    assert set(a) <= ALLOWED, set(a) - ALLOWED
    assert re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,63}", a["source"])
    assert isinstance(a["category"], str) and len(a["category"]) <= 64
    assert isinstance(a["ts"], float)
    for k in ("src_ip", "dst_ip"):
        if k in a:
            ipaddress.ip_address(a[k])
    for k in ("src_host", "dst_host", "user"):
        if k in a:
            assert isinstance(a[k], str) and len(a[k]) <= 64
    assert any(k in a for k in ("src_ip", "dst_ip", "src_host", "dst_host", "user"))
    if "dst_port" in a:
        assert 0 <= a["dst_port"] <= 65535
    assert a["severity"] in ("low", "medium", "high", "critical")
    if "confidence" in a:
        assert 0 <= a["confidence"] <= 1
    if "technique_id" in a:
        assert re.fullmatch(r"T\d{4}(\.\d{3})?", a["technique_id"])
    if "stage" in a:
        assert a["stage"] in STAGES
    if "summary" in a:
        assert len(a["summary"]) <= 500
    assert isinstance(a["details"], dict) and len(str(a["details"])) <= 4000
    json.dumps(a)


@pytest.fixture(autouse=True)
def run_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("SECLAB_RUN_DIR", str(tmp_path / "run"))
    return tmp_path / "run"


def closed_port() -> int:
    """A local port with nothing listening (bound, then released)."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class FakeLab:
    """A tiny HTTP server that answers like one lab: routes map (method, path) to a value or a function."""

    def __init__(self, name: str, routes: dict):
        self.name, self.routes, self.requests = name, routes, []
        lab = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _answer(self, method):
                parts = urlsplit(self.path)
                body = None
                if method == "POST":
                    raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                    body = json.loads(raw) if raw and self.headers.get("Content-Type") == "application/json" else raw
                lab.requests.append((method, parts.path, parse_qs(parts.query), body))
                if parts.path == "/api/health":
                    return self._send(200, {"status": "ok", "name": lab.name, "version": "0.1.0"})
                route = lab.routes.get((method, parts.path))
                if route is None:
                    return self._send(404, {"detail": "not found"})
                out = route(body, parse_qs(parts.query)) if callable(route) else (200, route)
                self._send(*out)

            def _send(self, code, payload, headers=None):
                data = json.dumps(payload).encode()
                self.send_response(code)
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                self._answer("GET")

            def do_POST(self):
                self._answer("POST")

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def fake_lab():
    labs = []

    def make(name, routes):
        lab = FakeLab(name, routes)
        labs.append(lab)
        return lab

    yield make
    for lab in labs:
        lab.close()
