#!/usr/bin/env python3
"""Seclab portal: a status page and launcher for the lab projects.

Listens on 127.0.0.1:8100 only. Health checks run here on the server side,
so the browser never has to reach the project ports directly. Start and stop
are delegated to the seclab script, and only for the known project names.
"""

import json
import subprocess
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

HOST = "127.0.0.1"
PORT = 8100
HERE = Path(__file__).resolve().parent
STATIC_DIR = HERE / "static"
SECLAB = HERE / "seclab"

HEALTH_TIMEOUT = 1.5   # seconds per project health check
COMMAND_TIMEOUT = 30   # seconds for seclab start or stop

# Only requests addressed to the portal itself are served (blocks DNS rebinding
# and cross-site POSTs from other origins).
ALLOWED_HOSTS = {f"127.0.0.1:{PORT}", f"localhost:{PORT}"}
ALLOWED_ORIGINS = {f"http://{h}" for h in ALLOWED_HOSTS}

PROJECTS = [
    {
        "name": "malware-lab",
        "title": "Malware Lab",
        "port": 8101,
        "description": "Isolated sandbox for static and dynamic malware analysis, IOC extraction, classification and reports.",
    },
    {
        "name": "threat-intel",
        "title": "Threat Intel",
        "port": 8102,
        "description": "Collects public threat intelligence and correlates infrastructure, ransomware groups, techniques, phishing and vulnerabilities.",
    },
    {
        "name": "honeypot-net",
        "title": "Honeypot Net",
        "port": 8103,
        "description": "Distributed low-interaction honeypot sensors with brute-force, exploit, infrastructure and geo/time analysis.",
    },
    {
        "name": "ics-sim",
        "title": "ICS Sim",
        "port": 8104,
        "description": "Water treatment plant simulator with PLC, SIS, Modbus and attack/mitigation scenarios.",
    },
    {
        "name": "ai-ids",
        "title": "AI IDS",
        "port": 8105,
        "description": "Anomaly and ML intrusion detection with explanations, false-positive reduction and cross-system correlation.",
    },
]
PROJECTS_BY_NAME = {p["name"]: p for p in PROJECTS}

# Local services only: ignore any proxy settings from the environment.
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
}


def check_project(project):
    """Return the public status record for one project."""
    record = {
        "name": project["name"],
        "title": project["title"],
        "port": project["port"],
        "url": f"http://{HOST}:{project['port']}/",
        "up": False,
        "version": None,
        "description": project["description"],
    }
    health_url = f"http://{HOST}:{project['port']}/api/health"
    try:
        with _OPENER.open(health_url, timeout=HEALTH_TIMEOUT) as resp:
            data = json.loads(resp.read(65536).decode("utf-8", "replace"))
    except (OSError, ValueError):
        return record

    if isinstance(data, dict) and data.get("status") == "ok" and data.get("name") == project["name"]:
        record["up"] = True
        record["version"] = str(data.get("version") or "")[:32] or None
    return record


def all_status():
    """Check every project in parallel so one slow port cannot delay the rest."""
    with ThreadPoolExecutor(max_workers=len(PROJECTS)) as pool:
        return list(pool.map(check_project, PROJECTS))


def run_seclab(action, name):
    """Run the seclab script for one project. Returns (http_status, payload)."""
    try:
        proc = subprocess.run(
            [str(SECLAB), action, name],
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            timeout=COMMAND_TIMEOUT,
            cwd=str(HERE),
        )
    except subprocess.TimeoutExpired:
        return 504, {"ok": False, "output": f"seclab {action} {name} timed out"}
    except OSError as exc:
        return 500, {"ok": False, "output": f"cannot run seclab script: {exc}"}

    ok = proc.returncode == 0
    output = (proc.stdout + proc.stderr).strip()
    return (200 if ok else 500), {"ok": ok, "output": output}


class PortalHandler(BaseHTTPRequestHandler):
    server_version = "seclab-portal"

    def _send(self, code, body, content_type):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, payload):
        self._send(code, json.dumps(payload).encode("utf-8"), "application/json; charset=utf-8")

    def _host_allowed(self):
        return self.headers.get("Host") in ALLOWED_HOSTS

    def _origin_allowed(self):
        origin = self.headers.get("Origin")
        return origin is None or origin in ALLOWED_ORIGINS

    def _static(self, relative):
        root = STATIC_DIR.resolve()
        target = (root / relative).resolve()
        if not target.is_relative_to(root) or not target.is_file():
            return self._json(404, {"error": "not found"})
        ctype = CONTENT_TYPES.get(target.suffix, "application/octet-stream")
        self._send(200, target.read_bytes(), ctype)

    def do_GET(self):
        if not self._host_allowed():
            return self._json(403, {"error": "host not allowed"})
        path = urlsplit(self.path).path
        if path in ("/", "/index.html"):
            return self._static("index.html")
        if path.startswith("/static/"):
            return self._static(path[len("/static/"):])
        if path == "/api/status":
            return self._json(200, all_status())
        return self._json(404, {"error": "not found"})

    def do_POST(self):
        if not self._host_allowed() or not self._origin_allowed():
            return self._json(403, {"error": "request not allowed"})
        parts = urlsplit(self.path).path.strip("/").split("/")
        if (
            len(parts) == 3
            and parts[0] == "api"
            and parts[1] in ("start", "stop")
            and parts[2] in PROJECTS_BY_NAME
        ):
            code, payload = run_seclab(parts[1], parts[2])
            return self._json(code, payload)
        return self._json(404, {"error": "unknown project or action"})


def main():
    try:
        httpd = ThreadingHTTPServer((HOST, PORT), PortalHandler)
    except OSError as exc:
        sys.exit(f"seclab portal: cannot bind {HOST}:{PORT}: {exc}")

    print(f"seclab portal on http://{HOST}:{PORT}/ (Ctrl+C to stop)", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
