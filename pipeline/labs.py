"""Minimal JSON client for the lab APIs on 127.0.0.1.

Safety rules that the rest of the pipeline relies on:
  * the host is always 127.0.0.1, the port comes from the fixed LAB_PORTS table
    (tests may pass their own port, but never a host)
  * proxies from the environment are ignored and redirects are refused, so a
    lab answer can never send the bridge to another address
  * every call has a timeout and responses larger than MAX_BYTES are refused
"""
from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from urllib.parse import quote, urlencode

HOST = "127.0.0.1"
LAB_PORTS = {"malware-lab": 8101, "threat-intel": 8102, "honeypot-net": 8103, "ics-sim": 8104, "ai-ids": 8105}
MAX_BYTES = 8 * 1024 * 1024
TIMEOUT = 10.0


class LabError(Exception):
    """A lab could not be reached or gave an unusable answer."""

    def __init__(self, message: str, status: int | None = None, body=None):
        super().__init__(message)
        self.status = status
        self.body = body


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)


_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


class LabClient:
    def __init__(self, name: str, port: int | None = None, timeout: float = TIMEOUT):
        if port is None:
            port = LAB_PORTS[name]
        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("bad port")
        self.name, self.port, self.timeout = name, port, timeout
        self.base = f"http://{HOST}:{port}"

    def url(self, path: str, params: dict | None = None) -> str:
        if not path.startswith("/"):
            raise ValueError("path must start with /")
        return self.base + path + ("?" + urlencode(params) if params else "")

    def call(self, method: str, path: str, params: dict | None = None, body=None, timeout: float | None = None,
             raw: bytes | None = None):
        """JSON in, JSON out. `raw` sends bytes as the body instead (file upload)."""
        data = raw if raw is not None else json.dumps(body).encode("utf-8") if body is not None else None
        ctype = "application/octet-stream" if raw is not None else "application/json"
        req = urllib.request.Request(self.url(path, params), data=data, method=method,
                                     headers={"Content-Type": ctype, "Accept": "application/json"})
        try:
            with _OPENER.open(req, timeout=timeout or self.timeout) as resp:
                raw = resp.read(MAX_BYTES + 1)
        except urllib.error.HTTPError as exc:
            detail = _parse(exc.read(65536)) if exc.fp else None
            raise LabError(f"{self.name}: HTTP {exc.code}", exc.code, detail) from None
        except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            raise LabError(f"{self.name}: unreachable ({reason})") from None
        if len(raw) > MAX_BYTES:
            raise LabError(f"{self.name}: response larger than {MAX_BYTES} bytes")
        out = _parse(raw)
        if out is None:
            raise LabError(f"{self.name}: response is not JSON")
        return out

    def get(self, path: str, **params):
        return self.call("GET", path, params or None)

    def post(self, path: str, body=None, timeout: float | None = None, **params):
        return self.call("POST", path, params or None, body, timeout)

    def healthy(self, timeout: float = 2.0) -> bool:
        """True when /api/health answers ok with this lab's own name."""
        try:
            data = self.call("GET", "/api/health", timeout=timeout)
        except LabError:
            return False
        return isinstance(data, dict) and data.get("status") == "ok" and data.get("name") == self.name


def _parse(raw: bytes):
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None


def path_part(value: str) -> str:
    """Quote one path segment (for ids taken from lab answers)."""
    return quote(value, safe="")
