"""Validation helpers for values that come from the labs.

Honeypot and malware data is attacker controlled: usernames, commands, URLs and
strings inside samples are chosen by whoever attacked the sensor or wrote the
sample. Nothing from there is trusted. Each helper returns a clean value or
None, and the mapping code drops a record when a required field is None.

Nothing here resolves, fetches or executes anything. URLs are only parsed as
text so their host can be checked.
"""
from __future__ import annotations

import ipaddress
import math
import re
import time
from urllib.parse import urlsplit

_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f​-‏ -‮⁦-⁩﻿]")
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_DOMAIN = re.compile(rf"(?:{_LABEL}\.)+[a-z](?:[a-z0-9-]{{0,61}}[a-z0-9])?")
_HOST = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
_TECHNIQUE = re.compile(r"T\d{4}(?:\.\d{3})?")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_TAG = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/+-]{0,47}")
URL_SCHEMES = {"http", "https", "ftp", "tftp"}

# Addresses that are never an attacker worth forwarding (lab traffic and noise).
# Documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) are kept on
# purpose: the simulators use them as stand-ins for public attacker hosts.
_LOCAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16",
    "127.0.0.0/8", "0.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4", "::1/128", "::/128",
    "fc00::/7", "fe80::/10", "ff00::/8")]


def text(value, limit: int = 200) -> str | None:
    """Single-line printable text, cut to `limit` characters. Only str is accepted."""
    if not isinstance(value, str):
        return None
    value = _CONTROL.sub(" ", value)
    value = " ".join(value.split())
    return value[:limit] if value else None


def number(value, lo: float = 0, hi: float = 1e12) -> float | None:
    """A finite int or float inside [lo, hi]. bool is rejected (True is an int in Python)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if not math.isfinite(value) or not lo <= value <= hi:
        return None
    return value


def count(value, hi: int = 10**9) -> int | None:
    n = number(value, 0, hi)
    return int(n) if n is not None else None


def timestamp(value) -> float | None:
    """Epoch seconds between 2001 and one day from now."""
    return number(value, 1e9, time.time() + 86400)


def ip(value) -> str | None:
    if not isinstance(value, str) or len(value) > 45:
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def is_local(addr: str) -> bool:
    a = ipaddress.ip_address(addr)
    return any(a in net for net in _LOCAL_NETS if net.version == a.version)


def external_ip(value) -> str | None:
    """An IP that is not loopback, RFC 1918, link-local, multicast or similar."""
    addr = ip(value)
    return addr if addr and not is_local(addr) else None


def domain(value) -> str | None:
    if not isinstance(value, str) or len(value) > 253:
        return None
    value = value.strip().lower().rstrip(".")
    return value if _DOMAIN.fullmatch(value) else None


def host_name(value) -> str | None:
    """A host label usable as an ai-ids src_host/dst_host (max 64 characters)."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value if _HOST.fullmatch(value) else None


def url(value, limit: int = 300) -> dict | None:
    """Parse a URL as text. Returns {url, scheme, host, host_ip, host_domain} or None.

    The URL is never requested. It is only split so the host part can be checked
    and enriched. Overlong or odd URLs are rejected rather than cut, because a cut
    URL would be a different indicator.
    """
    if not isinstance(value, str) or not 0 < len(value) <= limit or _CONTROL.search(value):
        return None
    try:
        parts = urlsplit(value.strip())
        hostname = parts.hostname
    except ValueError:
        return None
    if parts.scheme.lower() not in URL_SCHEMES or not hostname:
        return None
    host_ip, host_domain = ip(hostname), None
    if host_ip is None:
        host_domain = domain(hostname)
        if host_domain is None:
            return None
    return {"url": value.strip(), "scheme": parts.scheme.lower(), "host": host_ip or host_domain,
            "host_ip": host_ip, "host_domain": host_domain}


def technique(value) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip().upper()
    return value if _TECHNIQUE.fullmatch(value) else None


def techniques(value, limit: int = 8) -> list[str]:
    """Technique ids from a list or a comma separated string."""
    if isinstance(value, str):
        value = value.split(",")
    if not isinstance(value, list):
        return []
    out = []
    for v in value:
        t = technique(v)
        if t and t not in out:
            out.append(t)
    return out[:limit]


def sha256(value) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip().lower()
    return value if _SHA256.fullmatch(value) else None


def tags(value, limit: int = 8) -> list[str]:
    if not isinstance(value, list):
        return []
    out = [v for v in value if isinstance(v, str) and _TAG.fullmatch(v)]
    return out[:limit]


def str_list(value, limit: int = 8, size: int = 64) -> list[str]:
    if not isinstance(value, list):
        return []
    out = [t for t in (text(v, size) for v in value) if t]
    return out[:limit]
