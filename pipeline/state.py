"""Pipeline state: cursors, dedup keys, an outbox and the last run report.

Stored as JSON in <seclab>/.run/pipeline-state.json (or $SECLAB_RUN_DIR). The
file can hold attacker IPs and sample hashes, so it is written with umask 077
(mode 0600) and replaced atomically so a crash never leaves half a file.
"""
from __future__ import annotations

import contextlib
import fcntl
import json
import os
import time
from pathlib import Path

PORTAL_DIR = Path(__file__).resolve().parent.parent
VERSION = 1
MAX_SENT = 20000      # dedup keys kept
MAX_OUTBOX = 2000     # alerts waiting for ai-ids
MAX_MAP = 5000        # entries in per-IP / per-sample cursor maps
MAX_OURS = 20000      # ai-ids alert ids created by the pipeline


def run_dir() -> Path:
    env = os.environ.get("SECLAB_RUN_DIR")
    return Path(env) if env else PORTAL_DIR.parent / ".run"


def state_path() -> Path:
    return run_dir() / "pipeline-state.json"


def empty() -> dict:
    return {
        "version": VERSION,
        "honeypot": {"ips": {}, "download_id": 0},
        "malware": {"samples": {}},
        "ics": {"runs": [], "live_id": 0, "live_mb_id": 0, "live_t": 0.0},
        "intel_cache": {},
        "sent": {},
        "outbox": [],
        "aiids_alert_ids": [],
        "shared_indicators": [],
        "ioc_seen": {},
        "incidents": [],
        "last_run": None,
        "totals": {"forwarded": 0, "rejected": 0, "runs": 0},
    }


def load(path: Path | None = None) -> dict:
    path = path or state_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return empty()
    if not isinstance(data, dict) or data.get("version") != VERSION:
        return empty()
    base = empty()
    for key, value in base.items():
        if value is None:
            data.setdefault(key, None)
        elif not isinstance(data.get(key), type(value)):
            data[key] = value
    for key in ("honeypot", "malware", "ics"):
        for sub, value in base[key].items():
            kind = (int, float) if isinstance(value, (int, float)) else type(value)
            got = data[key].get(sub)
            if not isinstance(got, kind) or isinstance(got, bool):
                data[key][sub] = value
    return data


def _trim_map(m: dict, limit: int, key=None) -> dict:
    if len(m) <= limit:
        return m
    items = sorted(m.items(), key=key or (lambda kv: kv[1] if isinstance(kv[1], (int, float)) else 0))
    return dict(items[-limit:])


def compact(st: dict) -> dict:
    """Keep every collection bounded so the file cannot grow without limit."""
    st["sent"] = _trim_map(st["sent"], MAX_SENT)
    st["outbox"] = st["outbox"][-MAX_OUTBOX:]
    st["aiids_alert_ids"] = st["aiids_alert_ids"][-MAX_OURS:]
    st["honeypot"]["ips"] = _trim_map(st["honeypot"]["ips"], MAX_MAP, key=lambda kv: kv[1].get("last_seen", 0))
    st["malware"]["samples"] = _trim_map(st["malware"]["samples"], MAX_MAP, key=lambda kv: kv[1].get("at", 0))
    st["ics"]["runs"] = st["ics"]["runs"][-500:]
    st["intel_cache"] = _trim_map(st["intel_cache"], MAX_MAP, key=lambda kv: kv[1].get("at", 0))
    return st


def save(st: dict, path: Path | None = None) -> None:
    path = path or state_path()
    old = os.umask(0o077)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(compact(st), separators=(",", ":")), encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        os.umask(old)


@contextlib.contextmanager
def exclusive(path: Path | None = None):
    """Only one pipeline run at a time (CLI, --watch and the portal button share it).

    Yields True when the lock was taken, False when another run holds it.
    """
    lock_path = (path or state_path()).with_suffix(".lock")
    old = os.umask(0o077)
    try:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        fh = open(lock_path, "a")
    finally:
        os.umask(old)
    try:
        try:
            fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            yield False
            return
        yield True
    finally:
        fh.close()


def now() -> float:
    return time.time()
