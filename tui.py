#!/usr/bin/env python3
"""Terminal view of the lab: project status with start/stop (talks to the portal API on 127.0.0.1:8100)."""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import termhud  # noqa: E402

SPEC = {
    "title": "SECLAB",
    "refresh": 5,
    "views": [
        {"name": "Projects", "endpoint": "/api/status", "rows": "",
         "columns": [["name", 14], ["port", 6], ["up", 6], ["version", 8], ["description", 70]]},
    ],
    "actions": [
        {"key": "s", "label": "start selected", "method": "POST", "endpoint": "/api/start/{name}"},
        {"key": "x", "label": "stop selected", "method": "POST", "endpoint": "/api/stop/{name}", "confirm": True},
    ],
}

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="seclab terminal view")
    ap.add_argument("--url", default="http://127.0.0.1:8100")
    ap.add_argument("--once", action="store_true", help="print once as plain text and exit")
    a = ap.parse_args()
    sys.exit(termhud.run(SPEC, a.url, a.once))
