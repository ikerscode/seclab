#!/usr/bin/env python3
"""Terminal view of the lab: project status with start/stop, and the cross-lab pipeline.

Talks to the portal API on 127.0.0.1:8100.
"""
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
        {"name": "Pipeline", "endpoint": "/api/pipeline", "rows": "links",
         "columns": [["link", 30], ["status", 22], ["sent", 6], ["note", 26], ["carries", 50]]},
        {"name": "Incidents", "endpoint": "/api/pipeline", "rows": "incidents",
         "columns": [["id", 9], ["severity", 9], ["score", 6], ["alerts", 7], ["pipeline_alerts", 9],
                     ["systems", 44], ["stages", 60]]},  # Enter shows the whole incident row
    ],
    "actions": [
        {"key": "s", "label": "start selected", "method": "POST", "endpoint": "/api/start/{name}"},
        {"key": "x", "label": "stop selected", "method": "POST", "endpoint": "/api/stop/{name}", "confirm": True},
        {"key": "p", "label": "pipeline pass", "method": "POST", "endpoint": "/api/pipeline/run"},
    ],
}

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="seclab terminal view")
    ap.add_argument("--url", default="http://127.0.0.1:8100")
    ap.add_argument("--once", action="store_true", help="print once as plain text and exit")
    a = ap.parse_args()
    sys.exit(termhud.run(SPEC, a.url, a.once))
