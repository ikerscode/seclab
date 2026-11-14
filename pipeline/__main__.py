"""seclab pipeline [--once | --watch [SECONDS]] [--malware-host NAME] [--status]

Run from the portal folder: python3 -m pipeline ...
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time

from . import bridge, state


def print_report(rep: dict) -> None:
    if rep.get("busy"):
        print("pipeline: " + rep["error"])
        return
    up = rep["labs"]
    print("labs:  " + "  ".join(f"{n}={'up' if u else 'down'}" for n, u in up.items()))
    print(f"{'LINK':32} {'STATUS':34} {'SENT':>5}  NOTE")
    for r in rep["links"]:
        print(f"{r['link']:32} {r['status']:34} {r['sent']:>5}  {r['note']}")
    f = rep["forward"]
    print(f"ai-ids: {f['accepted']} accepted, {f['rejected']} rejected, {rep['outbox']} waiting in outbox"
          + (f" ({f['note']})" if f.get("note") else ""))
    print(f"incidents with pipeline alerts: {rep['incidents']} ({rep['cross_system_incidents']} span more than one system)")
    for e in rep["errors"][:10]:
        print("  error: " + e)


def print_incidents(st: dict, limit: int = 15) -> None:
    rows = st.get("incidents", [])
    if not rows:
        print("no ai-ids incidents contain pipeline alerts yet")
        return
    print(f"{'INCIDENT':10} {'SEV':9} {'SCORE':>5} {'ALERTS':>6}  SYSTEMS / STAGES")
    for i in rows[:limit]:
        print(f"{i['id']:10} {i['severity'] or '-':9} {i['score'] or 0:5.1f} {i['alerts'] or 0:6}  {i['systems']}")
        print(f"{'':34}{i['stages']}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="seclab pipeline", description="bridge the labs into ai-ids")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--once", action="store_true", help="one pass (default)")
    mode.add_argument("--watch", nargs="?", const=30, type=int, metavar="SECONDS", help="repeat every SECONDS (default 30)")
    mode.add_argument("--status", action="store_true", help="print the last report and incidents, contact nothing")
    ap.add_argument("--malware-host", default=os.environ.get("SECLAB_MALWARE_HOST"),
                    help="host the malware-lab samples were found on (e.g. CORP-WS-37); default: the sample itself")
    ap.add_argument("--json", action="store_true", help="print the report as JSON")
    a = ap.parse_args(argv)

    if a.status:
        s = bridge.summary()
        if a.json:
            print(json.dumps(s, indent=1))
            return 0
        when = (s["last_run"] or {}).get("finished")
        print("last pass: " + (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(when)) if when else "never"))
        for r in s["links"]:
            print(f"{r['link']:32} {r['status']:34} {r['sent']:>5}  {r['note']}")
        print(f"outbox: {s['outbox']}   totals: {s['totals']}")
        print_incidents(state.load())
        return 0

    def one() -> dict:
        rep = bridge.run_locked(a.malware_host, log=print if not a.json else None)
        if a.json:
            print(json.dumps(rep, indent=1, default=str))
        else:
            print_report(rep)
            if not rep.get("busy"):
                print_incidents(state.load())
        return rep

    if a.watch is None:
        rep = one()
        return 1 if rep.get("busy") else 0
    interval = max(5, a.watch)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    try:
        while True:
            print(time.strftime("\n== %H:%M:%S pipeline pass"))
            one()
            time.sleep(interval)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
