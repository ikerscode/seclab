"""seclab demo: start the labs one by one, seed them, run the pipeline once, print the incidents.

Gentle on the laptop: one lab starts at a time and must pass its health check
before the next one, every seeding step waits for the previous to finish, and
the seclab script runs the whole demo under nice and the shared CPU lock.
Every lab the demo started is stopped again at the end, also after an error or
Ctrl+C. Labs that were already running are left running.

What the demo adds to the labs' own data (all of it simulated):
  threat-intel  the bundled offline fixtures, only if its database is empty
  honeypot-net  two days of injected attack traffic at half scale (flagged simulated)
  malware-lab   one c2_beacon specimen (sandbox run, or static only without the image)
  ics-sim       one fast setpoint_change run
  ai-ids        a model trained on the simulated dataset, only if none exists
"""
from __future__ import annotations

import signal
import subprocess
import sys
import time
from pathlib import Path

from . import bridge, state
from .labs import LabClient, LabError, path_part

PORTAL_DIR = Path(__file__).resolve().parent.parent
SECLAB = PORTAL_DIR / "seclab"
ROOT = PORTAL_DIR.parent
ORDER = ["threat-intel", "honeypot-net", "malware-lab", "ics-sim", "ai-ids"]
ICS_SCENARIO = {"key": "setpoint_change", "mitigations": ["detector", "firewall", "sis"], "mode": "fast", "seed": 1}
SPECIMEN = "c2_beacon"
HEALTH_WAIT = 180   # seconds; a first start may create a venv


class DemoError(Exception):
    pass


def say(*parts):
    print(*parts, flush=True)


def wait_job(fetch, done, what: str, timeout: float, every: float = 2.0):
    """Poll fetch() until done(result) is true; return the last result."""
    end = time.time() + timeout
    while True:
        res = fetch()
        if done(res):
            return res
        if time.time() > end:
            raise DemoError(f"{what} did not finish within {timeout:.0f} s")
        time.sleep(every)


class Demo:
    def __init__(self, clients: dict | None = None):
        self.clients = clients or bridge.default_clients()
        self.started: list[str] = []

    # ------------------------------------------------------------------ lab lifecycle
    def start(self, name: str):
        cl = self.clients[name]
        if cl.healthy():
            say(f"[{name}] already running, will leave it running")
            return
        say(f"[{name}] starting")
        proc = subprocess.run([str(SECLAB), "start", name], capture_output=True, text=True, timeout=60)
        self.started.append(name)
        if proc.returncode != 0:
            raise DemoError(f"{name} did not start: {(proc.stdout + proc.stderr).strip()[-400:]}")
        end = time.time() + HEALTH_WAIT
        while not cl.healthy():
            if time.time() > end:
                raise DemoError(f"{name} did not pass its health check in {HEALTH_WAIT} s (see .run/{name}.log)")
            time.sleep(1)
        say(f"[{name}] healthy on 127.0.0.1:{cl.port}")

    def stop_all(self):
        for name in reversed(self.started):
            proc = subprocess.run([str(SECLAB), "stop", name], capture_output=True, text=True, timeout=60)
            say(f"[{name}] " + ((proc.stdout + proc.stderr).strip().splitlines() or ["stopped"])[-1].split(": ", 1)[-1])
        self.started.clear()

    # ------------------------------------------------------------------ seeding
    def seed_threat_intel(self):
        cl = self.clients["threat-intel"]
        n = (cl.get("/api/overview").get("counts") or {}).get("indicators", 0)
        if n:
            say(f"[threat-intel] database already holds {n} indicators, seed skipped")
            return
        job = cl.post("/api/seed")
        res = wait_job(lambda: cl.get(f"/api/jobs/{path_part(job['id'])}"), lambda j: j.get("status") != "running",
                       "threat-intel seed", 600)
        say(f"[threat-intel] seed {res.get('status')}")

    def seed_honeypot(self):
        cl = self.clients["honeypot-net"]
        cl.post("/api/simulate/inject", days=2, scale=0.5)
        res = wait_job(lambda: cl.get("/api/simulate/status"),
                       lambda s: (s.get("current") or {}).get("state") != "running", "honeypot inject", 300)
        out = (res.get("current") or {}).get("result") or {}
        say(f"[honeypot-net] inject {(res.get('current') or {}).get('state')}: "
            f"{out.get('inserted', out.get('sent', '?'))} events, campaigns {sorted((out.get('campaign_events') or {}).keys())}")

    def seed_malware(self) -> str | None:
        """Run one specimen in the sandbox, or analyse it statically. Returns the sample sha256."""
        cl = self.clients["malware-lab"]
        try:
            image = bool(cl.get("/api/sandbox").get("image_present"))
        except LabError:
            image = False
        if image:
            say(f"[malware-lab] sandbox image present: detonating specimen {SPECIMEN}")
            job_id = cl.post(f"/api/specimens/{SPECIMEN}/run", timeout=30)["job"]
        else:
            path = ROOT / "malware-lab" / "specimens" / f"{SPECIMEN}.py"
            say(f"[malware-lab] no sandbox image: static-only analysis of {path.name}")
            job_id = self._upload_static(cl, path)
        job = wait_job(lambda: cl.get(f"/api/jobs/{int(job_id)}"), lambda j: j.get("status") in ("done", "error"),
                       "malware analysis", 300)
        say(f"[malware-lab] job {job.get('status')}: {str(job.get('message', ''))[:160]}")
        if job.get("status") != "done":
            return None
        sha = job.get("target") if isinstance(job.get("target"), str) and len(job["target"]) == 64 else None
        if sha is None:   # a specimen job's target is the specimen name: take the newest sample from it
            rows = [r for r in cl.get("/api/samples") if r.get("source") == f"specimen:{SPECIMEN}"]
            sha = max(rows, key=lambda r: r.get("submitted_at") or 0)["sha256"] if rows else None
        return sha

    @staticmethod
    def _upload_static(cl: LabClient, path: Path) -> int:
        res = cl.call("POST", "/api/samples", {"filename": path.name, "dynamic": "false"}, raw=path.read_bytes(), timeout=60)
        return int(res["jobs"][0])

    def seed_ics(self) -> str:
        cl = self.clients["ics-sim"]
        say(f"[ics-sim] fast run of {ICS_SCENARIO['key']} with {', '.join(ICS_SCENARIO['mitigations'])}")
        res = cl.post("/api/scenarios/run", ICS_SCENARIO, timeout=600)
        say(f"[ics-sim] run {res.get('id')}: {res.get('outcome')}, detections {sorted((res.get('attack') or {}).get('detections', {}))}")
        meta = cl.get("/api/meta")
        sc = next((s for s in meta.get("scenarios", []) if s.get("key") == ICS_SCENARIO["key"]), {})
        host = ((sc.get("attacker") or {}).get("host") or "").split(" (")[0]
        return "-".join(host.split())

    def ensure_model(self):
        cl = self.clients["ai-ids"]
        st = cl.get("/api/status")
        if st.get("trained"):
            say(f"[ai-ids] model present (trained on {((st.get('model') or {}).get('dataset')) or 'unknown'}), training skipped")
            return
        names = {d.get("name") for d in (cl.get("/api/datasets").get("datasets") or []) if isinstance(d, dict)}
        if "sim" not in names:
            say("[ai-ids] no model and no sim dataset: generating a small simulated dataset")
            job = cl.post("/api/simulate", {"name": "sim", "days": 3, "scale": 0.5})
            self._wait_aiids(job["id"], "simulate")
        say("[ai-ids] no model: training on the sim dataset")
        job = cl.post("/api/train", {"dataset": "sim"})
        self._wait_aiids(job["id"], "train")

    def _wait_aiids(self, job_id: str, what: str):
        cl = self.clients["ai-ids"]
        res = wait_job(lambda: cl.get(f"/api/jobs/{path_part(job_id)}"), lambda j: j.get("status") != "running",
                       f"ai-ids {what}", 1800, every=5)
        if res.get("status") != "done":
            raise DemoError(f"ai-ids {what} failed: {res.get('error')}")
        say(f"[ai-ids] {what} done")

    # ------------------------------------------------------------------ main flow
    def run(self) -> int:
        t0 = time.time()
        self.start("threat-intel")
        self.seed_threat_intel()
        self.start("honeypot-net")
        self.seed_honeypot()
        self.start("malware-lab")
        sha = self.seed_malware()
        self.start("ics-sim")
        ot_host = self.seed_ics()
        self.start("ai-ids")
        self.ensure_model()

        hosts = {sha: ot_host} if sha and ot_host else {}
        if hosts:
            say(f"\n[pipeline] the demo treats sample {sha[:12]} as found on {ot_host}, "
                f"the workstation the ICS scenario attacks from")
        say("[pipeline] one pass")
        rep = bridge.run_locked(clients=self.clients, sample_hosts=hosts)
        from .__main__ import print_incidents, print_report
        print_report(rep)
        st = state.load()
        say("\nCross-system incidents (ai-ids incidents holding pipeline alerts, most systems first):")
        print_incidents(st, limit=12)
        shared = st.get("shared_indicators") or []
        if shared:
            say("\nIndicators reported by more than one lab:")
            for s in shared[:10]:
                say(f"  {s['indicator']:30} {s['labs']:28} intel: {s['intel']}")
        say(f"\ndemo finished in {time.time() - t0:.0f} s")
        return 0 if not rep.get("busy") else 1


def main() -> int:
    demo = Demo()

    def on_term(*_):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, on_term)
    try:
        return demo.run()
    except KeyboardInterrupt:
        say("\ninterrupted")
        return 130
    except (DemoError, LabError, OSError, KeyError, ValueError, TypeError) as exc:
        say(f"\ndemo failed: {exc}")
        return 1
    finally:
        say("\nstopping the labs the demo started")
        demo.stop_all()


if __name__ == "__main__":
    sys.exit(main())
