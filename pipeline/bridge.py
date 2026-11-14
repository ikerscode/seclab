"""One pipeline pass: poll the labs, enrich, forward to ai-ids, read incidents back.

Fail soft: a lab that is down only switches off the links that need it. Alerts
that cannot reach ai-ids wait in the state outbox and go out on the next pass,
so source cursors can still move forward without losing anything.
"""
from __future__ import annotations

import time

from . import SOURCES, clean, mapping, state as statemod
from .labs import LabClient, LabError, path_part

BATCH = 200            # alerts per POST /api/ingest (ai-ids allows 500)
ENRICH_BATCH = 500     # IOCs per POST /api/enrich
INTEL_TTL = 6 * 3600   # seconds an enrichment answer is reused
MAX_SAMPLE_FETCH = 50  # sample detail calls per pass
MAX_RUN_FETCH = 20     # ics-sim run detail calls per pass
MAX_INCIDENT_FETCH = 40

LINKS = [
    ("honeypot-net", "threat-intel", "attacker IPs and download URLs enriched"),
    ("malware-lab", "threat-intel", "sample IOCs enriched"),
    ("honeypot-net", "ai-ids", "brute force, exploits, shell use, payload downloads"),
    ("malware-lab", "ai-ids", "malware execution and C2 contacts"),
    ("ics-sim", "ai-ids", "detector alerts, SIS trips, blocked Modbus writes"),
    ("threat-intel", "ai-ids", "matches against public intel"),
]


def default_clients(ports: dict | None = None) -> dict:
    ports = ports or {}
    names = ("honeypot-net", "malware-lab", "ics-sim", "threat-intel", "ai-ids")
    return {n: LabClient(n, ports.get(n)) for n in names}


class Pass:
    """State for one run of the bridge."""

    def __init__(self, st: dict, clients: dict, malware_host: str | None = None, log=None,
                 sample_hosts: dict | None = None):
        self.st, self.clients, self.malware_host = st, clients, malware_host
        self.sample_hosts = {k.lower(): v for k, v in (sample_hosts or {}).items()}
        self.log = log or (lambda *a: None)
        self.now = time.time()
        self.up: dict[str, bool] = {}
        self.counts = {n: {"fetched": 0, "alerts": 0, "forwarded": 0, "rejected": 0, "skipped": 0} for n in SOURCES}
        self.enrich = {"honeypot-net": {"iocs": 0, "notable": 0}, "malware-lab": {"iocs": 0, "notable": 0}}
        self.errors: list[str] = []
        self.items: list[dict] = []

    # ------------------------------------------------------------------ sources
    def err(self, msg: str):
        self.errors.append(clean.text(msg, 300) or "error")
        self.log("  !", msg)

    def _counter(self, alert: dict) -> dict:
        """Per-source counters; an unknown source (only possible for a damaged outbox) counts nowhere."""
        return self.counts.get(alert.get("source"), {"alerts": 0, "forwarded": 0, "rejected": 0})

    def _tally(self, lab: str, stats: dict):
        c = self.counts[lab]
        c["fetched"] += stats.get("fetched", 0)
        c["rejected"] += stats.get("rejected", 0)
        c["skipped"] += stats.get("skipped_local", 0) + stats.get("skipped_benign", 0)

    def poll_honeypot(self):
        cl, hp = self.clients["honeypot-net"], self.st["honeypot"]
        try:
            infra = cl.get("/api/infrastructure")
            try:
                camps = cl.get("/api/campaigns")
            except LabError as exc:
                camps = {}
                self.err(f"honeypot-net campaigns: {exc}")
            downloads = cl.get("/api/events", event_type="download_attempt", limit=1000)
        except LabError as exc:
            return self.err(str(exc))
        items, hp["ips"], s1 = mapping.honeypot_ip_items(infra, camps, hp["ips"])
        dl_items, hp["download_id"], s2 = mapping.honeypot_download_items(downloads, hp["download_id"])
        self._tally("honeypot-net", s1)
        self._tally("honeypot-net", s2)
        self.items += items + dl_items

    def poll_malware(self):
        cl, seen = self.clients["malware-lab"], self.st["malware"]["samples"]
        try:
            rows = cl.get("/api/samples")
        except LabError as exc:
            return self.err(str(exc))
        if not isinstance(rows, list):
            return self.err("malware-lab: /api/samples is not a list")
        fetched = 0
        for row in rows[:2000]:
            sig = mapping.sample_signature(row)
            if sig is None:
                continue
            sha = row["sha256"].lower()
            # Samples named in sample_hosts are always re-read: a re-run of the same specimen
            # keeps its sha and verdict, but is a new analysis (its dedup key has the new time).
            if seen.get(sha, {}).get("sig") == sig and sha not in self.sample_hosts:
                continue
            if fetched >= MAX_SAMPLE_FETCH:
                break                                  # the rest waits for the next pass
            fetched += 1
            try:
                detail = cl.get(f"/api/samples/{path_part(sha)}")
            except LabError as exc:
                self.err(f"sample {sha[:12]}: {exc}")
                continue
            items, stats = mapping.malware_items(detail, self.sample_hosts.get(sha) or self.malware_host)
            self._tally("malware-lab", stats)
            self.items += items
            seen[sha] = {"sig": sig, "at": self.now}

    def poll_ics(self):
        cl, ics = self.clients["ics-sim"], self.st["ics"]
        try:
            hosts = mapping.ics_hosts(cl.get("/api/meta"))
            runs = cl.get("/api/runs")
            st = cl.get("/api/state")
            events = cl.get("/api/events", limit=2000)
            modbus = cl.get("/api/modbus", limit=2000)
        except LabError as exc:
            return self.err(str(exc))
        cursor = {k: ics.get(k, 0) for k in ("live_id", "live_mb_id", "live_t")}
        items, cursor, stats = mapping.ics_live_items(events, modbus, st, hosts, cursor, self.now)
        ics.update(cursor)
        self._tally("ics-sim", stats)
        self.items += items
        done = set(ics["runs"])
        fetched = 0
        for r in (runs if isinstance(runs, list) else [])[:200][::-1]:
            run_id = clean.text(r.get("id"), 40) if isinstance(r, dict) else None
            if run_id is None or run_id in done:
                continue
            if r.get("mode") != "fast":
                ics["runs"].append(run_id)            # real-time runs already reached us as live events
                continue
            if fetched >= MAX_RUN_FETCH:
                break
            fetched += 1
            try:
                detail = cl.get(f"/api/runs/{path_part(run_id)}")
            except LabError as exc:
                self.err(f"ics run {run_id}: {exc}")
                if exc.status == 404:
                    ics["runs"].append(run_id)        # report deleted: do not ask again
                continue
            items, stats = mapping.ics_run_items(detail, r.get("created"), hosts)
            self._tally("ics-sim", stats)
            self.items += items
            ics["runs"].append(run_id)

    # ------------------------------------------------------------------ enrichment
    def enrich_items(self):
        """Ask threat-intel about every IOC of the new items (cached for INTEL_TTL)."""
        todo = [i for i in self.items if i["lab"] in self.enrich and i["iocs"]]
        if not todo:
            return
        cache = self.st["intel_cache"]
        values = sorted({v for i in todo for v in i["iocs"]})
        missing = [v for v in values if self.now - cache.get(v, {}).get("at", 0) > INTEL_TTL]
        if missing and self.up.get("threat-intel"):
            cl = self.clients["threat-intel"]
            for k in range(0, len(missing), ENRICH_BATCH):
                try:
                    res = cl.post("/api/enrich", {"iocs": missing[k:k + ENRICH_BATCH]}, timeout=30)
                except LabError as exc:
                    self.err(f"enrich: {exc}")
                    break
                for value, info in mapping.intel_index(res).items():
                    cache[value] = {"at": self.now, "info": info}
        intel = {v: cache[v]["info"] for v in values if v in cache}
        for item in todo:
            self.enrich[item["lab"]]["iocs"] += len(item["iocs"])
        extra = mapping.apply_intel(todo, intel)
        for e in extra:
            lab = e["alert"]["details"].get("seen_by")
            if lab in self.enrich:
                self.enrich[lab]["notable"] += 1
        for item in todo:
            if not any(v in intel for v in item["iocs"]):
                item["alert"]["details"]["intel"] = "not checked (threat-intel down)" if not self.up.get("threat-intel") \
                    else "no match"
        self.items += extra

    # ------------------------------------------------------------------ cross-lab overlaps
    def note_shared(self):
        """Indicators that more than one lab reported (e.g. a honeypot download host that is also a sample's C2)."""
        seen = self.st.setdefault("ioc_seen", {})
        for item in self.items:
            if item["lab"] not in ("honeypot-net", "malware-lab"):
                continue
            for v in item["iocs"]:
                if clean.sha256(v):
                    continue
                labs = seen.setdefault(v, [])
                if item["lab"] not in labs:
                    labs.append(item["lab"])
        if len(seen) > 5000:
            self.st["ioc_seen"] = dict(list(seen.items())[-5000:])
        cache = self.st["intel_cache"]
        self.st["shared_indicators"] = [
            {"indicator": mapping.defang(v), "labs": ", ".join(sorted(labs)),
             "intel": cache.get(v, {}).get("info", {}).get("verdict", "-")}
            for v, labs in self.st["ioc_seen"].items() if len(labs) > 1][:50]

    # ------------------------------------------------------------------ ai-ids
    def queue(self):
        sent, outbox = self.st["sent"], self.st["outbox"]
        queued = {o["key"] for o in outbox}
        for item in self.items:
            if item["key"] in sent or item["key"] in queued:
                continue
            queued.add(item["key"])
            outbox.append({"key": item["key"], "alert": item["alert"]})
            self._counter(item["alert"])["alerts"] += 1

    def forward(self) -> dict:
        outbox = self.st["outbox"]
        result = {"pending_before": len(outbox), "accepted": 0, "rejected": 0, "incidents_touched": []}
        if not outbox:
            return result
        if not self.up.get("ai-ids"):
            result["note"] = "ai-ids is down; alerts kept in the outbox"
            return result
        cl, keep = self.clients["ai-ids"], []
        batches = [outbox[k:k + BATCH] for k in range(0, len(outbox), BATCH)]
        for n, batch in enumerate(batches):
            ok = self._send(cl, batch, result)
            if not ok:
                keep = [o for b in batches[n:] for o in b]
                break
        self.st["outbox"] = keep
        self.st["totals"]["forwarded"] += result["accepted"]
        self.st["totals"]["rejected"] += result["rejected"]
        return result

    def _send(self, cl, batch: list, result: dict, retry: bool = True) -> bool:
        try:
            res = cl.post("/api/ingest", {"alerts": [o["alert"] for o in batch]}, timeout=60)
        except LabError as exc:
            if exc.status == 422 and retry and isinstance(exc.body, dict):
                bad = {e.get("index") for e in exc.body.get("errors", []) if isinstance(e, dict)}
                for i in sorted(i for i in bad if isinstance(i, int) and 0 <= i < len(batch)):
                    self.err(f"ai-ids refused {batch[i]['key'][:80]}: {str(exc.body['errors'])[:200]}")
                    self._counter(batch[i]["alert"])["rejected"] += 1
                    result["rejected"] += 1
                good = [o for i, o in enumerate(batch) if i not in bad]
                return self._send(cl, good, result, retry=False) if good else True
            self.err(f"ingest: {exc}")
            return False
        ids = [i for i in (res.get("alert_ids") or []) if isinstance(i, int)] if isinstance(res, dict) else []
        for o in batch:
            self.st["sent"][o["key"]] = self.now
            self._counter(o["alert"])["forwarded"] += 1
        self.st["aiids_alert_ids"] += ids
        result["accepted"] += len(batch)
        for inc in (res.get("incidents") or []) if isinstance(res, dict) else []:
            if isinstance(inc, dict) and isinstance(inc.get("incident"), str):
                result["incidents_touched"].append(inc["incident"][:40])
        return True

    def incidents(self) -> list[dict]:
        """ai-ids incidents that contain at least one alert sent by this pipeline."""
        if not self.up.get("ai-ids"):
            return self.st.get("incidents", [])
        cl = self.clients["ai-ids"]
        try:
            rows = cl.get("/api/incidents", limit=200)
        except LabError as exc:
            self.err(f"incidents: {exc}")
            return self.st.get("incidents", [])
        ours, out = set(self.st["aiids_alert_ids"]), []
        candidates = [r for r in (rows if isinstance(rows, list) else []) if isinstance(r, dict)
                      and set(r.get("systems") or []) & set(SOURCES)]
        for r in candidates[:MAX_INCIDENT_FETCH]:
            inc_id = clean.text(r.get("id"), 40)
            if inc_id is None:
                continue
            try:
                detail = cl.get(f"/api/incidents/{path_part(inc_id)}")
            except LabError:
                continue
            ids = [i for i in detail.get("alert_ids", []) if isinstance(i, int)] if isinstance(detail, dict) else []
            mine = len(ours.intersection(ids))
            if not mine:
                continue
            systems = [s for s in (clean.text(x, 40) for x in (r.get("systems") or [])) if s]
            stages = r.get("stages") if isinstance(r.get("stages"), dict) else {}
            out.append({"id": inc_id, "severity": clean.text(r.get("severity"), 12), "score": clean.number(r.get("score"), 0, 100),
                        "alerts": clean.count(r.get("n_alerts")), "pipeline_alerts": mine,
                        "systems": ", ".join(systems), "n_systems": len(systems),
                        "stages": " > ".join(s for s in mapping.STAGES if s in stages),
                        "techniques": ", ".join(clean.techniques(r.get("techniques"), 12)),
                        "title": clean.text(r.get("title"), 160)})
        out.sort(key=lambda x: (-x["n_systems"], -(x["score"] or 0)))
        return out


def link_rows(p: Pass) -> list[dict]:
    rows = []
    for src, dst, what in LINKS:
        both = p.up.get(src) and p.up.get(dst)
        down = [n for n in (src, dst) if not p.up.get(n)]
        if dst == "threat-intel":
            e = p.enrich[src]
            sent, note = e["iocs"], f"{e['notable']} notable"
        else:
            c = p.counts[src]
            sent, note = c["forwarded"], f"{c['alerts']} new, {c['rejected']} rejected"
        rows.append({"link": f"{src} -> {dst}", "status": "up" if both else "down (" + ", ".join(down) + ")",
                     "sent": sent, "note": note, "carries": what})
    return rows


def run_once(st: dict, clients: dict | None = None, malware_host: str | None = None, log=None,
             sample_hosts: dict | None = None) -> dict:
    """One full pass. Updates `st` in place (the caller saves it) and returns the report.

    malware_host: host that every not yet forwarded sample is attributed to.
    sample_hosts: {sha256: host} for single samples (the demo uses this).
    """
    clients = clients or default_clients()
    p = Pass(st, clients, malware_host, log, sample_hosts)
    for name, cl in clients.items():
        p.up[name] = cl.healthy()
    p.log("labs up:", ", ".join(n for n, u in p.up.items() if u) or "none")
    for name, poll in (("honeypot-net", p.poll_honeypot), ("malware-lab", p.poll_malware), ("ics-sim", p.poll_ics)):
        if p.up.get(name):
            poll()
    p.enrich_items()
    p.note_shared()
    p.queue()
    fwd = p.forward()
    incidents = p.incidents()
    st["incidents"] = incidents
    st["totals"]["runs"] += 1
    report = {
        "started": p.now, "finished": time.time(), "labs": p.up, "links": link_rows(p), "counts": p.counts,
        "enrichment": p.enrich, "forward": fwd, "outbox": len(st["outbox"]), "errors": p.errors[:30],
        "incidents": len(incidents), "cross_system_incidents": sum(1 for i in incidents if i["n_systems"] > 1),
        "malware_host": malware_host,
    }
    st["last_run"] = report
    return report


def run_locked(malware_host: str | None = None, clients: dict | None = None, log=None,
               sample_hosts: dict | None = None) -> dict:
    """Load state, run one pass under the pipeline lock, save state."""
    with statemod.exclusive() as got:
        if not got:
            return {"busy": True, "error": "another pipeline run is in progress"}
        st = statemod.load()
        report = run_once(st, clients, malware_host, log, sample_hosts)
        statemod.save(st)
        return report


def summary(st: dict | None = None) -> dict:
    """What GET /api/pipeline returns: last run, links, incidents, shared indicators."""
    st = st if st is not None else statemod.load()
    last = st.get("last_run") or {}
    return {
        "last_run": {k: last.get(k) for k in ("started", "finished", "outbox", "incidents", "cross_system_incidents",
                                               "malware_host", "errors")} if last else None,
        "links": last.get("links") or [{"link": f"{s} -> {d}", "status": "not run yet", "sent": 0, "note": "", "carries": w}
                                       for s, d, w in LINKS],
        "counts": last.get("counts") or {},
        "totals": st.get("totals", {}),
        "outbox": len(st.get("outbox", [])),
        "incidents": st.get("incidents", []),
        "shared_indicators": st.get("shared_indicators", []),
    }
