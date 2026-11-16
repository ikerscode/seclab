"""The bridge end to end against fake lab servers, plus fail-soft behaviour."""
import os
import stat

import pytest

from conftest import check_aiids_alert, closed_port, load
from pipeline import bridge, labs, state
from pipeline.labs import LabClient, LabError

C2_SHA = load("malwarelab_sample_c2.json")["result"]["sha256"]
SETPOINT_RUN = "20261114-175453-d6946a"


class FakeAiids:
    """Records posted alerts, refuses ones that break the schema (like ai-ids does with HTTP 422)."""

    def __init__(self):
        self.alerts, self.next_id = [], 1000

    def ingest(self, body, _query):
        items = body["alerts"]
        errors = []
        for i, a in enumerate(items):
            try:
                check_aiids_alert(a)
            except AssertionError:
                errors.append({"index": i, "errors": [{"loc": ["?"], "msg": "invalid"}]})
        if errors:
            return 422, {"accepted": 0, "errors": errors}
        ids = list(range(self.next_id, self.next_id + len(items)))
        self.next_id += len(items)
        self.alerts += list(zip(ids, items))
        return 200, {"accepted": len(ids), "alert_ids": ids, "incidents": [{"incident": "INC-1000", "alerts": ids[:3]}]}

    def incidents(self, *_):
        systems = sorted({a["source"] for _, a in self.alerts})
        return 200, [{"id": "INC-1000", "severity": "critical", "score": 88.0, "n_alerts": len(self.alerts),
                      "systems": systems, "stages": {"execution_persistence": 1, "exfil_impact": 2},
                      "techniques": ["T1204", "T0855"], "title": "Execution -> Exfil / impact"},
                     {"id": "INC-7", "severity": "low", "score": 10.0, "n_alerts": 1, "systems": ["sensor-dmz"],
                      "stages": {"recon": 1}, "techniques": [], "title": "not ours"}]

    def incident(self, *_):
        return 200, {"id": "INC-1000", "alert_ids": [i for i, _ in self.alerts]}


@pytest.fixture
def lab_set(fake_lab):
    ai = FakeAiids()
    servers = {
        "honeypot-net": fake_lab("honeypot-net", {
            ("GET", "/api/infrastructure"): load("honeypot_infrastructure.json"),
            ("GET", "/api/campaigns"): load("honeypot_campaigns.json"),
            ("GET", "/api/events"): load("honeypot_downloads.json")}),
        "malware-lab": fake_lab("malware-lab", {
            ("GET", "/api/samples"): load("malwarelab_samples.json"),
            ("GET", f"/api/samples/{C2_SHA}"): load("malwarelab_sample_c2.json"),
            ("GET", "/api/samples/a84188d7dcecc084c817e8e8aba1610f98da415c889b938a3da1dbe3d1e380e0"):
                load("malwarelab_sample_benign.json")}),
        "ics-sim": fake_lab("ics-sim", {
            ("GET", "/api/meta"): load("icssim_meta.json"),
            ("GET", "/api/runs"): load("icssim_runs.json"),
            ("GET", f"/api/runs/{SETPOINT_RUN}"): load("icssim_run_setpoint_change.json"),
            ("GET", "/api/runs/20261114-042553-b72104"): load("icssim_run_oldsmar.json"),
            ("GET", "/api/state"): load("icssim_state.json"),
            ("GET", "/api/events"): load("icssim_events.json"),
            ("GET", "/api/modbus"): load("icssim_modbus.json")}),
        "threat-intel": fake_lab("threat-intel", {("POST", "/api/enrich"): load("threatintel_enrich.json")}),
        "ai-ids": fake_lab("ai-ids", {("POST", "/api/ingest"): ai.ingest, ("GET", "/api/incidents"): ai.incidents,
                                      ("GET", "/api/incidents/INC-1000"): ai.incident}),
    }
    clients = {n: LabClient(n, s.port) for n, s in servers.items()}
    return servers, clients, ai


def test_full_pass_against_fake_labs(lab_set, run_dir):
    servers, clients, ai = lab_set
    rep = bridge.run_locked(clients=clients, sample_hosts={C2_SHA: "CORP-WS-37"})
    assert all(rep["labs"].values())
    assert all(r["status"] == "up" for r in rep["links"])
    sources = {a["source"] for _, a in ai.alerts}
    assert sources == {"honeypot-net", "malware-lab", "ics-sim"}
    assert rep["forward"]["accepted"] == len(ai.alerts) and rep["forward"]["rejected"] == 0
    # the IT-to-OT chain: malware runs on CORP-WS-37 and CORP-WS-37 writes to the PLC
    corp = {a["category"] for _, a in ai.alerts if a.get("src_host") == "CORP-WS-37"}
    assert {"malware_exec", "c2_beacon", "modbus_blocked"} <= corp
    # only the fast run is read, real-time runs came in as live events
    run_paths = [p for m, p, q, b in servers["ics-sim"].requests if p.startswith("/api/runs/")]
    assert sorted(run_paths) == ["/api/runs/20261114-042100-920722", "/api/runs/20261114-042553-b72104",
                                 f"/api/runs/{SETPOINT_RUN}"]
    assert any("20261114-042100-920722" in e for e in rep["errors"])   # that report is missing in the fake
    # enrichment was asked for honeypot and malware IOCs in one batch
    [(_, _, _, body)] = [r for r in servers["threat-intel"].requests if r[0] == "POST"]
    assert "198.51.100.23" in body["iocs"] and C2_SHA in body["iocs"]
    st = state.load()
    assert [i["id"] for i in st["incidents"]] == ["INC-1000"]           # INC-7 holds no pipeline alert
    assert st["incidents"][0]["pipeline_alerts"] == len(ai.alerts)
    mode = stat.S_IMODE(os.stat(state.state_path()).st_mode)
    assert mode == 0o600


def test_second_pass_sends_nothing_new(lab_set):
    _, clients, ai = lab_set
    bridge.run_locked(clients=clients)
    first = len(ai.alerts)
    rep = bridge.run_locked(clients=clients)
    assert len(ai.alerts) == first and rep["forward"]["accepted"] == 0
    assert state.load()["totals"]["runs"] == 2


def test_refused_alert_is_dropped_and_the_rest_delivered(lab_set):
    _, clients, ai = lab_set
    st = state.load()
    good = {"source": "ics-sim", "ts": 1794000000.0, "category": "x", "severity": "low", "src_host": "h", "details": {}}
    bad = dict(good, source="Not Valid")
    st["outbox"] = [{"key": "good", "alert": good}, {"key": "bad", "alert": bad}]
    state.save(st)
    rep = bridge.run_locked(clients={"ai-ids": clients["ai-ids"]})
    assert rep["forward"]["rejected"] == 1 and rep["forward"]["accepted"] == 1
    assert state.load()["outbox"] == [] and "good" in state.load()["sent"]


def test_fail_soft_when_every_lab_is_down():
    dead = {n: LabClient(n, closed_port(), timeout=1) for n in labs.LAB_PORTS}
    rep = bridge.run_locked(clients=dead)
    assert not any(rep["labs"].values())
    assert all(r["status"].startswith("down") for r in rep["links"])
    assert rep["forward"]["accepted"] == 0 and rep["errors"] == []


def test_outbox_holds_alerts_while_ai_ids_is_down(lab_set):
    _, clients, ai = lab_set
    down = dict(clients, **{"ai-ids": LabClient("ai-ids", closed_port(), timeout=1),
                            "threat-intel": LabClient("threat-intel", closed_port(), timeout=1)})
    rep = bridge.run_locked(clients=down)
    waiting = rep["outbox"]
    assert waiting > 0 and ai.alerts == []
    assert "ai-ids is down" in rep["forward"]["note"]
    link = {r["link"]: r["status"] for r in rep["links"]}
    assert link["ics-sim -> ai-ids"] == "down (ai-ids)" and link["honeypot-net -> threat-intel"] == "down (threat-intel)"
    out = state.load()["outbox"]
    assert out[0]["alert"]["details"].get("intel") in (None, "not checked (threat-intel down)")
    rep2 = bridge.run_locked(clients=clients)            # ai-ids back: the queue drains, cursors did not rewind
    assert rep2["forward"]["accepted"] == waiting and len(ai.alerts) == waiting and rep2["outbox"] == 0


def test_concurrent_run_reports_busy():
    with state.exclusive() as got:
        assert got
        assert bridge.run_locked(clients={})["busy"] is True


def test_client_refuses_redirects_and_non_json(fake_lab):
    lab = fake_lab("ai-ids", {("GET", "/go"): lambda b, q: (302, {}, {"Location": "http://example.com/"}),
                              ("GET", "/api/incidents"): [1, 2]})
    cl = LabClient("ai-ids", lab.port)
    with pytest.raises(LabError) as exc:
        cl.get("/go")
    assert exc.value.status == 302
    assert cl.get("/api/incidents") == [1, 2]
    with pytest.raises(ValueError):
        cl.url("http://evil/")
    assert cl.base.startswith("http://127.0.0.1:")


def test_state_survives_corrupt_file(run_dir):
    run_dir.mkdir(parents=True, exist_ok=True)
    state.state_path().write_text("{not json")
    assert state.load() == state.empty()
    state.state_path().write_text('{"version": 1, "honeypot": [], "sent": 5}')
    st = state.load()
    assert st["honeypot"] == {"ips": {}, "download_id": 0} and st["sent"] == {}


def test_portal_pipeline_view(monkeypatch, lab_set):
    import server
    _, clients, _ = lab_set
    bridge.run_locked(clients=clients)
    monkeypatch.setattr(server, "all_status", lambda: [{"name": n, "up": n != "ics-sim"} for n in labs.LAB_PORTS])
    view = server.pipeline_view()
    status = {r["link"]: r["status"] for r in view["links"]}
    assert status["ics-sim -> ai-ids"] == "down (ics-sim)" and status["malware-lab -> ai-ids"] == "up"
    assert view["incidents"] and view["last_run"]["finished"]


def test_demo_flow_against_fake_labs(lab_set, monkeypatch, tmp_path, capsys):
    """The demo's seeding steps and final pass, with every lab already "running" as a fake."""
    from pipeline import demo
    servers, clients, ai = lab_set
    servers["threat-intel"].routes.update({
        ("GET", "/api/overview"): {"counts": {"indicators": 0}},
        ("POST", "/api/seed"): {"id": "j1", "status": "running"},
        ("GET", "/api/jobs/j1"): {"id": "j1", "status": "done"}})
    servers["honeypot-net"].routes.update({
        ("POST", "/api/simulate/inject"): {"name": "inject", "state": "running"},
        ("GET", "/api/simulate/status"): {"current": {"state": "done", "result": {"inserted": 5, "campaign_events": {"x": 5}}}}})
    servers["malware-lab"].routes.update({
        ("GET", "/api/sandbox"): {"image_present": False},
        ("POST", "/api/samples"): {"samples": [], "jobs": [7]},
        ("GET", "/api/jobs/7"): {"id": 7, "status": "done", "target": C2_SHA, "message": "malicious"}})
    servers["ics-sim"].routes.update({
        ("POST", "/api/scenarios/run"): {"id": SETPOINT_RUN, "outcome": "prevented", "attack": {"detections": {"firewall": {}}}}})
    servers["ai-ids"].routes.update({
        ("GET", "/api/status"): {"trained": False},
        ("GET", "/api/datasets"): {"datasets": [{"name": "sim"}]},
        ("POST", "/api/train"): {"id": "t1", "status": "running"},
        ("GET", "/api/jobs/t1"): {"id": "t1", "status": "done"}})
    spec = tmp_path / "malware-lab" / "specimens"
    spec.mkdir(parents=True)
    (spec / "c2_beacon.py").write_text("print('specimen stand-in')\n")
    monkeypatch.setattr(demo, "ROOT", tmp_path)
    d = demo.Demo(clients)
    assert d.run() == 0
    assert d.started == []                                   # nothing was started, so nothing to stop
    upload = [r for r in servers["malware-lab"].requests if r[:2] == ("POST", "/api/samples")]
    assert upload and upload[0][3] == b"print('specimen stand-in')\n" and upload[0][2]["dynamic"] == ["false"]
    assert [r[1] for r in servers["ai-ids"].requests if r[0] == "POST"][0] == "/api/train"
    corp = [a for _, a in ai.alerts if a.get("src_host") == "CORP-WS-37"]
    assert {"malware_exec", "modbus_blocked"} <= {a["category"] for a in corp}
    out = capsys.readouterr().out
    assert "treats sample caac2eacfaab as found on CORP-WS-37" in out and "INC-1000" in out


def test_demo_sandbox_run_picks_the_sample_it_just_analysed(lab_set, monkeypatch):
    """A re-run of the default specimen reuses its sample row, so submitted_at is old.

    An older variant of the same specimen (a training run) has a newer submitted_at. The demo must
    still map the sample the run analysed to CORP-WS-37, otherwise the malware alerts name the
    sample as their host and never meet the ICS alerts from CORP-WS-37.
    """
    from pipeline import demo
    servers, clients, ai = lab_set
    variant = "caac2eacfaab" + "0" * 52
    samples = load("malwarelab_samples.json")
    samples = [dict(r, submitted_at=1.0) if r.get("sha256") == C2_SHA else r for r in samples]
    samples.append({"sha256": variant, "source": "specimen:c2_beacon", "status": "done", "verdict": "malicious",
                    "category": "backdoor-c2", "score": 94, "submitted_at": 9e9})
    servers["malware-lab"].routes.update({
        ("GET", "/api/samples"): samples,
        ("GET", "/api/sandbox"): {"image_present": True},
        ("POST", "/api/specimens/c2_beacon/run"): {"job": 5},
        ("GET", "/api/jobs/5"): {"id": 5, "status": "done", "target": "c2_beacon", "message": "malicious"},
        ("GET", "/api/specimens"): [{"name": "other", "last": None},
                                    {"name": "c2_beacon", "last": {"sha256": C2_SHA, "analysed_at": 2.0}}]})
    assert demo.Demo(clients).seed_malware() == C2_SHA
    servers["malware-lab"].routes[("GET", "/api/specimens")] = [{"name": "c2_beacon", "last": None}]
    assert demo.Demo(clients).seed_malware() is None
