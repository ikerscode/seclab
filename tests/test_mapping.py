"""Mapping functions on canned answers copied from the real lab APIs (tests/fixtures)."""
import copy

from conftest import check_aiids_alert, load
from pipeline import mapping

HOSTS = mapping.ics_hosts(load("icssim_meta.json"))


def alerts(items):
    for i in items:
        check_aiids_alert(i["alert"])
    return [i["alert"] for i in items]


# --------------------------------------------------------------------------- honeypot-net
def test_honeypot_ips_map_to_valid_alerts_and_skip_lab_traffic():
    items, cursor, stats = mapping.honeypot_ip_items(load("honeypot_infrastructure.json"), load("honeypot_campaigns.json"), {})
    out = alerts(items)
    assert stats["skipped_local"] == 1                       # 127.0.0.1 from the live tests
    assert all(a["src_ip"] != "127.0.0.1" for a in out)
    assert "127.0.0.1" not in cursor
    brute = next(a for a in out if a["src_ip"] == "7.189.197.191" and a["category"] == "bruteforce")
    assert brute["technique_id"] == "T1110" and brute["stage"] == "initial_access"
    assert brute["details"]["campaign"] and brute["details"]["label"] == "botnet credential stuffing"
    assert "dst_ip" not in brute and "dst_host" not in brute  # decoys are not victims
    assert brute["details"]["via"] == "seclab-pipeline"


def test_honeypot_cursor_advances_and_only_new_activity_is_sent():
    infra = load("honeypot_infrastructure.json")
    items, cursor, _ = mapping.honeypot_ip_items(infra, {}, {})
    again, cursor2, _ = mapping.honeypot_ip_items(infra, {}, cursor)
    assert items and again == [] and cursor2 == cursor
    infra2 = copy.deepcopy(infra)
    row = next(r for r in infra2["top_ips"] if r["ip"] == "7.189.197.191")
    row["commands"] += 3
    row["last_seen"] += 60
    new, _, _ = mapping.honeypot_ip_items(infra2, {}, cursor)
    assert [(a["src_ip"], a["category"]) for a in alerts(new)] == [("7.189.197.191", "honeypot_shell_exec")]
    assert new[0]["alert"]["details"]["new"] == 3


def test_honeypot_hostile_rows_are_rejected_or_cleaned():
    infra = {"top_ips": [
        {"ip": "1.2.3.4; curl evil", "events": 1, "first_seen": 1794000000.0, "last_seen": 1794000001.0,
         "auth": 1, "commands": 0, "exploits": 0},
        {"ip": "5.6.7.8", "events": "9", "first_seen": 1794000000.0, "last_seen": 1794000001.0,
         "auth": 1, "commands": 0, "exploits": 0},
        {"ip": "9.9.9.9", "events": 2, "first_seen": True, "last_seen": 1794000001.0, "auth": 1, "commands": 0, "exploits": 0},
        "not a dict",
        {"ip": "45.9.168.192", "events": 3, "first_seen": 1794000000.0, "last_seen": 1794000001.0, "auth": 2,
         "commands": 0, "exploits": 0, "sensors": ["ssh\x1b[31m", {"x": 1}, "telnet"], "as_name": "A" * 5000,
         "country": "<img src=x onerror=alert(1)>"},
    ]}
    items, cursor, stats = mapping.honeypot_ip_items(infra, {"campaigns": "junk"}, {})
    assert stats["rejected"] == 4
    [a] = alerts(items)
    assert a["src_ip"] == "45.9.168.192"
    assert a["details"]["sensors"] == ["ssh [31m", "telnet"]
    assert len(a["details"]["as_name"]) == 80
    assert set(cursor) == {"45.9.168.192"}


def test_honeypot_downloads_dedup_cursor_and_reset():
    events = load("honeypot_downloads.json")
    items, last, stats = mapping.honeypot_download_items(events, 0)
    out = alerts(items)
    assert last == max(e["id"] for e in events)
    assert stats["skipped_local"] == 3                       # downloads from 127.0.0.1
    a = next(a for a in out if a["details"]["url"] == "hxxp://198[.]51[.]100[.]23/bins[.]sh")
    assert a["dst_ip"] == "198.51.100.23" and a["technique_id"] == "T1105"
    assert a["details"]["fetched_by_honeypot"] is False
    assert "http://" not in a["summary"]                      # defanged for display
    assert {"http://198.51.100.23/bins.sh", "198.51.100.23"} <= {v for i in items for v in i["iocs"]}
    again, last2, _ = mapping.honeypot_download_items(events, last)
    assert again == [] and last2 == last
    # ids went backwards: the honeypot database was purged, so start over (dedup keys stop resends)
    replay, last3, _ = mapping.honeypot_download_items(events, last + 10_000)
    assert len(replay) == len(items) and last3 == last


def test_honeypot_hostile_download_urls_are_rejected():
    base = load("honeypot_downloads.json")[-1]
    bad_urls = ["javascript:alert(1)", "file:///etc/passwd", "http://" + "a" * 400 + ".com/x", "http://x.com/\x00",
                {"nested": "http://a.com"}, "http://bad host/x"]
    events = []
    for n, u in enumerate(bad_urls):
        e = copy.deepcopy(base)
        e.update(id=900000 + n, src_ip="45.9.168.192", data={"url": u})
        events.append(e)
    items, last, stats = mapping.honeypot_download_items(events, 0)
    assert items == [] and stats["rejected"] == len(bad_urls) and last == 900000 + len(bad_urls) - 1


# --------------------------------------------------------------------------- malware-lab
def test_malware_sample_maps_to_exec_and_c2_alerts():
    items, stats = mapping.malware_items(load("malwarelab_sample_c2.json"), "CORP-WS-37")
    out = alerts(items)
    exec_, *c2 = out
    assert exec_["category"] == "malware_exec" and exec_["src_host"] == "CORP-WS-37"
    assert exec_["stage"] == "execution_persistence" and exec_["severity"] == "critical"
    assert exec_["details"]["verdict"] == "malicious" and exec_["details"]["specimen"] == "c2_beacon"
    assert {a["category"] for a in c2} == {"c2_beacon"}
    ip_alert = next(a for a in c2 if "dst_ip" in a)
    assert ip_alert["dst_ip"] == "198.51.100.183" and ip_alert["stage"] == "command_and_control"
    assert any(a.get("dst_host") == "assets-metrics32.c2.test" for a in c2)
    sha = load("malwarelab_sample_c2.json")["result"]["sha256"]
    assert sha in items[0]["iocs"]


def test_malware_without_origin_uses_the_sample_and_benign_is_skipped():
    items, _ = mapping.malware_items(load("malwarelab_sample_c2.json"))
    assert items[0]["alert"]["src_host"].startswith("sample-caac2eacfaab")
    none, stats = mapping.malware_items(load("malwarelab_sample_benign.json"))
    assert none == [] and stats["skipped_benign"] == 1


def test_malware_hostile_iocs():
    d = copy.deepcopy(load("malwarelab_sample_c2.json"))
    r = d["result"]
    r["iocs"] = [{"type": "ip", "value": "10.0.0.5"}, {"type": "ip", "value": "127.0.0.1"},
                 {"type": "ip_port", "value": "203.0.113.50:99999"}, {"type": "domain", "value": "evil..com"},
                 {"type": "domain", "value": "a" * 300}, {"type": "url", "value": "javascript:x"}, "junk",
                 {"type": "ip", "value": "203.0.113.9"}]
    r["sample"]["filename"] = "invoice.pdf\x1b]0;owned\x07.exe"
    items, _ = mapping.malware_items(d, "bad host name; rm")
    out = alerts(items)
    assert out[0]["src_host"].startswith("sample-")           # invalid origin host refused
    assert "\x1b" not in out[0]["details"]["filename"]
    assert sorted(a.get("dst_ip") for a in out[1:]) == ["203.0.113.50", "203.0.113.9"]
    d["result"]["sha256"] = "../../etc/passwd"
    assert mapping.malware_items(d)[1]["rejected"] == 1


def test_sample_signature_changes_when_reanalysed():
    row = load("malwarelab_samples.json")[1]
    sig = mapping.sample_signature(row)
    row2 = dict(row, score=12)
    assert sig and mapping.sample_signature(row2) != sig
    assert mapping.sample_signature(dict(row, status="running")) is None


# --------------------------------------------------------------------------- ics-sim
def test_ics_hosts_short_names():
    assert HOSTS["192.168.10.37"] == "CORP-WS-37" and HOSTS["10.10.1.10"] == "PLC-01"


def test_ics_fast_run_blocked_writes_are_attributed_to_the_attacker():
    created = 1794672893.0
    items, stats = mapping.ics_run_items(load("icssim_run_setpoint_change.json"), created, HOSTS)
    out = alerts(items)
    assert stats["rejected"] == 0 and len(out) == 2
    for a in out:
        assert a["category"] == "modbus_blocked" and a["src_host"] == "CORP-WS-37" and a["dst_host"] == "PLC-01"
        assert a["stage"] == "exfil_impact" and "src_ip" not in a and a["details"]["sim_src_ip"] == "192.168.10.37"
        assert a["ts"] <= created
    # the run's last event (t=1860) is placed at the save time, the first alert (t=1800) 60 s before it
    assert sorted(created - a["ts"] for a in out) == [0.0, 60.0]
    # attack steps are ground truth from the simulator and never become alerts
    assert not any("FC6 write" in a["summary"] for a in out)


def test_ics_fast_run_engineering_limit():
    items, _ = mapping.ics_run_items(load("icssim_run_oldsmar.json"), 1794623153.3, HOSTS)
    [a] = alerts(items)
    assert a["category"] == "modbus_write_rejected" and a["src_host"] == "HMI-01" and a["technique_id"] == "T0836"


def test_ics_live_events_modbus_and_reset():
    run = load("icssim_run_setpoint_change.json")
    events = [dict(e) for e in run["attack"]["timeline"]]
    events.append({"id": 20, "t": 1900.0, "kind": "alert", "severity": "crit", "source": "sis",
                   "message": "SIS TRIP: chlorine high; safe state", "clock": "D1 06:31:40"})
    events.append({"id": 21, "t": 1901.0, "kind": "alarm", "severity": "warn", "source": "plc", "message": "PLC alarm"})
    modbus = {"rows": load("icssim_modbus.json")["rows"] + [
        {"id": 30, "t": 1860.0, "src": "192.168.10.37", "zone": "enterprise", "unit": 1, "fc": 6, "addr": 7, "qty": None,
         "value": 600, "write": True, "result": "blocked", "reason": "source not in allowlist", "transport": "sim", "count": 1},
        {"id": 31, "t": 1861.0, "src": "192.168.10.37", "zone": "enterprise", "unit": 1, "fc": 6, "addr": 7, "qty": None,
         "value": 600, "write": True, "result": "blocked", "reason": "source not in allowlist", "transport": "sim", "count": 1}]}
    state = {"t": 2000.0, "speed": 10.0}
    now = 1794700000.0
    items, cursor, _ = mapping.ics_live_items(events, modbus, state, HOSTS, {}, now)
    out = alerts(items)
    cats = [a["category"] for a in out]
    assert cats.count("modbus_blocked") == 2 and "sis_trip" in cats and cats.count("modbus_write_blocked") == 1
    sis = next(a for a in out if a["category"] == "sis_trip")
    assert sis["dst_host"] == "SIS-01" and sis["severity"] == "critical" and sis["src_host"] == "CORP-WS-37"
    assert abs(sis["ts"] - (now - 10.0)) < 1e-6           # 100 sim seconds ago at 10x speed
    mb = next(a for a in out if a["category"] == "modbus_write_blocked")
    assert mb["details"]["count"] == 2 and mb["details"]["registers"] == [7]
    assert cursor["live_id"] == 21 and cursor["live_mb_id"] == max(r["id"] for r in modbus["rows"])
    again, cursor2, _ = mapping.ics_live_items(events, modbus, state, HOSTS, cursor, now)
    assert again == []
    # simulated time went backwards: the plant was reset and ids start again
    reset, cursor3, _ = mapping.ics_live_items(events, modbus, {"t": 5.0, "speed": 10.0}, HOSTS, cursor2, now)
    assert len(reset) == len(items) and cursor3["live_t"] == 5.0


# --------------------------------------------------------------------------- threat-intel
def test_intel_context_and_match_alert():
    intel = mapping.intel_index(load("threatintel_enrich.json"))
    assert intel["141.98.11.62"]["tags"] == ["in-drop", "tor-exit"]
    assert intel["50.16.16.211"]["malware"] == "qakbot" and "TA551" in intel["50.16.16.211"]["actors"]
    base = mapping.make_alert("honeypot-net", "bruteforce", 1794000000.0, src_ip="141.98.11.62", severity="medium",
                              technique_id="T1110", stage="initial_access", summary="x")
    plain = mapping.make_alert("honeypot-net", "bruteforce", 1794000000.0, src_ip="8.8.8.8", summary="y")
    items = [{"key": "a", "lab": "honeypot-net", "alert": base, "iocs": ["141.98.11.62"]},
             {"key": "b", "lab": "honeypot-net", "alert": plain, "iocs": ["8.8.8.8"]}]
    extra = mapping.apply_intel(items, intel)
    [x] = alerts(extra)
    assert x["source"] == "threat-intel" and x["category"] == "intel_match" and x["src_ip"] == "141.98.11.62"
    assert x["stage"] == "initial_access" and x["severity"] == "medium"
    assert "tor-exit" in x["summary"] and "141[.]98[.]11[.]62" in x["summary"]
    assert items[0]["alert"]["details"]["intel"][0]["verdict"] == "suspicious"
    assert "intel" not in items[1]["alert"]["details"]                     # unknown adds nothing


def test_intel_hostile_answer_is_cleaned():
    hostile = {"results": [{"input": "1.2.3.4", "verdict": "pwned", "tags": ["<script>"], "malware": "x" * 999,
                            "actors": [{"name": "\x1b[2J"}], "asn": "AS1"}, "junk", {"no": "input"}]}
    intel = mapping.intel_index(hostile)
    assert intel == {"1.2.3.4": {"verdict": "unknown", "match": False, "confidence": None, "sources": [], "tags": [],
                                 "malware": "x" * 40, "actors": ["[2J"], "inside_drop": None, "asn": None,
                                 "as_name": None, "country": None}}


# --------------------------------------------------------------------------- make_alert
def test_make_alert_refuses_what_ai_ids_would_refuse():
    ok = dict(src_host="h1")
    assert mapping.make_alert("Bad Source", "x", 1794000000.0, **ok) is None
    assert mapping.make_alert("lab", "Has Space", 1794000000.0, **ok) is None
    assert mapping.make_alert("lab", "x", "yesterday", **ok) is None
    assert mapping.make_alert("lab", "x", 1794000000.0) is None                    # no entity
    assert mapping.make_alert("lab", "x", 1794000000.0, dst_port=70000, **ok) is None
    assert mapping.make_alert("lab", "x", 1794000000.0, technique_id="T99", **ok) is None
    assert mapping.make_alert("lab", "x", 1794000000.0, stage="pwn", **ok) is None
    assert mapping.make_alert("lab", "x", 1794000000.0, src_ip="999.1.1.1") is None
    big = mapping.make_alert("lab", "x", 1794000000.0, summary="s" * 2000,
                             details={"a": "y" * 3000, "b": "z" * 3000, "c": 1}, **ok)
    check_aiids_alert(big)
    assert big["details"]["c"] == 1 and big["details"]["via"] == "seclab-pipeline"
