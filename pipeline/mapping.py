"""Turn lab API answers into ai-ids external alerts.

Every function here is pure: it takes parsed JSON (as the lab returned it) plus a
cursor, and returns new items, the advanced cursor and some counts. Nothing is
sent from here, which keeps the mapping easy to test with canned answers.

An item is {"key": dedup key, "alert": ai-ids alert, "iocs": [values to enrich],
"lab": lab that produced it}. The alert dict matches the ai-ids ExternalAlert
schema (see ai-ids/aiids/ingest.py), and make_alert() checks the same limits
locally so one bad record cannot get a whole batch refused.
"""
from __future__ import annotations

import re

from . import clean

STAGES = ["recon", "initial_access", "execution_persistence", "lateral_movement",
          "command_and_control", "exfil_impact"]
SEVERITIES = ("low", "medium", "high", "critical")
DETAILS_LIMIT = 3500          # ai-ids refuses details whose str() is over ~4000 characters
VIA = "seclab-pipeline"
_SOURCE = re.compile(r"[a-z0-9][a-z0-9_.-]{0,63}")
_CATEGORY = re.compile(r"[a-z0-9_]{1,64}")
_IP_IN_TEXT = re.compile(r"\bfrom (\d{1,3}(?:\.\d{1,3}){3})\b")


# --------------------------------------------------------------------------- helpers
def defang(value: str) -> str:
    """Make an indicator non-clickable for display (hxxp, [.])."""
    return value.replace("http", "hxxp").replace("ftp", "fxp").replace(".", "[.]")


def _fit_details(details: dict) -> dict:
    """Drop the largest entries until the details fit the ai-ids size limit."""
    details = dict(details)
    while len(str(details)) > DETAILS_LIMIT and len(details) > 1:
        biggest = max((k for k in details if k != "via"), key=lambda k: len(str(details[k])))
        details.pop(biggest)
    return details


def make_alert(source: str, category: str, ts, *, src_ip=None, dst_ip=None, src_host=None, dst_host=None,
               dst_port=None, severity: str = "medium", confidence=None, technique_id=None, stage=None,
               summary=None, details=None) -> dict | None:
    """Build one ai-ids alert, or None when a field would fail the ai-ids schema."""
    if not isinstance(source, str) or not _SOURCE.fullmatch(source):
        return None
    if not isinstance(category, str) or not _CATEGORY.fullmatch(category):
        return None
    ts = clean.timestamp(ts)
    if ts is None or severity not in SEVERITIES:
        return None
    alert = {"source": source, "ts": round(ts, 3), "category": category, "severity": severity}
    for key, value, check in (("src_ip", src_ip, clean.ip), ("dst_ip", dst_ip, clean.ip),
                              ("src_host", src_host, clean.host_name), ("dst_host", dst_host, clean.host_name)):
        if value is not None:
            good = check(value)
            if good is None:
                return None
            alert[key] = good
    if not any(k in alert for k in ("src_ip", "dst_ip", "src_host", "dst_host")):
        return None
    if dst_port is not None:
        port = clean.count(dst_port, 65535)
        if port is None:
            return None
        alert["dst_port"] = port
    if confidence is not None:
        conf = clean.number(confidence, 0, 1)
        if conf is None:
            return None
        alert["confidence"] = round(conf, 3)
    if technique_id is not None:
        tid = clean.technique(technique_id)
        if tid is None:
            return None
        alert["technique_id"] = tid
    if stage is not None:
        if stage not in STAGES:
            return None
        alert["stage"] = stage
    if summary is not None:
        alert["summary"] = clean.text(summary, 480) or category
    alert["details"] = _fit_details({"via": VIA, **(details or {})})
    return alert


def _item(lab: str, key: str, alert: dict | None, iocs=()) -> dict | None:
    if alert is None:
        return None
    return {"key": key, "lab": lab, "alert": alert, "iocs": [i for i in iocs if i]}


# --------------------------------------------------------------------------- honeypot-net
HONEYPOT_KINDS = {
    # counter in /api/infrastructure -> (category, technique, stage)
    "exploits": ("web_exploit", "T1190", "initial_access"),
    "auth": ("bruteforce", "T1110", "initial_access"),
    "commands": ("honeypot_shell_exec", "T1059", "execution_persistence"),
}


def campaign_index(campaigns) -> dict:
    """ip -> {campaign, label, size} from /api/campaigns."""
    out = {}
    rows = campaigns.get("campaigns") if isinstance(campaigns, dict) else None
    for c in (rows if isinstance(rows, list) else [])[:200]:
        if not isinstance(c, dict):
            continue
        info = {"campaign": clean.text(c.get("id"), 8), "label": clean.text(c.get("label"), 60),
                "size": clean.count(c.get("size"), 100000)}
        for addr in (c.get("ips") if isinstance(c.get("ips"), list) else [])[:200]:
            a = clean.ip(addr)
            if a:
                out[a] = info
    return out


def honeypot_ip_items(infra, campaigns, cursor: dict) -> tuple[list, dict, dict]:
    """Per attacker IP: one alert per behaviour whose counter went up since the last run.

    The decoy itself is not sent as a target: every attacker hits the same decoys,
    and ai-ids links alerts that share a victim within two minutes, so sending it
    would merge unrelated attackers into one incident. Sensor names go in details.
    """
    stats = {"fetched": 0, "rejected": 0, "skipped_local": 0}
    cursor = dict(cursor)
    rows = infra.get("top_ips") if isinstance(infra, dict) else None
    if not isinstance(rows, list):
        return [], cursor, stats
    camp = campaign_index(campaigns)
    items = []
    for row in rows[:1000]:
        stats["fetched"] += 1
        if not isinstance(row, dict):
            stats["rejected"] += 1
            continue
        addr = clean.ip(row.get("ip"))
        if addr is None:
            stats["rejected"] += 1
            continue
        if clean.is_local(addr):
            stats["skipped_local"] += 1       # lab traffic from this machine, not an attacker
            continue
        first, last = clean.timestamp(row.get("first_seen")), clean.timestamp(row.get("last_seen"))
        counts = {k: clean.count(row.get(k)) for k in ("events", "auth", "commands", "exploits")}
        if first is None or last is None or None in counts.values():
            stats["rejected"] += 1
            continue
        prev = cursor.get(addr, {})
        details = {"sensors": clean.str_list(row.get("sensors"), 6, 16), "nodes": clean.str_list(row.get("nodes"), 8, 32),
                   "country": clean.text(row.get("country"), 16), "asn": clean.count(row.get("asn"), 2**32),
                   "as_name": clean.text(row.get("as_name"), 80), "events": counts["events"],
                   "first_seen": first, "last_seen": last}
        if addr in camp:
            details.update(camp[addr])
        where = "/".join(details["sensors"]) or "honeypot"
        sent_any = False
        for kind, (category, tid, stage) in HONEYPOT_KINDS.items():
            delta = counts[kind] - prev.get(kind, 0)
            if delta <= 0:
                continue
            ts = first if kind != "commands" and not prev else last
            sev = ("high" if counts[kind] >= 50 or kind == "commands" else "medium") if kind != "exploits" else (
                "high" if counts[kind] >= 5 else "medium")
            what = {"exploits": f"{counts[kind]} exploit attempts", "auth": f"{counts[kind]} login attempts",
                    "commands": f"{counts[kind]} shell commands after login"}[kind]
            camp_txt = f", campaign {details['campaign']} ({details['label']})" if addr in camp else ""
            alert = make_alert("honeypot-net", category, ts, src_ip=addr, severity=sev, technique_id=tid, stage=stage,
                               summary=f"honeypot-net: {addr} {what} on {where}{camp_txt}",
                               details={**details, "kind": kind, "new": delta, "total": counts[kind]})
            item = _item("honeypot-net", f"hp:{addr}:{kind}:{counts[kind]}", alert, [addr])
            if item:
                items.append(item)
                sent_any = True
        if not prev and not sent_any and counts["events"] > 0:
            alert = make_alert("honeypot-net", "honeypot_scan", first, src_ip=addr, severity="low", technique_id="T1595",
                               stage="recon", summary=f"honeypot-net: {addr} probed {where} ({counts['events']} events)",
                               details={**details, "kind": "scan"})
            item = _item("honeypot-net", f"hp:{addr}:scan", alert, [addr])
            if item:
                items.append(item)
        cursor[addr] = {k: counts[k] for k in ("events", "auth", "commands", "exploits")} | {"last_seen": last}
    return items, cursor, stats


def honeypot_download_items(events, last_id: int) -> tuple[list, int, dict]:
    """download_attempt events (URLs typed into the fake shell) newer than last_id.

    The URL is only parsed, never requested. Its host becomes the alert target so
    two attackers pulling from the same server within minutes are linked.
    """
    stats = {"fetched": 0, "rejected": 0, "skipped_local": 0}
    if not isinstance(events, list):
        return [], last_id, stats
    ids = [clean.count(e.get("id")) for e in events if isinstance(e, dict)]
    ids = [i for i in ids if i is not None]
    if ids and max(ids) < last_id:
        last_id = 0                       # the honeypot database was purged and ids started again
    items, newest = [], last_id
    for e in events[:1000]:
        if not isinstance(e, dict):
            stats["rejected"] += 1
            continue
        eid = clean.count(e.get("id"))
        if eid is None:
            stats["rejected"] += 1
            continue
        if eid <= last_id:
            continue
        newest = max(newest, eid)
        stats["fetched"] += 1
        if e.get("event_type") != "download_attempt":
            continue
        addr = clean.ip(e.get("src_ip"))
        data = e.get("data") if isinstance(e.get("data"), dict) else {}
        u = clean.url(data.get("url"))
        ts = clean.timestamp(e.get("ts"))
        if addr is None or u is None or ts is None:
            stats["rejected"] += 1
            continue
        if clean.is_local(addr):
            stats["skipped_local"] += 1
            continue
        target = {}
        if u["host_ip"] and not clean.is_local(u["host_ip"]):
            target["dst_ip"] = u["host_ip"]
        elif u["host_domain"] and len(u["host_domain"]) <= 64:
            target["dst_host"] = u["host_domain"]
        sensor = clean.text(e.get("sensor"), 16) or "shell"
        alert = make_alert("honeypot-net", "payload_download", ts, src_ip=addr, severity="high", technique_id="T1105",
                           stage="command_and_control",
                           summary=f"honeypot-net: {addr} tried to download {defang(u['url'])} over {sensor}",
                           details={"url": defang(u["url"]), "payload_host": defang(u["host"]), "sensor": sensor,
                                    "node": clean.text(e.get("node_id"), 32), "fetched_by_honeypot": False},
                           **target)
        item = _item("honeypot-net", f"hp:dl:{addr}:{u['url']}", alert, [u["url"], u["host"]])
        if item:
            items.append(item)
    return items, newest, stats


# --------------------------------------------------------------------------- malware-lab
BAD_VERDICTS = ("malicious", "suspicious")


def sample_signature(row) -> str | None:
    """What /api/samples says about a sample; a change means it was re-analysed."""
    if not isinstance(row, dict) or row.get("status") != "done":
        return None
    sha = clean.sha256(row.get("sha256"))
    if sha is None:
        return None
    return f"{clean.text(row.get('verdict'), 16)}|{clean.text(row.get('category'), 40)}|{clean.count(row.get('score'), 1000)}"


def _endpoints(iocs) -> tuple[dict, list, list]:
    """External IPs (with port), domains and URLs from a malware-lab IOC list."""
    ips, domains, urls = {}, [], []
    for ioc in (iocs if isinstance(iocs, list) else [])[:300]:
        if not isinstance(ioc, dict):
            continue
        kind, value = ioc.get("type"), ioc.get("value")
        if kind == "ip":
            a = clean.external_ip(value)
            if a:
                ips.setdefault(a, None)
        elif kind == "ip_port" and isinstance(value, str) and ":" in value:
            host, _, port = value.rpartition(":")
            a, p = clean.external_ip(host), (int(port) if port.isdigit() and int(port) <= 65535 else None)
            if a:
                ips[a] = p if p is not None else ips.get(a)
        elif kind == "domain":
            d = clean.domain(value)
            if d and d not in domains:
                domains.append(d)
        elif kind == "url":
            u = clean.url(value)
            if u and u["url"] not in urls:
                urls.append(u["url"])
    return ips, domains[:20], urls[:20]


def malware_items(detail, origin_host: str | None = None) -> tuple[list, dict]:
    """A finished analysis -> one execution alert plus one C2 alert per external endpoint.

    The sample runs on `origin_host` when the analyst says where it was found
    (seclab pipeline --malware-host). Otherwise the sample itself is the entity.
    """
    stats = {"fetched": 1, "rejected": 0, "skipped_benign": 0}
    result = detail.get("result") if isinstance(detail, dict) else None
    if not isinstance(result, dict):
        stats["rejected"] += 1
        return [], stats
    sha = clean.sha256(result.get("sha256"))
    cls = result.get("classification") if isinstance(result.get("classification"), dict) else {}
    verdict = cls.get("verdict") if isinstance(cls.get("verdict"), str) else None
    at = clean.timestamp(result.get("analysed_at"))
    if sha is None or at is None or verdict is None:
        stats["rejected"] += 1
        return [], stats
    if verdict not in BAD_VERDICTS:
        stats["skipped_benign"] += 1
        return [], stats
    score = clean.count(cls.get("score"), 1000) or 0
    sample = result.get("sample") if isinstance(result.get("sample"), dict) else {}
    attack = [a for a in (result.get("attack") if isinstance(result.get("attack"), list) else [])[:40] if isinstance(a, dict)]
    techs = clean.techniques([a.get("id") for a in attack], 12)
    tactics = sorted({t for t in (clean.text(a.get("tactic"), 32) for a in attack) if t})
    exec_tid = next((clean.technique(a.get("id")) for a in attack
                     if a.get("tactic") in ("Execution", "Persistence") and clean.technique(a.get("id"))), "T1204")
    host = clean.host_name(origin_host) if origin_host else None
    src_host = host or f"sample-{sha[:12]}"
    severity = "critical" if verdict == "malicious" and score >= 90 else "high" if verdict == "malicious" else "medium"
    conf = min(0.99, max(0.3, score / 100))
    ips, domains, urls = _endpoints(result.get("iocs"))
    spec = result.get("specimen") if isinstance(result.get("specimen"), dict) else {}
    base = {"sha256": sha, "filename": clean.text(sample.get("filename"), 80), "file_type": clean.text(sample.get("file_type"), 40),
            "verdict": verdict, "category": clean.text(cls.get("category"), 40), "score": score,
            "techniques": techs, "tactics": tactics, "specimen": clean.text(spec.get("name"), 40),
            "origin_host": host or "unknown (sample itself used as entity)"}
    name = base["filename"] or sha[:12]
    items = []
    alert = make_alert("malware-lab", "malware_exec", at, src_host=src_host, severity=severity, confidence=conf,
                       technique_id=exec_tid, stage="execution_persistence",
                       summary=f"malware-lab: {name} is {verdict} ({base['category']}, score {score}) on {src_host}",
                       details={**base, "c2_ips": [defang(i) for i in ips][:10], "c2_domains": [defang(d) for d in domains][:10]})
    item = _item("malware-lab", f"ml:{sha}:{at:.0f}:exec", alert, [sha])
    if item:
        items.append(item)
    for n, (addr, port) in enumerate(ips.items()):
        alert = make_alert("malware-lab", "c2_beacon", at + 1 + n, src_host=src_host, dst_ip=addr, dst_port=port,
                           severity=severity, confidence=conf, technique_id="T1071.001", stage="command_and_control",
                           summary=f"malware-lab: {name} contacts {defang(addr)}" + (f":{port}" if port else ""),
                           details={"sha256": sha, "c2": defang(addr), "port": port, "verdict": verdict})
        item = _item("malware-lab", f"ml:{sha}:{at:.0f}:c2:{addr}", alert, [addr])
        if item:
            items.append(item)
    for n, d in enumerate(domains):
        target = {"dst_host": d} if len(d) <= 64 else {}
        alert = make_alert("malware-lab", "c2_beacon", at + 1 + len(ips) + n, src_host=src_host, severity=severity,
                           confidence=conf, technique_id="T1071.001", stage="command_and_control",
                           summary=f"malware-lab: {name} resolves {defang(d)}",
                           details={"sha256": sha, "c2": defang(d), "verdict": verdict}, **target)
        item = _item("malware-lab", f"ml:{sha}:{at:.0f}:c2:{d}", alert, [d] + [u for u in urls if d in u][:3])
        if item:
            items.append(item)
    return items, stats


# --------------------------------------------------------------------------- ics-sim
# (kind, source) of an ics-sim event -> (category, default technique, stage)
ICS_ALERTS = {
    ("alert", "detector"): ("ics_anomaly", "T0855", "exfil_impact"),
    ("alert", "firewall"): ("modbus_blocked", "T0855", "exfil_impact"),
    ("alert", "segmentation"): ("modbus_blocked", "T0855", "exfil_impact"),
    ("alert", "eng_limits"): ("modbus_write_rejected", "T0836", "exfil_impact"),
    ("alert", "integrity"): ("hmi_integrity", "T0856", "exfil_impact"),
    ("alert", "operator"): ("operator_report", "T0855", "exfil_impact"),
    ("alert", "sis"): ("sis_trip", "T0880", "exfil_impact"),
    ("sis", "sis_device"): ("sis_bypass", "T0836", "exfil_impact"),
    ("hazard", "plant"): ("process_hazard", "T0831", "exfil_impact"),
    ("plc", "plc"): ("plc_event", "T0843", "execution_persistence"),
}
ICS_SEVERITY = {"crit": "critical", "high": "high", "warn": "medium", "info": "low"}
PLC_IP, SIS_IP = "10.10.1.10", "10.10.4.11"


def ics_hosts(meta) -> dict:
    """ip -> short host name from /api/meta ("CORP-WS-37 (phished office PC)" -> "CORP-WS-37").

    ics-sim addresses overlap the ai-ids simulated network (10.10.2.10 is HMI-01
    here and web01 there), so OT alerts carry host names only and the sim IP goes
    in details. Otherwise ai-ids would file PLC writes under the wrong machine.
    """
    out = {}
    hosts = meta.get("hosts") if isinstance(meta, dict) else None
    for h in (hosts if isinstance(hosts, list) else [])[:100]:
        if not isinstance(h, dict):
            continue
        addr, name = clean.ip(h.get("ip")), h.get("host")
        if addr and isinstance(name, str):
            short = "-".join(name.split(" (")[0].split())[:64]
            if clean.host_name(short):
                out[addr] = short
    return out


def _ics_host(addr, hosts: dict) -> str | None:
    a = clean.ip(addr) if addr else None
    if a is None:
        return None
    return hosts.get(a) or f"ot-{a}".replace(":", "-")


def _forwardable(ev: dict):
    """(category, technique, stage) for events that a SOC should see, else None.

    Attack steps (kind "attack") are the simulator's ground truth, not detections,
    so they are never forwarded. They are only used to attribute the source host.
    """
    kind, source, sev = ev.get("kind"), ev.get("source"), ev.get("severity")
    rule = ICS_ALERTS.get((kind, source))
    if rule is None:
        return None
    if kind in ("sis", "hazard") and sev != "crit":
        return None                       # bypass switched off, hazard cleared
    if kind == "plc":
        msg = ev.get("message") if isinstance(ev.get("message"), str) else ""
        if sev == "crit":
            return ("plc_fault", "T0814", "exfil_impact")
        if "program downloaded" in msg:
            return ("plc_program_download", "T0843", "execution_persistence")
        return None
    return rule


def _ics_alert(ev: dict, rule, ts: float, src_host, hosts: dict, extra: dict, scenario: str, step_techs: list):
    category, default_tid, stage = rule
    message = clean.text(ev.get("message"), 300) or category
    target = hosts.get(SIS_IP, "SIS-01") if category.startswith("sis") else hosts.get(PLC_IP, "PLC-01")
    m = _IP_IN_TEXT.search(message)
    src_ip_sim = m.group(1) if m else None
    if src_ip_sim:
        src_host = _ics_host(src_ip_sim, hosts) or src_host
    tid = step_techs[0] if step_techs and category in ("ics_anomaly", "operator_report") else default_tid
    sev = ICS_SEVERITY.get(ev.get("severity"), "medium")
    where = f" [{scenario}]" if scenario else ""
    return make_alert("ics-sim", category, ts, src_host=src_host, dst_host=target, severity=sev, technique_id=tid,
                      stage=stage, summary=f"ics-sim{where}: {message}",
                      details={**extra, "mitigation": clean.text(ev.get("source"), 24), "sim_clock": clean.text(ev.get("clock"), 16),
                               "sim_src_ip": src_ip_sim, "step_techniques": step_techs[:6]})


def ics_run_items(run, created, hosts: dict) -> tuple[list, dict]:
    """A saved fast scenario run -> alerts.

    Fast runs simulate hours in seconds. The bridge places the run's last event at
    the moment the run was saved and keeps the simulated spacing before it, so
    the alerts sit in real time just before the run finished.
    """
    stats = {"fetched": 1, "rejected": 0}
    created = clean.timestamp(created)
    if not isinstance(run, dict) or created is None:
        stats["rejected"] += 1
        return [], stats
    run_id = clean.text(run.get("id"), 40)
    attack = run.get("attack") if isinstance(run.get("attack"), dict) else {}
    scenario = run.get("scenario") if isinstance(run.get("scenario"), dict) else {}
    key = clean.text(scenario.get("key"), 40) or "scenario"
    attacker = scenario.get("attacker") if isinstance(scenario.get("attacker"), dict) else {}
    attacker_host = _ics_host(attacker.get("ip"), hosts) or "field-device"
    timeline = [e for e in (attack.get("timeline") if isinstance(attack.get("timeline"), list) else [])[:500]
                if isinstance(e, dict) and clean.number(e.get("t"), 0, 1e8) is not None]
    detections = attack.get("detections") if isinstance(attack.get("detections"), dict) else {}
    seen = {(e.get("source"), e.get("t")) for e in timeline if e.get("kind") == "alert"}
    for src, d in list(detections.items())[:20]:          # first detections, in case the timeline was cut
        if isinstance(d, dict) and clean.number(d.get("t"), 0, 1e8) is not None and (src, d["t"]) not in seen:
            timeline.append({"kind": "alert", "source": src, "t": d["t"], "message": d.get("message"), "severity": "high"})
    if not timeline or run_id is None:
        return [], stats
    timeline.sort(key=lambda e: e["t"])
    anchor = timeline[-1]["t"]
    extra = {"run_id": run_id, "scenario": key, "outcome": clean.text(run.get("outcome"), 40),
             "mitigations": clean.str_list(attack.get("mitigations"), 8, 24), "mode": "fast"}
    items, src_host, step_techs = [], attacker_host, []
    for ev in timeline:
        if ev.get("kind") == "attack":
            src_host = _ics_host(ev.get("src"), hosts) or attacker_host
            step_techs = clean.techniques(ev.get("techniques"))
            continue
        rule = _forwardable(ev)
        if rule is None:
            continue
        ts = created - (anchor - ev["t"])
        alert = _ics_alert(ev, rule, ts, src_host, hosts, extra, key, step_techs)
        item = _item("ics-sim", f"ics:run:{run_id}:{ev.get('id', ev['t'])}:{ev.get('source')}", alert)
        if item:
            items.append(item)
        else:
            stats["rejected"] += 1
    return items, stats


def ics_live_items(events, modbus, state, hosts: dict, cursor: dict, now: float) -> tuple[list, dict, dict]:
    """Live plant: new alarms from /api/events and blocked Modbus writes from /api/modbus.

    Simulated time runs `speed` times faster than real time, so an event that
    happened dt simulated seconds ago is placed dt/speed real seconds ago.
    """
    stats = {"fetched": 0, "rejected": 0}
    cursor = dict(cursor)
    sim_t = clean.number(state.get("t") if isinstance(state, dict) else None, 0, 1e9)
    speed = clean.number(state.get("speed") if isinstance(state, dict) else None, 0.01, 10000) or 1.0
    if sim_t is None:
        return [], cursor, stats
    if sim_t < cursor.get("live_t", 0):
        cursor["live_id"] = cursor["live_mb_id"] = 0      # the plant was reset: ids start again
    cursor["live_t"] = sim_t

    def ts_of(t):
        return now - max(0.0, sim_t - t) / speed

    items = []
    evs = [e for e in (events if isinstance(events, list) else [])[:2000] if isinstance(e, dict)]
    last_id = cursor.get("live_id", 0)
    newest = last_id
    src_host, step_techs = None, []
    for ev in sorted(evs, key=lambda e: clean.count(e.get("id")) or 0):
        eid, t = clean.count(ev.get("id")), clean.number(ev.get("t"), 0, 1e9)
        if eid is None or t is None:
            stats["rejected"] += 1
            continue
        if ev.get("kind") == "attack":
            src_host = _ics_host(ev.get("src"), hosts) or src_host
            step_techs = clean.techniques(ev.get("techniques"))
        if eid <= last_id:
            continue
        newest = max(newest, eid)
        stats["fetched"] += 1
        rule = _forwardable(ev)
        if rule is None:
            continue
        # With no attack step seen yet there is no source host; the target alone is enough for ai-ids.
        alert = _ics_alert(ev, rule, ts_of(t), src_host, hosts, {"mode": "live"}, "", step_techs)
        item = _item("ics-sim", f"ics:live:{eid}:{ev.get('source')}:{t}", alert)
        if item:
            items.append(item)
        else:
            stats["rejected"] += 1
    cursor["live_id"] = newest

    rows = modbus.get("rows") if isinstance(modbus, dict) else None
    last_mb = cursor.get("live_mb_id", 0)
    newest_mb, blocked = last_mb, {}
    for row in (rows if isinstance(rows, list) else [])[:2000]:
        if not isinstance(row, dict):
            continue
        rid, t = clean.count(row.get("id")), clean.number(row.get("t"), 0, 1e9)
        if rid is None or t is None or rid <= last_mb:
            continue
        newest_mb = max(newest_mb, rid)
        if row.get("result") != "blocked" or row.get("write") is not True:
            continue
        src = clean.ip(row.get("src"))
        if src is None:
            stats["rejected"] += 1
            continue
        b = blocked.setdefault(src, {"count": 0, "first_t": t, "last_id": rid, "unit": row.get("unit"),
                                     "addrs": set(), "reason": clean.text(row.get("reason"), 80)})
        b["count"] += clean.count(row.get("count"), 10**6) or 1
        b["first_t"], b["last_id"] = min(b["first_t"], t), max(b["last_id"], rid)
        a = clean.count(row.get("addr"), 65535)
        if a is not None and len(b["addrs"]) < 10:
            b["addrs"].add(a)
    cursor["live_mb_id"] = newest_mb
    for src, b in blocked.items():
        target = hosts.get(SIS_IP, "SIS-01") if b["unit"] == 2 else hosts.get(PLC_IP, "PLC-01")
        host = _ics_host(src, hosts)
        alert = make_alert("ics-sim", "modbus_write_blocked", ts_of(b["first_t"]), src_host=host, dst_host=target,
                           severity="high", technique_id="T0855", stage="exfil_impact",
                           summary=f"ics-sim: {b['count']} Modbus write(s) from {host} to {target} blocked ({b['reason']})",
                           details={"mode": "live", "sim_src_ip": src, "registers": sorted(b["addrs"]), "count": b["count"]})
        item = _item("ics-sim", f"ics:mb:{src}:{b['last_id']}", alert)
        if item:
            items.append(item)
    return items, cursor, stats


# --------------------------------------------------------------------------- threat-intel
INTEL_ALERT_VERDICTS = {"malicious": "high", "suspicious": "medium", "low-confidence": "low"}


def intel_index(response) -> dict:
    """/api/enrich answer -> {input value: compact, validated context}."""
    out = {}
    results = response.get("results") if isinstance(response, dict) else None
    for r in (results if isinstance(results, list) else [])[:5000]:
        if not isinstance(r, dict) or not isinstance(r.get("input"), str):
            continue
        verdict = r.get("verdict") if r.get("verdict") in (
            "malicious", "suspicious", "low-confidence", "context", "unknown", "unsupported") else "unknown"
        asn = r.get("asn") if isinstance(r.get("asn"), dict) else {}
        actors = [clean.text(a.get("name"), 40) for a in (r.get("actors") if isinstance(r.get("actors"), list) else [])[:5]
                  if isinstance(a, dict)]
        out[r["input"]] = {
            "verdict": verdict, "match": r.get("match") is True,
            "confidence": clean.number(r.get("confidence"), 0, 100),
            "sources": clean.tags(r.get("sources"), 6), "tags": clean.tags(r.get("tags"), 8),
            "malware": clean.text(r.get("malware"), 40), "actors": [a for a in actors if a],
            "inside_drop": clean.text(r.get("inside_drop"), 43),
            "asn": clean.count(asn.get("asn"), 2**32), "as_name": clean.text(asn.get("as_name"), 60),
            "country": clean.text(asn.get("country"), 4),
        }
    return out


def _intel_text(value: str, info: dict) -> str:
    bits = [info["verdict"]]
    if info["malware"]:
        bits.append(f"linked to {info['malware']}")
    if info["actors"]:
        bits.append("groups " + ", ".join(info["actors"][:3]))
    if info["tags"]:
        bits.append("tags " + ", ".join(info["tags"][:4]))
    if info["inside_drop"]:
        bits.append(f"inside Spamhaus DROP {info['inside_drop']}")
    if info["sources"]:
        bits.append("from " + ", ".join(info["sources"][:3]))
    return f"threat-intel: {defang(value)} " + "; ".join(bits)


def apply_intel(items: list, intel: dict) -> list:
    """Add intel context to each item's details; return extra threat-intel alerts.

    A threat-intel alert is only raised when an indicator really matched public
    intel (or sits inside a DROP netblock). It copies the entities of the alert it
    belongs to, so ai-ids files it in the same incident and lists threat-intel as
    one of the systems that saw the activity.
    """
    extra = []
    for item in items:
        notes, raised = [], False
        for value in item["iocs"]:
            info = intel.get(value)
            if not info or info["verdict"] in ("unknown", "unsupported"):
                continue
            notes.append({"ioc": defang(value), **{k: v for k, v in info.items() if v not in (None, [], False)}})
            if raised or info["verdict"] not in INTEL_ALERT_VERDICTS or not (info["match"] or info["inside_drop"]):
                continue
            base = item["alert"]
            ents = {k: base[k] for k in ("src_ip", "dst_ip", "src_host", "dst_host", "dst_port") if k in base}
            conf = (info["confidence"] or 30) / 100
            alert = make_alert("threat-intel", "intel_match", base["ts"] + 0.1, severity=INTEL_ALERT_VERDICTS[info["verdict"]],
                               confidence=min(max(conf, 0.2), 0.99), technique_id=base.get("technique_id"),
                               stage=base.get("stage"), summary=_intel_text(value, info),
                               details={"ioc": defang(value), "seen_by": item["lab"], "about": base["category"],
                                        **{k: v for k, v in info.items() if v not in (None, [], False)}}, **ents)
            new = _item("threat-intel", item["key"] + ":intel", alert)
            if new:
                extra.append(new)
                raised = True
        if notes:
            item["alert"]["details"] = _fit_details({**item["alert"]["details"], "intel": notes[:4]})
    return extra
