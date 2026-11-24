"""ALL-2: builds the hand-made fixtures in fixtures/.

The fixtures tell one small story so every agent can be built before the
real upstream agent exists:

  attack   203.0.113.66 (outside) scans the network, attacks the WordPress
           server 10.0.1.20, uploads a web shell, runs commands, then the
           web server leaks data over DNS through 10.0.1.53.
  benign   the monitoring server 10.0.1.5 runs its routine port scan,
           an employee 10.0.2.15 downloads updates, the backup host
           10.0.1.30 copies files to the file share 10.0.1.40.

All data is invented. IP addresses are kept in every file.
Run:  python scripts/make_fixtures.py
"""
from __future__ import annotations

import csv
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "fixtures"
NET = "fixture-net"
T0 = datetime(2026, 1, 10, 8, 0, 0, tzinfo=timezone.utc)

ATTACKER, WEB, MAIL, DNS = "203.0.113.66", "10.0.1.20", "10.0.1.25", "10.0.1.53"
MONITOR, EMPLOYEE, UPDATES = "10.0.1.5", "10.0.2.15", "198.51.100.200"
BACKUP, FILESHARE = "10.0.1.30", "10.0.1.40"


def ts(minutes: float) -> str:
    return (T0 + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")


# ----------------------------------------------------------------- flows
def make_flows():
    rng = random.Random(42)
    rows = []

    def flow(minute, src, dst, dport, proto, nbytes, pkts, dur, raw, label, win):
        fid = f"f-{len(rows) + 1:06d}"
        rows.append({
            "flow_id": fid, "network": NET,
            "start_time": ts(minute), "end_time": ts(minute + dur / 60),
            "src_ip": src, "dst_ip": dst, "src_port": rng.randint(32768, 60999),
            "duration_s": round(dur, 3), "bytes": nbytes, "packets": pkts,
            "bytes_per_packet": round(nbytes / pkts, 2) if pkts else 0.0,
            "dst_port": dport, "protocol": proto,
            "win5_conn_count": win[0], "win5_distinct_dst_ports": win[1],
            "win5_distinct_dst_hosts": win[2], "win5_dns_count": win[3],
            "win5_dns_avg_bytes": win[4],
            "label_raw": raw, "label": label,
        })
        return fid

    f = {}
    # normal background traffic
    for i in range(10):
        flow(i * 3, EMPLOYEE, MAIL, 993, 6, rng.randint(2000, 9000), rng.randint(10, 40),
             rng.uniform(0.5, 4), "mail", 0, (3, 2, 2, 1, 70.0))
        flow(i * 3 + 1, EMPLOYEE, DNS, 53, 17, rng.randint(60, 120), 2,
             0.02, "dns", 0, (4, 3, 3, 2, 80.0))
    # attack: scans
    f["scan1"] = flow(0.0, ATTACKER, WEB, 22, 6, 60, 1, 0.01, "service_scan", 1, (180, 160, 2, 0, 0.0))
    f["scan2"] = flow(0.2, ATTACKER, WEB, 8080, 6, 60, 1, 0.01, "service_scan", 1, (240, 210, 2, 0, 0.0))
    f["scan3"] = flow(2.0, ATTACKER, MAIL, 25, 6, 60, 1, 0.01, "service_scan", 1, (300, 230, 3, 0, 0.0))
    f["wpscan"] = flow(10.0, ATTACKER, WEB, 80, 6, 48000, 400, 95.0, "wpscan", 1, (420, 3, 2, 0, 0.0))
    f["exploit"] = flow(18.0, ATTACKER, WEB, 80, 6, 6200, 18, 1.4, "upload_rce_shell", 1, (30, 1, 1, 0, 0.0))
    f["shell"] = flow(20.0, ATTACKER, WEB, 80, 6, 3100, 12, 0.9, "upload_rce_shell", 1, (12, 1, 1, 0, 0.0))
    f["cmd"] = flow(25.0, ATTACKER, WEB, 80, 6, 2500, 14, 1.1, "remote_command", 1, (9, 1, 1, 0, 0.0))
    f["exfil1"] = flow(40.0, WEB, DNS, 53, 17, 255, 2, 0.03, "data_exfiltration", 1, (310, 1, 1, 300, 240.0))
    f["exfil2"] = flow(45.0, WEB, DNS, 53, 17, 251, 2, 0.03, "data_exfiltration", 1, (420, 1, 1, 410, 243.0))
    # benign but noisy
    f["monitor"] = flow(5.0, MONITOR, WEB, 443, 6, 60, 1, 0.01, "monitoring", 0, (150, 40, 25, 0, 0.0))
    f["update"] = flow(30.0, EMPLOYEE, UPDATES, 443, 6, 85_000_000, 60000, 210.0, "browsing_update", 0, (6, 1, 2, 1, 75.0))
    f["backup"] = flow(90.0, BACKUP, FILESHARE, 445, 6, 420_000_000, 300000, 900.0, "file_share", 0, (2, 1, 1, 0, 0.0))
    return rows, f


# ----------------------------------------------------------------- messages
def env(mid, mtype, created_min, producer, refs):
    return {"message_id": mid, "message_type": mtype, "schema_version": "1.0",
            "created_at": ts(created_min), "producer": producer, "evidence_refs": refs}


def alert(n, minute, flows, src, dst, sport, dport, proto, detector, score, rules, summary,
          first=None, last=None, ids_source=None, signature=None, hostname=None):
    refs = [f"flow:{x}" for x in flows] + [f"rule:{r}" for r in rules]
    return {**env(f"alert-{n:04d}", "Alert", minute + 0.5, "detection_agent", refs),
            "network": NET, "detector": detector,
            "first_seen": ts(first if first is not None else minute),
            "last_seen": ts(last if last is not None else minute),
            "src_ip": src, "dst_ip": dst, "src_port": sport, "dst_port": dport, "protocol": proto,
            "rf_score": score, "rule_hits": rules, "ids_source": ids_source, "signature": signature,
            "user": None, "hostname": hostname, "summary": summary}


def make_alerts(f, flows_by_id):
    sp = lambda k: flows_by_id[f[k]]["src_port"]
    return [
        alert(1, 0.0, [f["scan1"], f["scan2"]], ATTACKER, WEB, sp("scan1"), 22, 6, "hybrid", 0.91,
              ["R-MANY-PORTS-5MIN"], "Possible port scan: 210 ports on the web server in 5 minutes", last=0.2,
              hostname="wordpress"),
        alert(2, 2.0, [f["scan3"]], ATTACKER, MAIL, sp("scan3"), 25, 6, "hybrid", 0.87,
              ["R-MANY-PORTS-5MIN"], "Possible port scan of the mail server from the same outside address",
              hostname="mail"),
        alert(3, 10.0, [f["wpscan"]], ATTACKER, WEB, sp("wpscan"), 80, 6, "rf", 0.78, [],
              "Unusually long, high-volume HTTP session to the WordPress site", last=11.6, hostname="wordpress"),
        alert(4, 18.0, [f["exploit"]], ATTACKER, WEB, sp("exploit"), 80, 6, "rf", 0.82, [],
              "Suspicious HTTP upload to the WordPress server", hostname="wordpress"),
        alert(5, 20.0, [f["shell"]], ATTACKER, WEB, sp("shell"), 80, 6, "rf", 0.80, [],
              "Short HTTP requests right after the upload (possible web shell use)", hostname="wordpress"),
        alert(6, 25.0, [f["cmd"]], ATTACKER, WEB, sp("cmd"), 80, 6, "rf", 0.74, [],
              "Repeated short HTTP requests that may carry commands", hostname="wordpress"),
        alert(7, 40.0, [f["exfil1"]], WEB, DNS, sp("exfil1"), 53, 17, "hybrid", 0.93,
              ["R-DNS-VOLUME-HIGH", "R-DNS-LARGE-QUERY"], "300 DNS requests in 5 minutes with unusually large queries",
              hostname="wordpress"),
        alert(8, 45.0, [f["exfil2"]], WEB, DNS, sp("exfil2"), 53, 17, "hybrid", 0.95,
              ["R-DNS-VOLUME-HIGH", "R-DNS-LARGE-QUERY"], "DNS volume from the web server keeps rising",
              hostname="wordpress"),
        alert(9, 5.0, [f["monitor"]], MONITOR, WEB, sp("monitor"), 443, 6, "rules", 0.40,
              ["R-MANY-PORTS-5MIN"], "Many ports and hosts contacted by the monitoring server", hostname="monitoring"),
        alert(10, 30.0, [f["update"]], EMPLOYEE, UPDATES, sp("update"), 443, 6, "rf", 0.55, [],
              "Large HTTPS download by an employee workstation", last=33.5),
        alert(11, 90.0, [f["backup"]], BACKUP, FILESHARE, sp("backup"), 445, 6, "rf", 0.52, [],
              "Very large internal file transfer at night", last=105.0, hostname="backup"),
    ]


def tech(tid, name, support, alerts):
    return {"technique_id": tid, "name": name, "support": support,
            "evidence_refs": [f"alert:alert-{a:04d}" for a in alerts]}


def stage(name, support, alerts):
    return {"stage": name, "support": support, "evidence_refs": [f"alert:alert-{a:04d}" for a in alerts]}


def link(a, to, entity, gap, strength):
    return {"alert_id": f"alert-{a:04d}", "linked_to": f"alert-{to:04d}",
            "shared_entity": entity, "gap_seconds": gap, "strength": strength}


def incident(n, inc, version, minute, alerts, ips, start, end, links, techniques, stages, conf, notes, hosts=()):
    refs = [f"alert:alert-{a:04d}" for a in alerts]
    return {**env(f"incupd-{n:04d}", "IncidentUpdate", minute, "investigation_agent", refs),
            "incident_id": inc, "version": version, "status": "open", "network": NET,
            "alert_ids": [f"alert-{a:04d}" for a in alerts],
            "entities": {"ips": ips, "hosts": list(hosts), "users": []},
            "start_time": ts(start), "end_time": ts(end), "link_reasons": links,
            "candidate_techniques": techniques, "stage_hypotheses": stages,
            "confidence": conf, "uncertainty_notes": notes}


def make_incidents():
    return [
        # first version: only the scans and the web attack are known
        incident(1, "inc-0001", 1, 19.0, [1, 2, 3, 4], [ATTACKER, WEB, MAIL], 0.0, 18.0,
                 [link(2, 1, f"ip:{ATTACKER}", 120, "strong"), link(3, 1, f"ip:{ATTACKER}", 600, "strong"),
                  link(4, 3, f"ip:{ATTACKER}", 480, "strong")],
                 [tech("T1595", "Active Scanning", "strong", [1, 2, 3]),
                  tech("T1190", "Exploit Public-Facing Application", "weak", [4])],
                 [stage("reconnaissance", "strong", [1, 2, 3]), stage("exploitation", "weak", [4])],
                 "medium", "Exploit is inferred from traffic shape only; no host log confirms it yet.",
                 hosts=["wordpress", "mail"]),
        # second version: the full chain
        incident(2, "inc-0001", 2, 46.0, [1, 2, 3, 4, 5, 6, 7, 8], [ATTACKER, WEB, MAIL, DNS], 0.0, 45.0,
                 [link(2, 1, f"ip:{ATTACKER}", 120, "strong"), link(3, 1, f"ip:{ATTACKER}", 600, "strong"),
                  link(4, 3, f"ip:{ATTACKER}", 480, "strong"), link(5, 4, f"ip:{WEB}", 120, "strong"),
                  link(6, 5, f"ip:{WEB}", 300, "strong"), link(7, 6, f"ip:{WEB}", 900, "weak"),
                  link(8, 7, f"ip:{WEB}", 300, "strong")],
                 [tech("T1595", "Active Scanning", "strong", [1, 2, 3]),
                  tech("T1190", "Exploit Public-Facing Application", "strong", [3, 4]),
                  tech("T1505.003", "Server Software Component: Web Shell", "weak", [5]),
                  tech("T1059", "Command and Scripting Interpreter", "weak", [6]),
                  tech("T1048", "Exfiltration Over Alternative Protocol", "strong", [7, 8])],
                 [stage("reconnaissance", "strong", [1, 2, 3]), stage("exploitation", "strong", [4]),
                  stage("installation", "weak", [5]), stage("command_and_control", "weak", [6]),
                  stage("actions_on_objectives", "strong", [7, 8])],
                 "high", "Link 6->7 is weak: a 15-minute gap and a new destination (DNS server). "
                         "Web shell and command steps are not confirmed by host logs.",
                 hosts=["wordpress", "mail"]),
        incident(3, "inc-0002", 1, 6.0, [9], [MONITOR, WEB], 5.0, 5.0, [],
                 [tech("T1595", "Active Scanning", "weak", [9])], [stage("reconnaissance", "weak", [9])],
                 "low", "Source is the monitoring server; this is most likely its scheduled scan.",
                 hosts=["monitoring"]),
        incident(4, "inc-0003", 1, 34.0, [10], [EMPLOYEE, UPDATES], 30.0, 33.5, [], [], [],
                 "low", "Single alert, no shared entity with other alerts; looks like a software update."),
        incident(5, "inc-0004", 1, 106.0, [11], [BACKUP, FILESHARE], 90.0, 105.0, [], [], [],
                 "low", "Single alert between two internal hosts at backup time; likely the nightly backup.",
                 hosts=["backup"]),
    ]


def rec(action, reason, technique=None):
    return {"action": action, "reason": reason, "technique_id": technique, "requires_human_approval": True}


def assessment(n, inc, version, minute, severity, rule, reasons, recs):
    return {**env(f"assess-{n:04d}", "Assessment", minute, "response_agent", [f"incident:{inc}"]),
            "incident_id": inc, "incident_version": version, "severity": severity,
            "policy_rule_id": rule, "severity_reasons": reasons, "recommendations": recs,
            "review_status": "pending"}


def make_assessments():
    return [
        assessment(1, "inc-0001", 2, 47.0, "High", "SEV-MULTISTAGE-OBJECTIVE",
                   ["Five linked stages from reconnaissance to actions on objectives",
                    "Strong evidence of possible data theft over DNS (alerts 7 and 8)",
                    "Target is the public WordPress server"],
                   [rec("Check the WordPress server for unknown or recently uploaded files",
                        "Possible web shell upload (alert-0005)", "T1505.003"),
                    rec("Preserve web server and DNS logs for the incident window",
                        "Needed to confirm or rule out the attack"),
                    rec("Review outgoing DNS traffic from 10.0.1.20",
                        "Possible exfiltration over DNS (alerts 7 and 8)", "T1048"),
                    rec("Consider blocking 203.0.113.66 at the firewall",
                        "Same outside address in every early step", "T1595")]),
        assessment(2, "inc-0002", 1, 7.0, "Low", "SEV-SINGLE-WEAK",
                   ["One alert with weak support", "Source is a known monitoring host"],
                   [rec("Confirm the scan matches the monitoring schedule", "Innocent explanation is likely")]),
        assessment(3, "inc-0003", 1, 35.0, "Low", "SEV-SINGLE-UNMAPPED",
                   ["One alert, no technique mapped"], []),
        assessment(4, "inc-0004", 1, 107.0, "Low", "SEV-SINGLE-UNMAPPED",
                   ["One alert, no technique mapped", "Matches the backup window"], []),
    ]


def make_report_requests():
    def rr(n, inc, assess, minute, producer, reason):
        return {**env(f"repreq-{n:04d}", "ReportRequest", minute, producer,
                      [f"incident:{inc}", f"assessment:{assess}"]),
                "incident_id": inc, "assessment_id": assess, "requested_by_reason": reason,
                "format": "markdown"}
    return [rr(1, "inc-0001", "assess-0001", 47.5, "orchestrator", "New High assessment"),
            rr(2, "inc-0002", "assess-0002", 8.0, "analyst", "Analyst asked for a report")]


def main():
    OUT.mkdir(exist_ok=True)
    flows, f = make_flows()
    with open(OUT / "features_sample.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(flows[0].keys()))
        w.writeheader()
        w.writerows(flows)
    by_id = {r["flow_id"]: r for r in flows}
    files = {
        "alerts.json": make_alerts(f, by_id),
        "incident_updates.json": make_incidents(),
        "assessments.json": make_assessments(),
        "report_requests.json": make_report_requests(),
    }
    for name, data in files.items():
        (OUT / name).write_text(json.dumps(data, indent=2) + "\n")
    print(f"wrote {len(flows)} flows and {sum(len(v) for v in files.values())} messages to {OUT}")


if __name__ == "__main__":
    main()
