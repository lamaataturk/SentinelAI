"""R-5: turn incidents into contract IncidentUpdate messages for the Response Agent.

Techniques and Kill Chain stages come from Omar's O-3 mapper (map_alerts), fed with
the incident's Alert messages and the observations from knowledge.py. Every IP the
alerts carry is kept in entities.ips.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from . import knowledge


def _iso(ts) -> str:
    return pd.Timestamp(int(ts), unit="s", tz="UTC").strftime("%Y-%m-%dT%H:%M:%SZ")


def _val(x):
    return None if x is None or (isinstance(x, float) and np.isnan(x)) or x is pd.NA else x


def alert_message(r: dict) -> dict:
    """One row of the alerts table as a contract Alert message (IDS alert, every IP kept)."""
    return {"message_id": r["alert_id"], "message_type": "Alert", "schema_version": "1.0",
            "created_at": r["time"], "producer": "ait_ids_loader",
            "evidence_refs": [f"raw_log:{r['network']}/{r['alert_id']}"],
            "network": r["network"], "detector": "ids", "first_seen": r["time"], "last_seen": r["time"],
            "host_ip": _val(r["host_ip"]), "src_ip": _val(r.get("src_ip")), "dst_ip": _val(r.get("dst_ip")),
            "src_port": None, "dst_port": None, "protocol": None, "rf_score": None, "rule_hits": [],
            "ids_source": r["ids_source"], "signature": r["signature"], "user": None,
            "hostname": r["host"], "summary": f"{r['short']}: {r['signature']}"}


def incident_updates(a: pd.DataFrame, g: pd.DataFrame, links: pd.DataFrame, inc: pd.DataFrame,
                     network: str, external_sources=()) -> list[dict]:
    """One IncidentUpdate per non-routine incident, in time order."""
    if not knowledge.MAPPER_AVAILABLE:
        raise RuntimeError("Omar's O-3 mapper (sentinelai/frameworks/mapper.py) is not in the repo yet")
    msgs = []
    by_inc = dict(tuple(a.groupby("incident_id")))
    groups_by_inc = dict(tuple(g.groupby("incident_id")))
    links_by_inc = dict(tuple(links.groupby("incident_id")))
    for n, r in enumerate(inc[~inc["routine"]].sort_values("first_ts").itertuples(index=False), start=1):
        sub = by_inc[r.incident_id].sort_values("ts", kind="stable")
        mapping = knowledge.map_alerts([alert_message(x) for x in sub.to_dict("records")],
                                       external_sources=external_sources,
                                       observations=knowledge.observations_for(sub))
        lr = links_by_inc[r.incident_id].to_dict("records") if r.incident_id in links_by_inc else []
        ips = sorted({ip for col in ("host_ip", "src_ip", "dst_ip") if col in sub for ip in sub[col].dropna()})
        notes = []
        if not mapping["candidate_techniques"]:
            notes.append("No ATT&CK technique supported by the available evidence.")
        elif all(t["support"] == "weak" for t in mapping["candidate_techniques"]):
            notes.append("All techniques are weak: IDS signatures alone, no reviewed host evidence.")
        if not mapping["stage_hypotheses"]:
            notes.append("No Kill Chain stage hypothesis (needs two independent alert types per step).")
        if any(l["order"] == "out_of_order" for l in lr):
            notes.append(f"{sum(l['order'] == 'out_of_order' for l in lr)} link(s) out of Kill Chain order (kept, marked weak).")
        if any(l["long_gap"] for l in lr):
            notes.append("Joined across a long gap by shared machine/IP and Kill Chain order (Rule 5, weak).")
        if r.weak_links:
            notes.append(f"{r.weak_links} weak link(s) in total.")
        if r.groups == 1:
            notes.append("Single alert group; nothing else linked to it.")
        firsts = groups_by_inc[r.incident_id].sort_values("first_ts")["first_alert"].tolist()
        msgs.append({
            "message_id": f"incupd-{network}-{n:06d}", "message_type": "IncidentUpdate",
            "schema_version": "1.0", "created_at": _iso(r.last_ts), "producer": "investigation_agent",
            "evidence_refs": [f"alert:{x}" for x in firsts],
            "incident_id": r.incident_id.replace("inc-", f"inc-{network}-", 1),
            "version": 1, "status": "open", "network": network,
            "alert_ids": sub["alert_id"].tolist(),
            "entities": {"ips": ips, "hosts": list(r.hosts), "users": []},
            "start_time": _iso(r.first_ts), "end_time": _iso(r.last_ts),
            "link_reasons": [{k: (int(l[k]) if k == "gap_seconds" else (bool(l[k]) if k == "long_gap" else l[k]))
                              for k in ("alert_id", "linked_to", "shared_entity", "gap_seconds",
                                        "strength", "order", "long_gap")} for l in lr],
            "candidate_techniques": mapping["candidate_techniques"],
            "stage_hypotheses": mapping["stage_hypotheses"],
            "confidence": r.confidence, "uncertainty_notes": " ".join(notes),
        })
    return msgs
