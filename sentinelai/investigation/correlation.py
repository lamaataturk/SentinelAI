"""R-2 / R-3: the Investigation Agent's five linking rules (version 2, 24 Nov).

Reads only the alerts table, never the answers. Every link keeps its reason.

1. Merge bursts: repeats of the same alert type on the same machine less than
   burst_gap_s apart become one group, capped at max_group_span_s. Groups keep
   their signatures and every src/dst IP.
2. Routine filter: an alert type seen in at least routine_min_bins 10-minute
   slots of the first baseline_hours ("normal day") is routine, unless the group
   is a spike of more than spike_factor x its busiest normal slot.
3. Link only on shared evidence: a group joins an incident only if it shares a
   machine or IP with it and starts within max_gap_s of when that machine/IP was
   last seen. strong if the gap <= strong_gap_s, else weak.
4. Order check: a step whose Kill Chain stage comes BEFORE a stage the incident
   already reached is still linked, but weak and marked out_of_order.
5. Long-gap joins (decision b): a later incident joins an earlier one when they
   share a machine/IP, the gap is over max_gap_s but at most max_long_gap_s, and
   its earliest stage comes strictly after the earlier one's latest stage.
   Always weak, marked long_gap.

Tuned on russellmitchell, santos and shaw only (decisions of 23 Nov):
max_gap_s 30 -> 45 min; routine filter stays at 6 slots / 3x spike.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass

import numpy as np
import pandas as pd

from .knowledge import signature_stage

SLOT_S = 600  # 10-minute slots for the routine baseline


@dataclass(frozen=True)
class CorrelationConfig:
    burst_gap_s: int = 60
    max_group_span_s: int = 600
    baseline_hours: float = 24
    routine_min_bins: int = 6
    spike_factor: float = 3
    max_gap_s: int = 2700           # tuned 30 -> 45 min (23 Nov)
    strong_gap_s: int = 300
    max_long_gap_s: int = 24 * 3600  # Rule 5 limit (design choice, not tuned)

    def as_dict(self) -> dict:
        return asdict(self)


# ------------------------------------------------------------------ Rule 1
def _ips(s):
    return sorted({ip for ip in s.dropna()})


def merge_bursts(alerts: pd.DataFrame, burst_gap_s=60, max_group_span_s=600):
    """Returns (groups, group_of_alert); group_of_alert is indexed like alerts."""
    a = alerts.sort_values(["host", "short", "ts", "alert_id"], kind="stable").copy()
    for col in ("src_ip", "dst_ip"):
        if col not in a:
            a[col] = None
    host, short = a["host"].astype(object), a["short"].astype(object)  # same result on any pandas version
    same_type = ((host == host.shift()) & (short == short.shift())).fillna(False).astype(bool)
    new_run = ~same_type | (a["ts"].diff() > burst_gap_s).fillna(False).astype(bool)
    run_id = new_run.astype("int64").cumsum()
    run_start = a.groupby(run_id)["ts"].transform("min")
    piece = (a["ts"] - run_start) // max_group_span_s
    a["group_key"] = run_id.astype(str) + "-" + piece.astype(str)
    groups = (a.groupby("group_key", sort=False)
                .agg(host=("host", "first"), host_ip=("host_ip", "first"),
                     short=("short", "first"), signature=("signature", "first"),
                     signatures=("signature", lambda s: sorted(set(s))),
                     src_ips=("src_ip", _ips), dst_ips=("dst_ip", _ips),
                     first_ts=("ts", "min"), last_ts=("ts", "max"),
                     count=("ts", "size"), first_alert=("alert_id", "first"))
                .sort_values("first_ts", kind="stable")
                .reset_index())
    groups["group_id"] = [f"grp-{i:06d}" for i in range(len(groups))]
    key_to_id = dict(zip(groups["group_key"], groups["group_id"]))
    group_of_alert = a["group_key"].map(key_to_id).reindex(alerts.index)
    return groups.drop(columns="group_key"), group_of_alert


# ------------------------------------------------------------------ Rule 2
def routine_baseline(alerts: pd.DataFrame, baseline_hours=24) -> pd.DataFrame:
    start = alerts["ts"].min()
    base = alerts[alerts["ts"] < start + baseline_hours * 3600]
    slot = (base["ts"] - start) // SLOT_S
    per_slot = base.assign(slot=slot).groupby(["host", "short", "slot"]).size()
    return (per_slot.groupby(level=["host", "short"])
                    .agg(baseline_slots="size", baseline_peak="max")
                    .reset_index())


def mark_routine(groups: pd.DataFrame, baseline: pd.DataFrame, routine_min_bins=6, spike_factor=3):
    g = groups.merge(baseline, on=["host", "short"], how="left")
    g[["baseline_slots", "baseline_peak"]] = g[["baseline_slots", "baseline_peak"]].fillna(0)
    regular = g["baseline_slots"] >= routine_min_bins
    spike = g["count"] > spike_factor * g["baseline_peak"]
    g["routine"] = regular & ~spike
    g["why"] = np.select(
        [regular & ~spike, regular & spike, ~regular],
        ["routine: seen regularly on a normal day, at normal volume",
         "unusual: a normal alert type, but a spike over its normal volume",
         "unusual: not seen regularly on a normal day"],
        default="")
    return g


# ------------------------------------------------------------------ Rules 3 and 4
def entities(group) -> set[str]:
    ents = {f"host:{group['host']}"}
    if isinstance(group.get("host_ip"), str):
        ents.add(f"ip:{group['host_ip']}")
    for col in ("src_ips", "dst_ips"):
        for ip in group.get(col) or []:
            ents.add(f"ip:{ip}")
    return ents


def group_stage(group) -> int | None:
    stages = [signature_stage(s) for s in group.get("signatures") or [group.get("signature")]]
    stages = [s for s in stages if s]
    return min(stages) if stages else None


def link_groups(groups: pd.DataFrame, max_gap_s=2700, strong_gap_s=300):
    """Rule 3 + Rule 4. Returns (groups with incident_id, links)."""
    groups = groups.sort_values(["first_ts", "group_id"], kind="stable").reset_index(drop=True)
    incident_of, links = [], []
    max_stage = {}      # incident -> latest Kill Chain stage reached so far
    last_seen = {}      # entity -> {'incident_id', 'last_ts', 'alert_id'}
    n = 0
    for row in groups.to_dict("records"):
        if row["routine"]:
            n += 1
            incident_of.append(f"inc-{n:06d}")
            continue
        ents, stage, best = entities(row), group_stage(row), None
        for e in sorted(ents):
            seen = last_seen.get(e)
            if seen is None:
                continue
            gap = row["first_ts"] - seen["last_ts"]
            if gap <= max_gap_s and (best is None or gap < best[0]):
                best = (gap, e, seen)
        if best is None:
            n += 1
            iid = f"inc-{n:06d}"
        else:
            gap, e, seen = best
            iid = seen["incident_id"]
            reached = max_stage.get(iid)
            if stage is None or reached is None:
                order = "unknown"
            else:
                order = "out_of_order" if stage < reached else "in_order"
            links.append({"incident_id": iid, "alert_id": row["first_alert"],
                          "linked_to": seen["alert_id"], "shared_entity": e,
                          "gap_seconds": int(max(gap, 0)),
                          "strength": "strong" if gap <= strong_gap_s and order != "out_of_order" else "weak",
                          "order": order, "long_gap": False})
        if stage is not None:
            max_stage[iid] = max(max_stage.get(iid, 0), stage)
        incident_of.append(iid)
        for e in ents:
            prev = last_seen.get(e)
            if prev is None or prev["incident_id"] != iid or row["last_ts"] >= prev["last_ts"]:
                last_seen[e] = {"incident_id": iid, "last_ts": row["last_ts"], "alert_id": row["first_alert"]}
    groups["incident_id"] = incident_of
    links = pd.DataFrame(links, columns=["incident_id", "alert_id", "linked_to", "shared_entity",
                                         "gap_seconds", "strength", "order", "long_gap"])
    return groups, links


# ------------------------------------------------------------------ Rule 5
def join_long_gaps(groups: pd.DataFrame, links: pd.DataFrame, max_gap_s=2700, max_long_gap_s=24 * 3600):
    """Rule 5 - decision (b). Incidents without a known stage never join."""
    g = groups.copy()
    g["stage"] = [group_stage(r) for r in g.to_dict("records")]
    real = g[~g["routine"]]
    inc = {}
    for iid, part in real.groupby("incident_id", sort=False):
        rows = part.sort_values("first_ts").to_dict("records")
        stages = [r["stage"] for r in rows if r["stage"]]
        inc[iid] = {"first_ts": rows[0]["first_ts"], "last_ts": max(r["last_ts"] for r in rows),
                    "ents": set().union(*[entities(r) for r in rows]),
                    "min_stage": min(stages) if stages else None, "max_stage": max(stages) if stages else None,
                    "first_alert": rows[0]["first_alert"], "last_alert": rows[-1]["first_alert"]}
    merged_into, new_links = {}, []
    for b in sorted(inc, key=lambda k: inc[k]["first_ts"]):
        B = inc[b]
        if B["min_stage"] is None:
            continue
        best = None
        for a_id, A in inc.items():
            if a_id == b or a_id in merged_into or A["max_stage"] is None:
                continue
            gap = B["first_ts"] - A["last_ts"]
            shared = sorted(A["ents"] & B["ents"])
            if max_gap_s < gap <= max_long_gap_s and shared and B["min_stage"] > A["max_stage"]:
                if best is None or gap < best[0]:
                    best = (gap, a_id, shared[0])
        if best:
            gap, a_id, e = best
            A = inc[a_id]
            new_links.append({"incident_id": a_id, "alert_id": B["first_alert"], "linked_to": A["last_alert"],
                              "shared_entity": e, "gap_seconds": int(gap), "strength": "weak",
                              "order": "in_order", "long_gap": True})
            merged_into[b] = a_id
            A["last_ts"] = max(A["last_ts"], B["last_ts"])
            A["ents"] |= B["ents"]
            A["max_stage"] = max(A["max_stage"], B["max_stage"])
            A["last_alert"] = B["last_alert"]
    if merged_into:
        g["incident_id"] = g["incident_id"].replace(merged_into)
        links = links.assign(incident_id=links["incident_id"].replace(merged_into))
        links = pd.concat([links, pd.DataFrame(new_links)], ignore_index=True)
    return g.drop(columns="stage"), links


# ------------------------------------------------------------------ incidents
def summarise_incidents(groups: pd.DataFrame, links: pd.DataFrame) -> pd.DataFrame:
    weak = links[links["strength"] == "weak"].groupby("incident_id").size()
    inc = groups.groupby("incident_id").agg(
        routine=("routine", "all"), groups=("group_id", "size"), alerts=("count", "sum"),
        hosts=("host", lambda s: sorted(set(s))), first_ts=("first_ts", "min"),
        last_ts=("last_ts", "max"), types=("short", lambda s: sorted(set(s)))).reset_index()
    inc["weak_links"] = inc["incident_id"].map(weak).fillna(0).astype(int)
    inc["confidence"] = np.select([inc["routine"] | (inc["groups"] == 1), inc["weak_links"] > 0],
                                  ["low", "medium"], default="high")
    return inc


def investigate(alerts: pd.DataFrame, cfg: CorrelationConfig = CorrelationConfig()):
    """The Investigation Agent (Rules 1-5). Reads only the alerts table.

    Returns (alerts with incident_id, groups, links, incidents).
    """
    g, g_of_a = merge_bursts(alerts, cfg.burst_gap_s, cfg.max_group_span_s)
    g = mark_routine(g, routine_baseline(alerts, cfg.baseline_hours), cfg.routine_min_bins, cfg.spike_factor)
    g, links = link_groups(g, cfg.max_gap_s, cfg.strong_gap_s)
    g, links = join_long_gaps(g, links, cfg.max_gap_s, cfg.max_long_gap_s)
    inc = summarise_incidents(g, links)
    a = alerts.assign(incident_id=g_of_a.map(g.set_index("group_id")["incident_id"]).values)
    return a, g, links, inc
