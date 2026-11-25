"""R-6: score the agent's output against the AIT-ADS answers.

The ONLY module that reads the answers (eval_phase, eval_event_label). It is called
after the agent has finished; the agent itself never sees them.

"attack" = an alert with an exact attack label inside an attack-phase window.
"""
from __future__ import annotations

import pandas as pd

from .ait_ads import ATTACK_PHASES


def evaluate(network: str, a: pd.DataFrame, links: pd.DataFrame, inc: pd.DataFrame,
             msgs: list[dict], eval_labels: pd.DataFrame, problems: list[str] = ()) -> dict:
    """a, links, inc = investigate(...) output; msgs = incident_updates(...) output."""
    p = a[["alert_id", "incident_id"]].merge(eval_labels, on="alert_id")
    p["kept"] = ~p["incident_id"].isin(set(inc.loc[inc["routine"], "incident_id"]))
    p["attack"] = (p["eval_event_label"] != "-") & p["eval_phase"].isin(ATTACK_PHASES)
    normal_time = ~p["eval_phase"].isin(ATTACK_PHASES)
    att = p[p["kept"] & p["attack"]]
    counts = att["incident_id"].value_counts()
    top = counts.index[0]
    inside = p[p["incident_id"].isin(counts.index)]
    top_msg = next(m for m in msgs if m["incident_id"] == top.replace("inc-", f"inc-{network}-", 1))
    in_window = p[p["eval_phase"].isin(ATTACK_PHASES)]
    phases_seen = in_window.groupby("eval_phase")["kept"].any()
    return {
        "network": network, "alerts": len(p), "alerts_kept": round(p["kept"].mean(), 3),
        "incidents": int((~inc["routine"]).sum()),
        "attack_kept": round(len(att) / max(int(p["attack"].sum()), 1), 4),
        "false_alarms_kept": round(p.loc[normal_time, "kept"].mean(), 4),
        "attack_incidents": len(counts),
        "top_share": round(counts.iloc[0] / len(att), 3),
        "top_steps": ", ".join(sorted(set(att.loc[att["incident_id"] == top, "eval_event_label"]))),
        "purity": round(inside["attack"].mean(), 3),
        "phases_seen": f"{int(phases_seen.sum())} of {len(phases_seen)}",
        "top_techniques": ", ".join(t["technique_id"] for t in top_msg["candidate_techniques"]),
        "top_stages": ", ".join(s["stage"] for s in top_msg["stage_hypotheses"]) or "-",
        "incidents_with_technique": sum(bool(m["candidate_techniques"]) for m in msgs),
        "out_of_order_links": int((links["order"] == "out_of_order").sum()),
        "long_gap_joins": int(links["long_gap"].sum()),
        "contract_problems": len(problems),
    }
