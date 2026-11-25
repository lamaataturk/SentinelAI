"""Page 2: searchable alert table and alert details."""
from __future__ import annotations

import pandas as pd
import streamlit as st

from sentinelai.dashboard import nav, theme
from sentinelai.dashboard.views.common import fetch, system

DETECTORS = ["All", "hybrid", "rf", "rules", "ids"]


def _table(items: list[dict]) -> pd.DataFrame:
    return pd.DataFrame([{
        "Alert": a["message_id"],
        "First seen (UTC)": theme.fmt_ts(a["first_seen"]),
        "Detector": a["detector"],
        "RF score": theme.fmt_score(a["rf_score"]),
        "Rule hits": ", ".join(a["rule_hits"]) or "none",
        "Source IP": theme.fmt_ip(a["src_ip"]),
        "Destination IP": theme.fmt_ip(a["dst_ip"]),
        "Host IP": theme.fmt_ip(a["host_ip"]),
        "Dst port": "not recorded" if a["dst_port"] is None else str(a["dst_port"]),
        "Host": a["hostname"] or "not recorded",
        "Summary": a["summary"],
        "Incidents": ", ".join(a["incident_ids"]) or "none",
        "Evidence refs": ", ".join(a["evidence_refs"]),
    } for a in items])


def render() -> None:
    sys_info = system()
    theme.header("Alerts", "Alert messages written by the Detection Agent (or the AIT IDS loader).")
    theme.demo_banner(sys_info)

    with st.container(border=True):
        c1, c2, c3, c4 = st.columns([2.2, 1.2, 1.6, 1.6])
        q = c1.text_input("Search", placeholder="alert ID, summary, signature, host…", key="al-q")
        detector = c2.selectbox("Detection method", DETECTORS, key="al-det")
        ip = c3.text_input("IP address", placeholder="source, destination or host IP", key="al-ip")
        score_mode = c4.selectbox("RF score", ["Any", "Has a score", "No score"], key="al-score-mode")
        min_score = None
        if score_mode == "Has a score":
            min_score = st.slider("Minimum RF score", 0.0, 1.0, 0.0, 0.05, key="al-min")

    data = fetch("/api/alerts", q=q.strip() or None, detector=None if detector == "All" else detector,
                 ip=ip.strip() or None, min_score=min_score or None,
                 has_score={"Has a score": "true", "No score": "false"}.get(score_mode))
    items = data["items"]
    st.caption(f"{data['total']} alert(s) match. RF score = Random Forest output between 0 and 1. "
               "It is not a calibrated probability or an accuracy figure. \"not available\" means the "
               "detector produced no score; it is not a score of zero.")
    if not items:
        theme.empty("No alerts match these filters.")
        return
    st.dataframe(_table(items), hide_index=True, height=min(460, 38 + 35 * len(items)))

    theme.section("Alert details")
    ids = [a["message_id"] for a in items]
    if st.session_state.get("alert_id") not in ids:
        st.session_state["alert_id"] = ids[0]
    alert_id = st.selectbox("Alert", ids, key="alert_id")
    alert = fetch(f"/api/alerts/{alert_id}")

    c1, c2 = st.columns([3, 2])
    with c1:
        with st.container(border=True):
            theme.html_block(f"<b>{theme.esc(alert['summary'])}</b><br>"
                             + theme.badge(f"Detector: {alert['detector']}", "#38BDF8")
                             + theme.badge(f"RF score: {theme.fmt_score(alert['rf_score'])}", "#818CF8"))
            theme.kv([
                ("First / last seen", f"{theme.fmt_ts(alert['first_seen'])} → {theme.fmt_ts(alert['last_seen'])}"),
                ("Source", f"{theme.fmt_ip(alert['src_ip'])} : {alert['src_port'] if alert['src_port'] is not None else '-'}"),
                ("Destination", f"{theme.fmt_ip(alert['dst_ip'])} : {alert['dst_port'] if alert['dst_port'] is not None else '-'}"),
                ("Host IP", theme.fmt_ip(alert["host_ip"])),
                ("Protocol", "not recorded" if alert["protocol"] is None else str(alert["protocol"])),
                ("Hostname / user", f"{alert['hostname'] or '-'} / {alert['user'] or '-'}"),
                ("IDS source / signature", f"{alert['ids_source'] or '-'} / {alert['signature'] or '-'}"),
                ("Network", alert["network"]),
                ("Producer", alert["producer"]),
            ])
    with c2:
        with st.container(border=True):
            st.markdown("**Rule hits**")
            theme.html_block("".join(theme.chip(r) for r in alert["rule_hits"])
                             or "<span class='sx-muted'>none recorded</span>")
            st.markdown("**Evidence references**")
            theme.html_block("".join(theme.ref_chip(e) for e in alert["evidence"]))
            st.markdown("**Part of incident(s)**")
            if alert["incident_ids"]:
                for inc in alert["incident_ids"]:
                    if st.button(f"Open {inc}", key=f"al-open-{inc}"):
                        nav.go("incidents", incident_id=inc)
            else:
                st.caption("Not linked to any incident (latest versions).")
