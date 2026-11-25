"""Page 3: incident investigation (timeline, alerts, assessment, evidence, uncertainty)."""
from __future__ import annotations

import altair as alt
import pandas as pd
import streamlit as st

from sentinelai.dashboard import nav, theme
from sentinelai.dashboard.views.common import fetch, incident_picker, system


def _timeline_chart(events: list[dict]) -> alt.Chart:
    df = pd.DataFrame([{
        "time": e["time"], "end": e["last_seen"], "alert": e["alert_id"], "detector": e["detector"],
        "summary": e["summary"], "rf_score": theme.fmt_score(e["rf_score"]),
    } for e in events])
    df["time"] = pd.to_datetime(df["time"])
    df["end"] = pd.to_datetime(df["end"])
    return alt.Chart(df).mark_circle(size=150, opacity=1).encode(
        x=alt.X("time:T", title="Time (UTC), alert first seen"),
        y=alt.Y("alert:N", sort=list(df["alert"]), title=None, axis=alt.Axis(labelOverlap=False)),
        color=alt.Color("detector:N", scale=alt.Scale(range=theme.CHART_COLORS),
                        legend=alt.Legend(title="Detector", orient="bottom")),
        tooltip=[alt.Tooltip("alert:N"), alt.Tooltip("time:T", format="%H:%M:%S", title="first seen"),
                 alt.Tooltip("end:T", format="%H:%M:%S", title="last seen"), "detector", "rf_score", "summary"],
    ).properties(height=34 * len(df) + 110, width="container")  # includes axis + legend


def _timeline_list(events: list[dict]) -> str:
    items = []
    for e in events:
        links = "".join(
            theme.badge(f"linked to {l['linked_to']} via {l['shared_entity']} · {l['gap_seconds']}s · {l['strength']}",
                        "#38BDF8" if l["strength"] == "strong" else "#FBBF24")
            for l in e["links"]
        )
        where = " → ".join(theme.esc(theme.fmt_ip(v)) for v in (e["src_ip"], e["dst_ip"]) if v) or \
            f"host {theme.esc(theme.fmt_ip(e['host_ip']))}"
        items.append(
            f'<div class="sx-tl-item"><div class="sx-tl-dot"></div>'
            f'<div class="sx-tl-time">{theme.esc(theme.fmt_ts(e["time"]))} · {theme.esc(e["alert_id"])} · '
            f'{theme.esc(e["detector"])} · RF {theme.esc(theme.fmt_score(e["rf_score"]))}</div>'
            f'<div class="sx-tl-text">{theme.esc(e["summary"])} <span class="sx-muted">({where})</span></div>'
            f"<div>{links}</div></div>"
        )
    return f'<div class="sx-tl">{"".join(items)}</div>'


def render() -> None:
    sys_info = system()
    theme.header("Incident Investigation",
                 "Incidents built by the Investigation Agent and judged by the Response Agent.")
    theme.demo_banner(sys_info)

    incidents = fetch("/api/incidents")["items"]
    if not incidents:
        theme.empty("No incidents stored yet.")
        return
    c1, c2 = st.columns([3, 1])
    with c1:
        incident_id = incident_picker(incidents)
    summary = next(i for i in incidents if i["incident_id"] == incident_id)
    versions = summary["versions_available"]
    with c2:
        version = st.selectbox("Version", list(reversed(versions)), key=f"ver-{incident_id}",
                               format_func=lambda v: f"v{v} (latest)" if v == versions[-1] else f"v{v}")
    inc = fetch(f"/api/incidents/{incident_id}", version=version)
    timeline = fetch(f"/api/incidents/{incident_id}/timeline", version=version)
    current = inc["current_assessment"]

    if not inc["is_latest_version"]:
        theme.banner(f"You are viewing version {version}. The latest version is {inc['latest_version']}; "
                     "severity and recommendations below belong to the latest version.", "info")

    with st.container(border=True):
        theme.html_block(
            f"<span style='font-size:1.3rem;font-weight:700'>{theme.esc(inc['incident_id'])}</span> "
            f"<span class='sx-muted'>version {inc['version']} · {theme.esc(inc['status'])} · "
            f"network {theme.esc(inc['network'])}</span><br>"
            + theme.severity_badge(current["severity"] if current else None)
            + theme.badge(f"Confidence: {inc['confidence']}", "#94A3B8")
            + theme.badge("Possible incident, not confirmed", "#FBBF24")
        )
        st.write("")
        cols = st.columns(4)
        with cols[0]:
            theme.metric("Alerts", len(inc["alert_ids"]), f"{len(inc['missing_alerts'])} missing", "#818CF8")
        with cols[1]:
            theme.metric("Start (UTC)", theme.fmt_ts(inc["start_time"])[11:19] or "-",
                         theme.fmt_ts(inc["start_time"])[:10], "#38BDF8")
        with cols[2]:
            theme.metric("End (UTC)", theme.fmt_ts(inc["end_time"])[11:19] or "-",
                         theme.fmt_ts(inc["end_time"])[:10], "#38BDF8")
        with cols[3]:
            weak = sum(1 for l in inc["link_reasons"] if l["strength"] == "weak")
            theme.metric("Alert links", len(inc["link_reasons"]), f"{weak} weak", "#FBBF24")
        st.write("")
        ents = inc["entities"]
        theme.html_block("<span class='sx-muted'>IPs </span>" + "".join(theme.chip(i) for i in ents.get("ips", []))
                         + "<span class='sx-muted'> Hosts </span>" + "".join(theme.chip(h) for h in ents.get("hosts", []))
                         + ("<span class='sx-muted'> Users </span>" + "".join(theme.chip(u) for u in ents["users"])
                            if ents.get("users") else ""))

    st.write("")
    step = st.radio("Investigation step", ["1 · Timeline", "2 · Related alerts", "3 · Assessment",
                                           "4 · Evidence & uncertainty"], horizontal=True, key="inc-step",
                    label_visibility="collapsed")

    if step.startswith("1"):
        theme.section("Chronological timeline")
        if timeline["events"]:
            st.altair_chart(_timeline_chart(timeline["events"]))
            theme.html_block(_timeline_list(timeline["events"]))
        else:
            theme.empty("None of this incident's alerts are stored.")

    elif step.startswith("2"):
        theme.section("Related alerts")
        alerts = fetch(f"/api/incidents/{incident_id}/alerts", version=version)["items"]
        if alerts:
            st.dataframe(pd.DataFrame([{
                "Alert": a["message_id"], "First seen": theme.fmt_ts(a["first_seen"]), "Detector": a["detector"],
                "RF score": theme.fmt_score(a["rf_score"]), "Rules": ", ".join(a["rule_hits"]) or "none",
                "Source": theme.fmt_ip(a["src_ip"]), "Destination": theme.fmt_ip(a["dst_ip"]),
                "Host IP": theme.fmt_ip(a["host_ip"]), "Summary": a["summary"],
            } for a in alerts]), hide_index=True)
            pick = st.selectbox("Open alert details", [a["message_id"] for a in alerts], key="inc-alert-pick")
            if st.button("Open in Alerts page"):
                nav.go("alerts", alert_id=pick, **{"al-q": "", "al-det": "All", "al-ip": "", "al-score-mode": "Any"})
        if inc["missing_alerts"]:
            theme.banner("Referenced alerts not found in shared memory: " + ", ".join(inc["missing_alerts"]), "error")

    elif step.startswith("3"):
        theme.section("Severity assessment (Response Agent)")
        if current is None:
            theme.empty("No assessment exists for the latest version of this incident.")
        else:
            c1, c2 = st.columns([3, 2])
            with c1:
                with st.container(border=True):
                    theme.html_block(theme.severity_badge(current["severity"])
                                     + theme.badge(f"Policy rule: {current['policy_rule_id']}", "#38BDF8")
                                     + theme.badge(f"Judged version: v{current['incident_version']}", "#94A3B8"))
                    st.markdown("**Why this severity**")
                    for reason in current["severity_reasons"]:
                        theme.html_block(f"<div class='sx-tl-text'>• {theme.esc(reason)}</div>")
                    st.markdown("**Assessment evidence**")
                    theme.html_block("".join(theme.chip(r) for r in current["evidence_refs"]))
            with c2:
                with st.container(border=True):
                    rs = current["review_summary"]
                    st.markdown("**Defensive recommendations (advice only)**")
                    theme.html_block(theme.badge(f"{rs['pending']} pending", "#FBBF24")
                                     + theme.badge(f"{rs['approved']} approved", "#22C55E")
                                     + theme.badge(f"{rs['rejected']} rejected", "#EF4444"))
                    for rec in current["recommendations"]:
                        theme.html_block(f"<div class='sx-rec'><div class='sx-rec-action'>{theme.esc(rec['action'])}"
                                         f"</div><div>{theme.decision_badge(rec['review_decision'])}</div></div>")
                    if current["recommendations"] and st.button("Review these recommendations"):
                        nav.go("reviews", review_assessment=current["message_id"])
        outdated = [a for a in inc["assessments"] if not a["is_current"]]
        if outdated:
            st.caption("Older assessments (for earlier incident versions): "
                       + ", ".join(f"{a['message_id']} (v{a['incident_version']}, {a['severity']})" for a in outdated))

    else:
        c1, c2 = st.columns(2)
        with c1:
            theme.section("Uncertainty and missing information")
            for note in inc["uncertainty"] or ["No uncertainty notes recorded by the Investigation Agent."]:
                theme.html_block(f"<div class='sx-rec'>{theme.esc(note)}</div>")
            weak = [l for l in inc["link_reasons"] if l["strength"] == "weak"]
            for l in weak:
                theme.html_block(f"<div class='sx-rec'>Weak link: {theme.esc(l['alert_id'])} → "
                                 f"{theme.esc(l['linked_to'])} ({theme.esc(l['shared_entity'])}, "
                                 f"{l['gap_seconds']} s gap)</div>")
            for a in inc["missing_alerts"]:
                theme.html_block(f"<div class='sx-rec'>Missing referenced alert: {theme.esc(a)}</div>")
            unmapped = [t["technique_id"] for t in inc["candidate_techniques"] if t["support"] == "unmapped"]
            if unmapped:
                theme.html_block(f"<div class='sx-rec'>Unmapped techniques: {theme.esc(', '.join(unmapped))}</div>")
        with c2:
            theme.section("Possible benign explanations")
            if inc["benign_explanations"]:
                for b in inc["benign_explanations"]:
                    theme.html_block(f"<div class='sx-rec'><div class='sx-rec-action'>{theme.esc(b['technique_id'])}"
                                     f"</div><div class='sx-rec-reason'>{theme.esc(b['text'])}</div>"
                                     f"<div class='sx-muted'>Source: {theme.esc(b['source'])}</div></div>")
            else:
                theme.empty("The knowledge base lists no benign explanation for this incident's techniques.")
            st.caption("These are documented alternative explanations from the O-1 knowledge base, not observed findings.")
        theme.section("Incident evidence references")
        theme.html_block("".join(theme.chip(r) for r in inc["evidence_refs"]))
