"""Page 1: overview of everything stored in shared memory."""
from __future__ import annotations

import altair as alt
import pandas as pd
import streamlit as st

from sentinelai.dashboard import nav, theme
from sentinelai.dashboard.views.common import fetch, system


def _severity_chart(distribution: dict) -> alt.Chart:
    rows = [{"severity": s, "incidents": distribution.get(s, 0)} for s in theme.SEVERITY_ORDER]
    return alt.Chart(pd.DataFrame(rows)).mark_bar(cornerRadiusEnd=4).encode(
        x=alt.X("incidents:Q", title="Incidents (latest version)", axis=alt.Axis(tickMinStep=1)),
        y=alt.Y("severity:N", sort=theme.SEVERITY_ORDER, title=None),
        color=alt.Color("severity:N", legend=None,
                        scale=alt.Scale(domain=theme.SEVERITY_ORDER,
                                        range=[theme.SEVERITY_COLORS[s] for s in theme.SEVERITY_ORDER])),
        tooltip=["severity", "incidents"],
    ).properties(height=210, width="container")


def _activity_chart(activity: dict) -> alt.Chart:
    df = pd.DataFrame(activity["items"])
    minutes = activity["bucket_minutes"]
    fmt = "%H:%M" if minutes < 1440 else "%Y-%m-%d"
    df["label"] = pd.to_datetime(df["start"]).dt.strftime(fmt if len(df) < 2 or
                                                         df["start"].str[:10].nunique() == 1 else "%m-%d " + fmt)
    unit = f"{minutes} min" if minutes < 60 else (f"{minutes // 60} h" if minutes < 1440 else f"{minutes // 1440} day")
    return alt.Chart(df).mark_bar(color="#38BDF8", cornerRadiusTopLeft=3, cornerRadiusTopRight=3).encode(
        x=alt.X("label:O", sort=list(df["label"]), title=f"Time (UTC), {unit} buckets by alert first_seen",
                axis=alt.Axis(labelAngle=0, labelOverlap=True)),
        y=alt.Y("alerts:Q", title="Alerts", axis=alt.Axis(tickMinStep=1)),
        tooltip=[alt.Tooltip("start:N", title="bucket start"), "alerts"],
    ).properties(height=210, width="container")


def _detector_chart(distribution: dict) -> alt.Chart:
    df = pd.DataFrame([{"detector": k, "alerts": v} for k, v in distribution.items()])
    return alt.Chart(df).mark_arc(innerRadius=55, stroke="#0B1220", strokeWidth=2).encode(
        theta="alerts:Q",
        color=alt.Color("detector:N", scale=alt.Scale(range=theme.CHART_COLORS),
                        legend=alt.Legend(title="Detection method", orient="right")),
        tooltip=["detector", "alerts"],
    ).properties(height=210, width="container")


def _stage_chart(stage_support: dict) -> alt.Chart:
    rows = []
    for stage, counts in stage_support.items():
        for support in ("strong", "weak", "unmapped"):
            rows.append({"stage": stage.replace("_", " ").title(), "support": support,
                         "incidents": counts.get(support, 0)})
    order = [s.replace("_", " ").title() for s in stage_support]
    return alt.Chart(pd.DataFrame(rows)).mark_bar().encode(
        y=alt.Y("stage:N", sort=order, title=None, axis=alt.Axis(labelOverlap=False, labelLimit=220)),
        x=alt.X("incidents:Q", title="Incidents with this stage hypothesis", axis=alt.Axis(tickMinStep=1)),
        color=alt.Color("support:N", scale=alt.Scale(domain=["strong", "weak", "unmapped"],
                                                     range=[theme.SUPPORT_COLORS[k] for k in
                                                            ("strong", "weak", "unmapped")]),
                        legend=alt.Legend(title="Support", orient="bottom")),
        tooltip=["stage", "support", "incidents"],
    ).properties(height=280, width="container")


def render() -> None:
    sys_info = system()
    theme.header("Security Operations Overview",
                 "Everything below is counted from the messages in shared memory at the time of loading.")
    theme.demo_banner(sys_info)
    for warning in sys_info.get("warnings", []):
        theme.banner(warning, "info")

    stats = fetch("/api/stats")
    validation = fetch("/api/validation")

    cols = st.columns(5)
    with cols[0]:
        theme.metric("Alerts", stats["total_alerts"], "stored Alert messages", "#38BDF8")
    with cols[1]:
        theme.metric("Incidents", stats["total_incidents"],
                     f"{stats['incident_versions']} versions in total", "#818CF8")
    with cols[2]:
        theme.metric("High / Critical", stats["high_or_critical_incidents"],
                     "current assessments", theme.SEVERITY_COLORS["High"])
    with cols[3]:
        theme.metric("Pending reviews", stats["recommendations_pending"],
                     f"{stats['recommendations_approved']} approved · {stats['recommendations_rejected']} rejected",
                     "#FBBF24")
    with cols[4]:
        theme.metric("Reports", stats["reports_generated"],
                     f"of {stats['report_requests']} report request(s)", "#34D399")

    if stats["total_alerts"] == 0 and stats["total_incidents"] == 0:
        st.write("")
        theme.empty("Shared memory is empty. For the demo run: python scripts/init_demo.py")
        return

    left, right = st.columns([1, 1])
    with left:
        theme.section("Severity distribution")
        st.altair_chart(_severity_chart(stats["severity_distribution"]))
    with right:
        theme.section("Alert activity over time")
        if stats["alert_activity"]["items"]:
            st.altair_chart(_activity_chart(stats["alert_activity"]))
        else:
            theme.empty("No alerts stored.")

    left, right = st.columns([1, 1])
    with left:
        theme.section("Detection method")
        if stats["detector_distribution"]:
            st.altair_chart(_detector_chart(stats["detector_distribution"]))
        else:
            theme.empty("No alerts stored.")
    with right:
        theme.section("Kill Chain stage hypotheses (latest incident versions)")
        st.altair_chart(_stage_chart(stats["stage_support"]))
        st.caption("Hypotheses from the Investigation Agent, not confirmed stages.")

    theme.section("Incidents")
    incidents = fetch("/api/incidents")["items"]
    if not incidents:
        theme.empty("No incidents stored yet.")
    for item in incidents:
        review = item["review_summary"] or {}
        c1, c2, c3 = st.columns([5, 3, 1.3])
        with c1:
            theme.html_block(
                f"<b>{theme.esc(item['incident_id'])}</b> "
                f"<span class='sx-muted'>v{item['version']} · {theme.esc(theme.fmt_ts(item['start_time']))} → "
                f"{theme.esc(theme.fmt_ts(item['end_time']))}</span><br>"
                + theme.severity_badge(item["severity"])
                + theme.badge(f"Confidence: {item['confidence']}", "#94A3B8")
                + theme.badge(f"{item['alert_count']} alert(s)", "#818CF8")
            )
        with c2:
            techniques = "".join(theme.chip(t) for t in item["technique_ids"]) or \
                "<span class='sx-muted'>no candidate technique</span>"
            theme.html_block(techniques + "<br><span class='sx-muted'>Review: "
                             f"{theme.esc(review.get('status', 'not assessed')).replace('_', ' ')}</span>")
        with c3:
            if st.button("Investigate", key=f"ov-inv-{item['incident_id']}"):
                nav.go("incidents", incident_id=item["incident_id"])

    theme.section("System status")
    c1, c2 = st.columns(2)
    with c1:
        theme.kv([
            ("Mode", sys_info["mode"]),
            ("Data source", sys_info["data_source"]),
            ("Database", f"{sys_info['database']} ({sys_info['messages_stored']} messages)"),
            ("Initialised", theme.fmt_ts(sys_info.get("initialised_at")) or "-"),
            ("Authentication", sys_info["authentication"]),
        ])
    with c2:
        theme.kv([
            ("Evidence validation", theme.badge("passed", "#22C55E") if validation["valid"]
             else theme.badge(f"{len(validation['errors'])} problem(s)", "#EF4444")),
            ("Messages checked", theme.esc(validation["messages_checked"])),
            ("Flow references", theme.esc("checked against " + str(validation["flow_ids_available"]) + " flow IDs"
                                          if validation["flow_references_checked"] else "not checked")),
            ("Rule definitions", "not independently verified"),
            ("Automatic actions", "none: recommendations are advice only"),
        ], raw=True)
