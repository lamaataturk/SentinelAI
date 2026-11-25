"""Page 6: human review of Response Agent recommendations (approve / reject, persisted)."""
from __future__ import annotations

import pandas as pd
import streamlit as st

from sentinelai.dashboard import theme
from sentinelai.dashboard.client import ApiError
from sentinelai.dashboard.views.common import client, fetch, system


def _submit(assessment: dict, rec: dict, decision: str, comment: str, analyst: str) -> None:
    payload = {
        "assessment_id": assessment["message_id"],
        "recommendation_index": rec["index"],
        "incident_version": assessment["incident_version"],
        "decision": decision,
        "comment": comment,
        "analyst": analyst,
    }
    try:
        status, review = client().post("/api/reviews", payload)
    except ApiError as exc:
        st.session_state["rv-flash"] = ("error", f"Decision not recorded: {exc.detail}")
        return
    if status == 201:
        msg = (f"Recorded: {decision} for {review['recommendation_ref']} at {theme.fmt_ts(review['reviewed_at'])}. "
               "No action was executed.")
    else:
        msg = f"This decision was already recorded for {review['recommendation_ref']}; nothing changed."
    st.session_state["rv-flash"] = ("success", msg)


def _recommendation(assessment: dict, rec: dict, analyst: str) -> None:
    key = f"{assessment['message_id']}-{rec['index']}"
    with st.container(border=True):
        c1, c2 = st.columns([4, 1.4])
        with c1:
            theme.html_block(
                f"<div class='sx-rec-action'>{rec['index'] + 1}. {theme.esc(rec['action'])}</div>"
                f"<div class='sx-rec-reason'>Justification: {theme.esc(rec['reason'])}</div>"
                + (theme.chip(rec["technique_id"]) if rec.get("technique_id") else "")
                + theme.chip(rec["recommendation_ref"])
            )
        with c2:
            theme.html_block(theme.decision_badge(rec["review_decision"])
                             + theme.badge("Needs human approval", "#94A3B8"))
            if rec["review"]:
                r = rec["review"]
                theme.html_block(f"<div class='sx-muted'>{theme.esc(theme.fmt_ts(r['reviewed_at']))}"
                                 f"{' · ' + theme.esc(r['analyst']) if r['analyst'] else ''}</div>")
        with st.form(f"rv-form-{key}", clear_on_submit=True, border=False):
            comment = st.text_area("Analyst comment (optional)", key=f"rv-comment-{key}", height=70,
                                   max_chars=2000, placeholder="Why you approve or reject this advice")
            b1, b2, _ = st.columns([1, 1, 4])
            approve = b1.form_submit_button("Approve", type="primary")
            reject = b2.form_submit_button("Reject")
        if approve or reject:
            _submit(assessment, rec, "approved" if approve else "rejected", comment, analyst)
            st.rerun()


def render() -> None:
    sys_info = system()
    theme.header("Human Review",
                 "Approve or reject each defensive recommendation. A decision is only recorded; "
                 "SentinelAI never carries out an action.")
    theme.demo_banner(sys_info)
    if flash := st.session_state.pop("rv-flash", None):
        (st.success if flash[0] == "success" else st.error)(flash[1])

    c1, c2 = st.columns([2, 3])
    with c1:
        analyst = st.text_input("Analyst name (self-reported, not authenticated)", key="rv-analyst",
                                max_chars=100)
    assessments = [a for a in fetch("/api/assessments", current_only="true")["items"] if a["recommendations"]]
    if not assessments:
        theme.empty("No current assessment has recommendations to review.")
    else:
        order = {s: i for i, s in enumerate(theme.SEVERITY_ORDER)}
        assessments.sort(key=lambda a: (order.get(a["severity"], 9), a["incident_id"]))
        ids = [a["message_id"] for a in assessments]
        if st.session_state.get("review_assessment") not in ids:
            st.session_state["review_assessment"] = ids[0]
        with c2:
            pick = st.selectbox(
                "Assessment", ids, key="review_assessment",
                format_func=lambda i: next(f"{a['incident_id']} · {a['severity']} · {i} · "
                                           f"{a['review_summary']['pending']} pending"
                                           for a in assessments if a["message_id"] == i))
        a = next(x for x in assessments if x["message_id"] == pick)

        with st.container(border=True):
            rs = a["review_summary"]
            theme.html_block(
                f"<b>{theme.esc(a['incident_id'])}</b> <span class='sx-muted'>· incident version "
                f"{a['incident_version']} (latest) · assessment {theme.esc(a['message_id'])}</span><br>"
                + theme.severity_badge(a["severity"])
                + theme.badge(f"Policy: {a['policy_rule_id']}", "#38BDF8")
                + theme.badge(f"{rs['pending']} pending · {rs['approved']} approved · {rs['rejected']} rejected",
                              "#FBBF24")
            )
            theme.html_block("<div class='sx-muted' style='margin-top:.35rem'>Severity reasons: "
                             + theme.esc(" · ".join(a["severity_reasons"])) + "</div>"
                             + "<div style='margin-top:.35rem'>"
                             + "".join(theme.chip(r) for r in a["evidence_refs"]) + "</div>")
            st.caption(f"Stored review_status in the Assessment message: '{a['stored_review_status']}' "
                       "(agent messages are never changed; current decisions come from the review log).")

        for rec in a["recommendations"]:
            _recommendation(a, rec, analyst)

    theme.section("Decision history (audit log)")
    history = fetch("/api/reviews")["items"]
    if not history:
        theme.empty("No decisions recorded yet.")
        return
    st.dataframe(pd.DataFrame([{
        "Reviewed at (UTC)": theme.fmt_ts(r["reviewed_at"]),
        "Decision": r["decision"],
        "Recommendation": r["recommendation_ref"],
        "Action": r["recommendation_action"],
        "Incident": f"{r['incident_id']} v{r['incident_version']}",
        "Applies to latest version": "yes" if r["applies_to_latest_version"] else "no (outdated)",
        "Analyst": r["analyst"] or "-",
        "Comment": r["comment"] or "-",
        "Replaces": r["supersedes"] or "-",
        "Review ID": r["review_id"],
    } for r in reversed(history)]), hide_index=True)
