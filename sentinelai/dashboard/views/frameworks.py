"""Page 4: MITRE ATT&CK candidate techniques and Cyber Kill Chain stage hypotheses."""
from __future__ import annotations

import streamlit as st

from sentinelai.dashboard import theme
from sentinelai.dashboard.views.common import fetch, incident_picker, system

LEGEND = (
    "<div class='sx-card' style='height:auto'>"
    "<b>How to read this page</b>"
    "<div class='sx-kv' style='margin-top:.5rem'>"
    "<dt>Observation</dt><dd>What a detector recorded: an alert, flow, rule hit or log line (evidence chips).</dd>"
    "<dt>Hypothesis</dt><dd>What the Investigation Agent infers from those observations: a <i>possible</i> "
    "ATT&amp;CK technique or Kill Chain stage, with strong or weak support.</dd>"
    "<dt>Confirmed</dt><dd>Nothing on this page is confirmed. Only an analyst can confirm a finding after "
    "reviewing the evidence.</dd></div></div>"
)


def _kill_chain(stages: list[dict]) -> str:
    cells = []
    for s in stages:
        color = theme.SUPPORT_COLORS.get(s["support"], "#1E293B")
        filled = s["support"] in ("strong", "weak")
        background = f"{color}22" if filled else "rgba(17,26,46,.6)"
        border = f"{color}" if filled else "#22314F"
        label = {"strong": "Possible · strong support", "weak": "Possible · weak support",
                 "unmapped": "Unmapped", "no_hypothesis": "No hypothesis"}[s["support"]]
        cells.append(
            f"<div class='sx-kc-stage' style='background:{background};border-color:{border}'>"
            f"<div class='sx-kc-order'>Stage {theme.esc(s['order'] or '')}</div>"
            f"<div class='sx-kc-name'>{theme.esc(s['name'])}</div>"
            f"<div style='color:{color if filled else '#64748B'};font-size:.74rem;font-weight:600'>"
            f"{theme.esc(label)}</div>"
            f"<div class='sx-muted' style='font-size:.7rem;margin-top:.25rem'>"
            f"{len(s['evidence'])} evidence ref(s)</div></div>"
        )
    return f"<div class='sx-kc'>{''.join(cells)}</div>"


def render() -> None:
    sys_info = system()
    theme.header("MITRE ATT&CK & Cyber Kill Chain",
                 "Possible techniques and attack stages, with the evidence behind each one.")
    theme.demo_banner(sys_info)

    incidents = fetch("/api/incidents")["items"]
    if not incidents:
        theme.empty("No incidents stored yet.")
        return
    incident_id = incident_picker(incidents)
    fw = fetch(f"/api/incidents/{incident_id}/frameworks")
    theme.html_block(LEGEND)

    theme.section(f"Cyber Kill Chain · {incident_id} v{fw['version']}")
    theme.html_block(_kill_chain(fw["kill_chain"]))
    missing = [s["name"] for s in fw["kill_chain"] if s["support"] in ("no_hypothesis", "unmapped")]
    if missing:
        st.caption("Stages without a supported hypothesis: " + ", ".join(missing)
                   + ". No hypothesis means no evidence was mapped to the stage. It does not show the stage "
                     "did not happen.")
    with st.expander("Evidence for each stage"):
        for s in fw["kill_chain"]:
            if not s["evidence"]:
                continue
            theme.html_block(f"<b>{theme.esc(s['name'])}</b> {theme.support_badge(s['support'])}<br>"
                             + "".join(theme.ref_chip(e) for e in s["evidence"]))

    theme.section("Candidate ATT&CK techniques")
    if not fw["techniques"]:
        theme.empty("The Investigation Agent recorded no candidate technique for this incident.")
    strong = [t for t in fw["techniques"] if t["support"] == "strong"]
    weak = [t for t in fw["techniques"] if t["support"] != "strong"]
    for group, title in ((strong, "Strong support"), (weak, "Weak support or unmapped")):
        if not group:
            continue
        st.markdown(f"**{title}**")
        cols = st.columns(2)
        for n, t in enumerate(group):
            with cols[n % 2]:
                with st.container(border=True):
                    link = (f" <a href='{theme.esc(t['reference_url'])}' target='_blank' "
                            f"style='font-size:.75rem'>ATT&amp;CK page ↗</a>" if t.get("reference_url") else "")
                    stages = ", ".join(s.replace("_", " ").title() for s in t["possible_stages"]) or "none listed"
                    theme.html_block(
                        f"<div class='sx-rec-action'>Possible {theme.esc(t['technique_id'])} · "
                        f"{theme.esc(t['name'])}{link}</div>"
                        + theme.support_badge(t["support"])
                        + "".join(theme.badge(f"Tactic: {x}", "#818CF8") for x in t["tactics"])
                        + f"<div class='sx-muted' style='margin:.3rem 0'>Kill Chain stages this technique may "
                          f"point to (O-1 knowledge base): {theme.esc(stages)}</div>"
                        + "".join(theme.ref_chip(e) for e in t["evidence"])
                        + ("" if t["in_knowledge_base"] else
                           "<div class='sx-muted'>Not in the O-1 knowledge base.</div>")
                    )
    st.caption(fw["note"])

    theme.section("Evidence status legend")
    theme.html_block("".join(theme.badge(label, color) for color, label in theme.REF_STATUS.values()))
