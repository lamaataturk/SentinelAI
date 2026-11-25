"""SentinelAI analyst dashboard (Streamlit).

    python -m streamlit run sentinelai/dashboard/app.py

The dashboard only talks to the FastAPI backend (SENTINELAI_API_URL,
default http://127.0.0.1:8000). Start the API first.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:  # `streamlit run` puts only this folder on sys.path
    sys.path.insert(0, str(ROOT))

import streamlit as st  # noqa: E402

from sentinelai.dashboard import nav, theme  # noqa: E402
from sentinelai.dashboard.client import ApiClient, ApiError  # noqa: E402
from sentinelai.dashboard.views import (alerts, frameworks, incidents, overview, reports,  # noqa: E402
                                        reviews)
from sentinelai.platform.config import Settings  # noqa: E402

st.set_page_config(page_title="SentinelAI · SOC Dashboard", page_icon="🛡️", layout="wide",
                   initial_sidebar_state="expanded")
theme.apply()

if "api_client" not in st.session_state:
    st.session_state["api_client"] = ApiClient(Settings.from_env().api_url)
api = st.session_state["api_client"]

pages = {
    "overview": st.Page(overview.render, title="Overview", icon="📊", default=True),
    "alerts": st.Page(alerts.render, title="Alerts", icon="🚨", url_path="alerts"),
    "incidents": st.Page(incidents.render, title="Incident Investigation", icon="🔎", url_path="incidents"),
    "frameworks": st.Page(frameworks.render, title="ATT&CK & Kill Chain", icon="🧭", url_path="frameworks"),
    "reports": st.Page(reports.render, title="Incident Reports", icon="📄", url_path="reports"),
    "reviews": st.Page(reviews.render, title="Human Review", icon="✅", url_path="reviews"),
}
nav.PAGES.update(pages)

st.logo(str(Path(__file__).with_name("assets") / "logo.svg"), size="large")

navigation = st.navigation(list(pages.values()), position="sidebar")

with st.sidebar:
    try:
        health = api.get("/api/health")
        source = health["data_source"]
        source_label = {"fixtures": "Demo fixtures (synthetic)", "agents": "Agent output",
                        "uninitialised": "Not initialised"}.get(source, source)
        theme.html_block(
            theme.badge("API online", "#22C55E")
            + theme.badge(f"Mode: {health['mode']}", "#38BDF8")
            + "<br>" + theme.badge(source_label, "#FBBF24" if source == "fixtures" else "#94A3B8")
        )
    except ApiError:
        theme.html_block(theme.badge("API offline", "#EF4444"))
    theme.html_block(f'<div class="sx-muted" style="margin-top:.5rem">API: {theme.esc(api.base_url)}<br>'
                     "Advice only: approving a recommendation records a decision and executes nothing."
                     "<br>No authentication (local prototype).</div>")
    if st.button("Refresh data"):
        st.rerun()

navigation.run()
