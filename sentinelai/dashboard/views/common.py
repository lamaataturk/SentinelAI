"""Helpers shared by every page."""
from __future__ import annotations

import streamlit as st

from sentinelai.dashboard import theme
from sentinelai.dashboard.client import ApiClient, ApiError


def client() -> ApiClient:
    return st.session_state["api_client"]


def fetch(path: str, **params):
    """GET from the API; on failure show a clear message and stop this page."""
    try:
        return client().get(path, **params)
    except ApiError as exc:
        if exc.status is None:
            theme.banner(f"Backend not reachable. {exc.detail} Start it with: python -m sentinelai.platform.api",
                         "error")
        elif exc.status == 404:
            theme.banner(f"Not found: {exc.detail}", "error")
        else:
            theme.banner(f"API error {exc.status}: {exc.detail}", "error")
        st.stop()


def system() -> dict:
    return fetch("/api/system")


def incident_picker(incidents: list[dict], key: str = "incident_id", label: str = "Incident") -> str | None:
    if not incidents:
        return None
    ids = [i["incident_id"] for i in incidents]
    labels = {i["incident_id"]: f"{i['incident_id']} · {i['severity'] or 'Unassessed'} · "
                                f"{i['alert_count']} alert(s) · v{i['version']}" for i in incidents}
    if st.session_state.get(key) not in ids:
        st.session_state[key] = ids[0]
    return st.selectbox(label, ids, key=key, format_func=labels.get)
