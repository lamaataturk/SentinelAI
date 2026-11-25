"""L-6.6: end-to-end checks across shared memory, agents, API and dashboard.

* The orchestrator drives the real Response Agent (Omar) and Reporting Agent (L-4)
  on fixture incidents; the API then serves that agent output in live mode.
* The Streamlit dashboard is run with Streamlit's AppTest against a real API
  server (uvicorn on a free local port), so it goes through HTTP like in use.
"""
import json
import socket
import threading
import time
from pathlib import Path

import pytest
import requests
import uvicorn
from fastapi.testclient import TestClient
from streamlit.testing.v1 import AppTest

from sentinelai.platform.api import create_app
from sentinelai.platform.config import Settings, load_flow_ids
from sentinelai.platform.metadata import set_meta
from sentinelai.platform.orchestrator import Orchestrator
from sentinelai.platform.shared_memory import SharedMemory
from sentinelai.reporting.reporting_agent import ReportingAgent
from sentinelai.response.response_agent import ResponseAgent

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "fixtures"


class PassThroughInvestigation:
    """Stand-in: the Investigation Agent has no run(message, memory) adapter yet,
    so the fixture IncidentUpdates are written directly."""

    def run(self, message, memory):
        return None


def test_orchestrated_agent_output_is_served_by_the_api(tmp_path):
    db, reports = tmp_path / "live.db", tmp_path / "reports"
    memory = SharedMemory(str(db))
    for name in ("alerts.json", "incident_updates.json"):
        for message in json.loads((FIX / name).read_text(encoding="utf-8")):
            memory.write(message)
    set_meta(db, "data_source", "agents")
    flows = load_flow_ids(FIX / "features_sample.csv")

    orchestrator = Orchestrator(memory, PassThroughInvestigation(), ResponseAgent(),
                                ReportingAgent(reports, flow_ids=flows))
    result = orchestrator.run_once()
    assert result["incidents_processed"] == 5
    assessments = memory.read("Assessment")
    assert len(assessments) == 4 and all(a["producer"] == "response_agent" for a in assessments)

    settings = Settings.for_mode("live", db_path=db, reports_dir=reports, flows_csv=FIX / "features_sample.csv")
    api = TestClient(create_app(settings))
    assert api.get("/api/system").json()["is_demo_data"] is False

    inc = api.get("/api/incidents/inc-0001").json()
    current = inc["current_assessment"]
    assert current["producer"] == "response_agent" and current["incident_version"] == 2
    assert current["severity"] in ("Low", "Medium", "High", "Critical")

    reports_list = api.get("/api/reports").json()["items"]
    assert len(reports_list) == 4 and all(r["generated"] and not r["is_demo_data"] for r in reports_list)
    one = reports_list[0]["request_id"]
    assert api.get(f"/api/reports/{one}/download").status_code == 200

    stats = api.get("/api/stats").json()
    assert stats["total_incidents"] == 4 and sum(stats["severity_distribution"].values()) == 4
    assert api.get("/api/validation").json()["valid"] is True

    with_recs = [a for a in assessments if a["recommendations"]]
    if with_recs:
        a = with_recs[0]
        r = api.post("/api/reviews", json={"assessment_id": a["message_id"], "recommendation_index": 0,
                                           "incident_version": a["incident_version"], "decision": "rejected"})
        assert r.status_code == 201
        # restart the API on the same files: the decision is still there
        restarted = TestClient(create_app(settings))
        rec = restarted.get(f"/api/assessments/{a['message_id']}").json()["recommendations"][0]
        assert rec["review_decision"] == "rejected"
        assert memory.get(a["message_id"])["review_status"] == "pending"  # agent message unchanged


# ---------------------------------------------------------------- dashboard + live API
def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def live_api(demo_settings, monkeypatch):
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(create_app(demo_settings), host="127.0.0.1", port=port,
                                           log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    url = f"http://127.0.0.1:{port}"
    monkeypatch.setenv("SENTINELAI_API_URL", url)
    yield url
    server.should_exit = True
    thread.join(timeout=5)


def _page_script(page: str, url: str):
    import streamlit as st

    from sentinelai.dashboard import theme
    from sentinelai.dashboard.client import ApiClient
    from sentinelai.dashboard.views import alerts, frameworks, incidents, overview, reports, reviews

    theme.apply()
    st.session_state["api_client"] = ApiClient(url)
    {"overview": overview, "alerts": alerts, "incidents": incidents, "frameworks": frameworks,
     "reports": reports, "reviews": reviews}[page].render()


def _page(page, url) -> AppTest:
    at = AppTest.from_function(_page_script, args=(page, url), default_timeout=30)
    at.run()
    assert not at.exception, [e.value for e in at.exception]
    return at


def _text(at) -> str:
    return " ".join(m.value for m in at.markdown) + " ".join(c.value for c in at.caption)


def test_full_app_starts_on_the_overview(live_api):
    at = AppTest.from_file(str(ROOT / "sentinelai" / "dashboard" / "app.py"), default_timeout=30)
    at.run()
    assert not at.exception, [e.value for e in at.exception]
    text = _text(at)
    assert "Security Operations Overview" in text and "DEMONSTRATION DATA" in text
    assert "API online" in text


@pytest.mark.parametrize("page, expected", [
    ("overview", ["Security Operations Overview", "DEMONSTRATION DATA", ">11<", "inc-0001"]),
    ("alerts", ["Alerts", "11 alert(s) match", "not a calibrated probability"]),
    ("incidents", ["Incident Investigation", "inc-0001", "Severity: High", "Possible incident, not confirmed"]),
    ("frameworks", ["Cyber Kill Chain", "Possible T1595", "Nothing on this page is confirmed"]),
    ("reports", ["Incident Reports", "# SentinelAI Incident Report", "Evidence validation"]),
    ("reviews", ["Human Review", "assess-0001#rec-0", "No decisions recorded yet"]),
])
def test_every_page_renders_from_api_data(live_api, page, expected):
    text = _text(_page(page, live_api))
    for snippet in expected:
        assert snippet in text, f"{page}: {snippet!r} missing"


def test_alert_search_filters_through_the_api(live_api):
    at = _page("alerts", live_api)
    at.text_input(key="al-ip").input("10.0.1.53").run()
    assert "2 alert(s) match" in _text(at)


def test_approve_in_the_dashboard_is_persisted(live_api):
    at = _page("reviews", live_api)
    at.text_input(key="rv-analyst").input("Lama").run()
    approve = next(b for b in at.button if b.label == "Approve")
    approve.click().run()
    assert not at.exception
    assert any("No action was executed" in s.value for s in at.success)

    items = requests.get(f"{live_api}/api/reviews", timeout=5).json()["items"]
    assert len(items) == 1 and items[0]["decision"] == "approved" and items[0]["analyst"] == "Lama"
    # a fresh dashboard session (browser refresh) shows the stored decision
    assert "Approved" in _text(_page("reviews", live_api))


def test_dashboard_shows_a_clear_error_when_the_api_is_down():
    at = AppTest.from_function(_page_script, args=("overview", "http://127.0.0.1:9"), default_timeout=30)
    at.run()
    assert not at.exception
    assert "Backend not reachable" in _text(at)
