"""L-6.2 / L-6.5: FastAPI backend on a temporary demo database."""
import json
from pathlib import Path

import pytest

FIX = Path(__file__).resolve().parents[1] / "fixtures"


def fixture(name):
    return json.loads((FIX / name).read_text(encoding="utf-8"))


# ------------------------------------------------------------------ system
def test_health(api):
    r = api.get("/api/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "api_version": "1.0", "mode": "demo", "data_source": "fixtures"}


def test_system_status_labels_demo_data(api):
    body = api.get("/api/system").json()
    assert body["is_demo_data"] is True
    assert body["messages_stored"] == 22
    assert body["flow_evidence_loaded"] and body["flow_ids_available"] == 32
    assert body["actions_executed_automatically"] is False
    assert body["warnings"] == []


# ------------------------------------------------------------------ dashboard stats
def test_stats_match_the_fixtures(api):
    s = api.get("/api/stats").json()
    alerts = fixture("alerts.json")
    assert s["total_alerts"] == len(alerts) == 11
    # inc-0001 has two versions: counted once
    assert s["total_incidents"] == 4 and s["incident_versions"] == 5
    assert s["severity_distribution"] == {"Low": 3, "Medium": 0, "High": 1, "Critical": 0, "Unassessed": 0}
    assert s["high_or_critical_incidents"] == 1
    detectors = {}
    for a in alerts:
        detectors[a["detector"]] = detectors.get(a["detector"], 0) + 1
    assert s["detector_distribution"] == detectors
    assert sum(b["alerts"] for b in s["alert_activity"]["items"]) == 11
    pending = sum(len(a["recommendations"]) for a in fixture("assessments.json"))
    assert s["recommendations_pending"] == pending == 5
    assert s["reports_generated"] == 2 and s["report_requests"] == 2


def test_stats_follow_review_decisions(api):
    api.post("/api/reviews", json={"assessment_id": "assess-0001", "recommendation_index": 0,
                                   "incident_version": 2, "decision": "approved"})
    api.post("/api/reviews", json={"assessment_id": "assess-0002", "recommendation_index": 0,
                                   "incident_version": 1, "decision": "rejected"})
    s = api.get("/api/stats").json()
    assert (s["recommendations_pending"], s["recommendations_approved"], s["recommendations_rejected"]) == (3, 1, 1)


# ------------------------------------------------------------------ alerts
def test_list_alerts(api):
    body = api.get("/api/alerts").json()
    assert body["total"] == 11 and len(body["items"]) == 11
    times = [a["first_seen"] for a in body["items"]]
    assert times == sorted(times)
    first = next(a for a in body["items"] if a["message_id"] == "alert-0001")
    assert first["incident_ids"] == ["inc-0001"]


@pytest.mark.parametrize("params, expected", [
    ({"detector": "rf"}, {a["message_id"] for a in fixture("alerts.json") if a["detector"] == "rf"}),
    ({"ip": "10.0.1.53"}, {"alert-0007", "alert-0008"}),
    ({"rule": "R-MANY-PORTS-5MIN"}, {a["message_id"] for a in fixture("alerts.json")
                                     if "R-MANY-PORTS-5MIN" in a["rule_hits"]}),
    ({"min_score": 0.9}, {a["message_id"] for a in fixture("alerts.json")
                          if a["rf_score"] is not None and a["rf_score"] >= 0.9}),
    ({"has_score": "false"}, {a["message_id"] for a in fixture("alerts.json") if a["rf_score"] is None}),
    ({"incident_id": "inc-0002"}, set(fixture("incident_updates.json")[2]["alert_ids"])),
    ({"q": "port scan"}, {a["message_id"] for a in fixture("alerts.json") if "port scan" in a["summary"].lower()}),
])
def test_filter_alerts(api, params, expected):
    body = api.get("/api/alerts", params=params).json()
    assert {a["message_id"] for a in body["items"]} == expected


def test_alert_pagination(api):
    body = api.get("/api/alerts", params={"limit": 3, "offset": 9}).json()
    assert body["total"] == 11 and len(body["items"]) == 2


def test_alert_detail_classifies_evidence(api):
    body = api.get("/api/alerts/alert-0001").json()
    status = {e["ref"]: e["status"] for e in body["evidence"]}
    assert status["flow:f-000021"] == "resolved"
    assert status["rule:R-MANY-PORTS-5MIN"] == "not_verified"


@pytest.mark.parametrize("url, code", [
    ("/api/alerts/alert-9999", 404),
    ("/api/alerts/not-an-alert", 422),
    ("/api/alerts?detector=magic", 422),
    ("/api/alerts?min_score=2", 422),
    ("/api/alerts?min_score=0.9&max_score=0.1", 422),
    ("/api/alerts?limit=0", 422),
    ("/api/alerts?incident_id=inc-9999", 404),
])
def test_alert_errors(api, url, code):
    r = api.get(url)
    assert r.status_code == code
    assert "detail" in r.json()


# ------------------------------------------------------------------ incidents
def test_incident_list_uses_latest_versions(api):
    items = api.get("/api/incidents").json()["items"]
    assert len(items) == 4
    inc1 = next(i for i in items if i["incident_id"] == "inc-0001")
    assert inc1["version"] == 2 and inc1["versions_available"] == [1, 2]
    assert inc1["severity"] == "High" and inc1["assessment_id"] == "assess-0001"
    assert items[0]["incident_id"] == "inc-0001"  # highest severity first


def test_incident_detail_latest_and_specific_version(api):
    latest = api.get("/api/incidents/inc-0001").json()
    assert latest["version"] == 2 and latest["is_latest_version"]
    assert latest["current_assessment"]["message_id"] == "assess-0001"
    assert latest["uncertainty"] and latest["missing_alerts"] == []
    v1 = api.get("/api/incidents/inc-0001", params={"version": 1}).json()
    assert v1["version"] == 1 and not v1["is_latest_version"] and v1["latest_version"] == 2


def test_incident_subresources(api):
    assert [v["version"] for v in api.get("/api/incidents/inc-0001/versions").json()["items"]] == [1, 2]
    alerts = api.get("/api/incidents/inc-0001/alerts").json()
    assert alerts["total"] == 8
    timeline = api.get("/api/incidents/inc-0001/timeline").json()
    times = [e["time"] for e in timeline["events"]]
    assert times == sorted(times) and len(times) == 8
    weak = [l for e in timeline["events"] for l in e["links"] if l["strength"] == "weak"]
    assert weak and weak[0]["alert_id"] == "alert-0007"
    assessments = api.get("/api/incidents/inc-0001/assessments").json()
    assert [a["message_id"] for a in assessments["items"]] == ["assess-0001"]


def test_frameworks_are_hypotheses_with_evidence(api):
    fw = api.get("/api/incidents/inc-0001/frameworks").json()
    assert [s["stage"] for s in fw["kill_chain"]][0] == "reconnaissance" and len(fw["kill_chain"]) == 7
    supports = {s["stage"]: s["support"] for s in fw["kill_chain"]}
    assert supports["weaponization"] == "no_hypothesis"
    t1595 = next(t for t in fw["techniques"] if t["technique_id"] == "T1595")
    assert t1595["support"] == "strong" and t1595["possible_stages"] == ["reconnaissance"]
    assert all(e["status"] == "resolved" for e in t1595["evidence"])
    assert "not confirmed" in fw["note"]


def test_benign_explanations_come_from_the_knowledge_base(api):
    inc = api.get("/api/incidents/inc-0002").json()
    assert inc["benign_explanations"]
    assert all(b["source"].startswith("O-1 knowledge base") for b in inc["benign_explanations"])


@pytest.mark.parametrize("url, code", [
    ("/api/incidents/inc-9999", 404),
    ("/api/incidents/inc-0001?version=7", 404),
    ("/api/incidents/inc-0001?version=0", 422),
    ("/api/incidents/drop table", 422),
    ("/api/incidents/inc-9999/timeline", 404),
    ("/api/incidents/inc-9999/assessments", 404),
])
def test_incident_errors(api, url, code):
    assert api.get(url).status_code == code


# ------------------------------------------------------------------ assessments
def test_assessment_detail(api):
    a = api.get("/api/assessments/assess-0001").json()
    assert a["severity"] == "High" and a["is_current"]
    assert a["stored_review_status"] == "pending"
    assert [r["recommendation_ref"] for r in a["recommendations"]][0] == "assess-0001#rec-0"
    assert all(r["requires_human_approval"] is True for r in a["recommendations"])
    assert api.get("/api/assessments/assess-9999").status_code == 404
    assert api.get("/api/assessments", params={"current_only": True}).json()["total"] == 4


# ------------------------------------------------------------------ reviews
def test_review_round_trip(api):
    body = {"assessment_id": "assess-0001", "recommendation_index": 2, "incident_version": 2,
            "decision": "approved", "comment": "ok", "analyst": "Lama"}
    r = api.post("/api/reviews", json=body)
    assert r.status_code == 201 and r.json()["created"] is True
    assert "No action was executed" in r.json()["note"]
    again = api.post("/api/reviews", json=body)
    assert again.status_code == 200 and again.json()["created"] is False
    history = api.get("/api/reviews", params={"assessment_id": "assess-0001"}).json()
    assert history["total"] == 1 and history["items"][0]["applies_to_latest_version"]
    pending = api.get("/api/reviews/pending").json()
    assert "assess-0001#rec-2" not in {p["recommendation_ref"] for p in pending["items"]}
    assessment = api.get("/api/assessments/assess-0001").json()
    assert assessment["recommendations"][2]["review_decision"] == "approved"


@pytest.mark.parametrize("change, code", [
    ({"decision": "execute"}, 422),
    ({"decision": "pending"}, 422),
    ({"assessment_id": "assess-9999"}, 404),
    ({"assessment_id": "bad id"}, 422),
    ({"recommendation_index": 4}, 404),
    ({"recommendation_index": -1}, 422),
    ({"incident_version": 1}, 409),
    ({"comment": "x" * 2001}, 422),
])
def test_invalid_reviews(api, change, code):
    body = {"assessment_id": "assess-0001", "recommendation_index": 0, "incident_version": 2,
            "decision": "approved"}
    body.update(change)
    r = api.post("/api/reviews", json=body)
    assert r.status_code == code
    assert api.get("/api/reviews").json()["total"] == 0


def test_review_requires_a_body(api):
    assert api.post("/api/reviews", json={}).status_code == 422


# ------------------------------------------------------------------ reports
def test_list_and_view_reports(api):
    reports = api.get("/api/reports").json()["items"]
    assert {r["request_id"] for r in reports} == {"repreq-0001", "repreq-0002"}
    assert all(r["generated"] and r["is_demo_data"] for r in reports)
    report = api.get("/api/reports/repreq-0001").json()
    assert report["content"].startswith("# SentinelAI Incident Report")
    assert "## 11. Evidence Validation" in report["content"]


def test_download_report(api, demo_settings):
    r = api.get("/api/reports/repreq-0001/download")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/markdown")
    assert 'attachment; filename="repreq-0001.md"' == r.headers["content-disposition"]
    assert r.content == (Path(demo_settings.reports_dir) / "repreq-0001.md").read_bytes()


@pytest.mark.parametrize("url", [
    "/api/reports/..%2F..%2Fetc%2Fpasswd",
    "/api/reports/repreq-..%2Fsecret/download",
    "/api/reports/repreq-0001.md/download",
    "/api/reports/%2Fetc%2Fpasswd/download",
    "/api/reports/repreq-9999/download",
    "/api/reports/report-0001",
])
def test_report_paths_are_safe(api, url):
    assert api.get(url).status_code in (404, 422)


def test_file_outside_report_requests_is_not_served(api, demo_settings):
    (Path(demo_settings.reports_dir) / "repreq-unlisted.md").write_text("secret", encoding="utf-8")
    assert api.get("/api/reports/repreq-unlisted/download").status_code == 404


def test_generate_report_uses_the_reporting_agent(api, demo_settings):
    r = api.post("/api/reports", json={"assessment_id": "assess-0003"})
    assert r.status_code == 201
    body = r.json()
    assert body["incident_id"] == "inc-0003" and body["requested_by"] == "analyst"
    assert (Path(demo_settings.reports_dir) / f"{body['request_id']}.md").is_file()
    assert "Incident report" in body["content"] or "# SentinelAI Incident Report" in body["content"]
    # a second request reuses the stored ReportRequest instead of writing a new one
    again = api.post("/api/reports", json={"assessment_id": "assess-0003"}).json()
    assert again["request_id"] == body["request_id"]
    assert api.get("/api/reports").json()["total"] == 3


def test_generate_report_errors(api):
    assert api.post("/api/reports", json={"assessment_id": "assess-9999"}).status_code == 404
    assert api.post("/api/reports", json={"assessment_id": "nope"}).status_code == 422


def test_report_for_outdated_assessment_is_refused(demo_settings):
    from fastapi.testclient import TestClient
    from sentinelai.platform.api import create_app
    from sentinelai.platform.shared_memory import SharedMemory

    memory = SharedMemory(str(demo_settings.db_path))
    v2 = dict(memory.latest_incident("inc-0003"))
    v2.update(message_id="incupd-0098", version=2, created_at="2026-01-10T09:00:00Z")
    memory.write(v2)
    client = TestClient(create_app(demo_settings))
    r = client.post("/api/reports", json={"assessment_id": "assess-0003"})
    assert r.status_code == 409
    assert client.get("/api/incidents/inc-0003").json()["current_assessment"] is None


# ------------------------------------------------------------------ validation
def test_validation_integration(api):
    v = api.get("/api/validation").json()
    assert v["valid"] is True and v["errors"] == []
    assert v["messages_checked"] == 22 and v["flow_references_checked"] is True
    assert v["scope"] == "entire database" and v["rule_definitions_verified"] is False
    assert any("does not show that an attack happened" in t for t in v["limitations"])


def test_validation_reports_broken_evidence(tmp_path):
    from fastapi.testclient import TestClient
    from sentinelai.platform.api import create_app
    from sentinelai.platform.config import Settings
    from sentinelai.platform.shared_memory import SharedMemory

    memory = SharedMemory(str(tmp_path / "x.db"))
    alert = fixture("alerts.json")[0]
    alert["evidence_refs"] = ["flow:f-does-not-exist"]
    memory.write(alert)
    settings = Settings.for_mode("live", db_path=tmp_path / "x.db", reports_dir=tmp_path / "r",
                                 flows_csv=FIX / "features_sample.csv")
    v = TestClient(create_app(settings)).get("/api/validation").json()
    assert v["valid"] is False
    assert any("f-does-not-exist" in e for e in v["errors"])


def test_api_refuses_requests_for_other_host_names(demo_settings):
    from dataclasses import replace

    from fastapi.testclient import TestClient
    from sentinelai.platform.api import create_app

    settings = replace(demo_settings, allowed_hosts=("127.0.0.1", "localhost"))
    client = TestClient(create_app(settings), base_url="http://127.0.0.1:8000")
    assert client.get("/api/health").status_code == 200
    assert client.get("/api/health", headers={"host": "localhost:8000"}).status_code == 200
    review = {"assessment_id": "assess-0001", "recommendation_index": 0,
              "incident_version": 2, "decision": "approved"}
    rebound = client.post("/api/reviews", json=review, headers={"host": "attacker.example:8000"})
    assert rebound.status_code == 400
    assert client.get("/api/reviews").json()["total"] == 0
    assert client.post("/api/reviews", json=review).status_code == 201


def test_attack_link_only_shows_https_addresses():
    from sentinelai.dashboard.views.frameworks import _attack_link

    link = _attack_link("https://attack.mitre.org/techniques/T1595/")
    assert "href='https://attack.mitre.org/techniques/T1595/'" in link
    assert "rel='noopener noreferrer'" in link
    assert _attack_link("javascript:alert(1)") == ""
    assert _attack_link(None) == ""
    assert "&#x27;" in _attack_link("https://example.org/'onmouseover='x")


def test_unexpected_errors_hide_internals(api, monkeypatch):
    from fastapi.testclient import TestClient

    service = api.app.state.service
    monkeypatch.setattr(service, "stats", lambda: 1 / 0)
    client = TestClient(api.app, raise_server_exceptions=False)
    r = client.get("/api/stats")
    assert r.status_code == 500
    assert r.json() == {"detail": "internal server error"}
    assert "ZeroDivisionError" not in r.text
