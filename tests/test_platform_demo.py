"""L-6: demo initialisation (scripts/init_demo.py) and demo/live separation."""
import json
from pathlib import Path

import pytest
from init_demo import InitError, initialise, main

from sentinelai.platform.config import Settings, load_flow_ids
from sentinelai.platform.metadata import get_meta, message_count, set_meta
from sentinelai.platform.shared_memory import SharedMemory

FIX = Path(__file__).resolve().parents[1] / "fixtures"
QUIET = dict(log=lambda *_: None)


def test_initialise_loads_fixtures_and_generates_reports(tmp_path):
    result = initialise(tmp_path / "demo.db", tmp_path / "reports", **QUIET)
    expected = sum(len(json.loads((FIX / f).read_text(encoding="utf-8"))) for f in
                   ("alerts.json", "incident_updates.json", "assessments.json", "report_requests.json"))
    assert result["added"] == expected == 22 and result["skipped"] == 0
    assert result["validation_passed"] and result["flow_ids"] == 32
    assert sorted(result["reports"]) == ["repreq-0001.md", "repreq-0002.md"]
    assert get_meta(tmp_path / "demo.db", "data_source") == "fixtures"
    report = (tmp_path / "reports" / "repreq-0001.md").read_text(encoding="utf-8")
    assert "**Incident:** inc-0001" in report and "**Incident version:** 2" in report


def test_initialise_twice_adds_no_duplicates(tmp_path):
    initialise(tmp_path / "demo.db", tmp_path / "reports", **QUIET)
    second = initialise(tmp_path / "demo.db", tmp_path / "reports", **QUIET)
    assert second["added"] == 0 and second["skipped"] == 22
    assert message_count(tmp_path / "demo.db") == 22


def test_reviews_survive_reinitialisation(tmp_path):
    from sentinelai.platform.reviews import ReviewStore

    db = tmp_path / "demo.db"
    initialise(db, tmp_path / "reports", **QUIET)
    ReviewStore(str(db)).record(SharedMemory(str(db)), assessment_id="assess-0001", recommendation_index=0,
                                decision="approved", incident_version=2)
    initialise(db, tmp_path / "reports", **QUIET)
    assert len(ReviewStore(str(db)).history()) == 1


def test_reset_rebuilds_the_demo_database(tmp_path):
    db, reports = tmp_path / "demo.db", tmp_path / "reports"
    initialise(db, reports, **QUIET)
    (reports / "keep-me.txt").write_text("not a generated report", encoding="utf-8")
    result = initialise(db, reports, reset=True, **QUIET)
    assert result["added"] == 22
    assert (reports / "keep-me.txt").exists()  # only repreq-*.md files are removed


def test_refuses_to_touch_a_database_with_agent_data(tmp_path):
    db = tmp_path / "real.db"
    memory = SharedMemory(str(db))
    memory.write(json.loads((FIX / "alerts.json").read_text(encoding="utf-8"))[0])
    with pytest.raises(InitError):
        initialise(db, tmp_path / "reports", **QUIET)
    with pytest.raises(InitError):
        initialise(db, tmp_path / "reports", reset=True, **QUIET)
    assert db.exists() and message_count(db) == 1


def test_refuses_a_database_marked_as_agent_output(tmp_path):
    db = tmp_path / "real.db"
    SharedMemory(str(db)).write(json.loads((FIX / "alerts.json").read_text(encoding="utf-8"))[0])
    set_meta(db, "data_source", "agents")
    with pytest.raises(InitError):
        initialise(db, tmp_path / "reports", **QUIET)


def test_detects_changed_fixture_content(tmp_path):
    db = tmp_path / "demo.db"
    initialise(db, tmp_path / "reports", **QUIET)
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    for f in FIX.iterdir():
        fixtures.joinpath(f.name).write_bytes(f.read_bytes())
    alerts = json.loads((fixtures / "alerts.json").read_text(encoding="utf-8"))
    alerts[0]["summary"] = "edited"
    (fixtures / "alerts.json").write_text(json.dumps(alerts), encoding="utf-8")
    with pytest.raises(InitError):
        initialise(db, tmp_path / "reports", fixtures_dir=fixtures, **QUIET)


def test_cli_refuses_the_live_database_path():
    live = Settings.for_mode("live")
    assert main(["--db", str(live.db_path)]) == 2


def test_demo_and_live_use_different_files():
    demo, live = Settings.for_mode("demo"), Settings.for_mode("live")
    assert demo.db_path != live.db_path and demo.reports_dir != live.reports_dir
    assert live.flows_csv is None


def test_settings_from_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELAI_MODE", "live")
    monkeypatch.setenv("SENTINELAI_DB", str(tmp_path / "a.db"))
    monkeypatch.setenv("SENTINELAI_REPORTS_DIR", str(tmp_path / "r"))
    monkeypatch.setenv("SENTINELAI_FLOWS_CSV", "none")
    monkeypatch.setenv("SENTINELAI_API_PORT", "8123")
    s = Settings.from_env()
    assert (s.mode, s.db_path, s.flows_csv, s.api_port, s.api_url) == (
        "live", tmp_path / "a.db", None, 8123, "http://127.0.0.1:8123")
    assert s.api_host == "127.0.0.1"
    monkeypatch.setenv("SENTINELAI_MODE", "production")
    with pytest.raises(ValueError):
        Settings.from_env()


def test_flow_ids_loader(tmp_path):
    assert len(load_flow_ids(FIX / "features_sample.csv")) == 32
    assert load_flow_ids(None) is None
    bad = tmp_path / "bad.csv"
    bad.write_text("a,b\n1,2\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_flow_ids(bad)


def test_empty_live_database_gives_empty_but_valid_responses(tmp_path):
    from fastapi.testclient import TestClient
    from sentinelai.platform.api import create_app

    settings = Settings.for_mode("live", db_path=tmp_path / "live.db", reports_dir=tmp_path / "r")
    client = TestClient(create_app(settings))
    system = client.get("/api/system").json()
    assert system["data_source"] == "agents" and system["is_demo_data"] is False
    stats = client.get("/api/stats").json()
    assert stats["total_alerts"] == 0 and stats["alert_activity"]["items"] == []
    assert client.get("/api/incidents").json() == {"items": [], "total": 0}
    assert client.get("/api/reports").json() == {"items": [], "total": 0}
    assert client.get("/api/validation").json()["valid"] is True
