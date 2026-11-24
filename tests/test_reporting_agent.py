
import json
from pathlib import Path

import pytest

from sentinelai.platform.shared_memory import SharedMemory
from sentinelai.reporting.reporting_agent import ReportingAgent
from sentinelai.platform.orchestrator import Orchestrator


FIX = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.fixture
def setup_reporting(tmp_path):
    memory = SharedMemory(tmp_path / "reporting.db")

    for filename in (
        "alerts.json",
        "incident_updates.json",
        "assessments.json",
        "report_requests.json",
    ):
        messages = json.loads(
            (FIX / filename).read_text(encoding="utf-8")
        )

        for message in messages:
            memory.write(message)

    agent = ReportingAgent(tmp_path / "reports")

    request = next(
        request
        for request in memory.read("ReportRequest")
        if memory.get(request["assessment_id"])["incident_version"]
        == memory.latest_incident(request["incident_id"])["version"]
    )

    return memory, agent, request


def test_report_generated(setup_reporting):
    memory, agent, request = setup_reporting

    path = agent.run(request, memory)

    assert path.exists()
    assert path.suffix == ".md"
    assert path.stat().st_size > 0


def test_report_contains_required_sections(setup_reporting):
    memory, agent, request = setup_reporting

    report = agent.run(request, memory).read_text(
        encoding="utf-8"
    )

    sections = [
        "Incident Overview",
        "Event Timeline",
        "Evidence and Detection Results",
        "MITRE ATT&CK",
        "Cyber Kill Chain",
        "Severity Assessment",
        "Defensive Recommendations",
        "Uncertainty and Missing Evidence",
        "Possible Benign Explanations",
        "Human Review",
    ]

    for section in sections:
        assert section in report


def test_report_matches_incident(setup_reporting):
    memory, agent, request = setup_reporting

    report = agent.run(request, memory).read_text(
        encoding="utf-8"
    )

    assessment = memory.get(request["assessment_id"])

    assert request["incident_id"] in report
    assert request["assessment_id"] in report
    assert assessment["severity"] in report


def test_human_approval_required(setup_reporting):
    memory, agent, request = setup_reporting

    report = agent.run(request, memory).read_text(
        encoding="utf-8"
    )

    assert "Human approval required: Yes" in report
    assert "possible security incident" in report.lower()


def test_missing_assessment_rejected(setup_reporting):
    memory, agent, request = setup_reporting

    invalid = dict(request)
    invalid["assessment_id"] = "missing-assessment"

    with pytest.raises(ValueError):
        agent.run(invalid, memory)


def test_wrong_message_type_rejected(setup_reporting):
    memory, agent, _ = setup_reporting

    alert = memory.read("Alert")[0]

    with pytest.raises(ValueError):
        agent.run(alert, memory)


def test_report_tracks_output_path(setup_reporting):
    memory, agent, request = setup_reporting

    path = agent.run(request, memory)

    assert agent.reports[request["message_id"]] == path


def test_deterministic_report(setup_reporting):
    memory, agent, request = setup_reporting

    first = agent.run(request, memory).read_text(
        encoding="utf-8"
    )

    second = agent.run(request, memory).read_text(
        encoding="utf-8"
    )

    assert first == second


def test_missing_alerts_disclosed(setup_reporting):
    memory, agent, request = setup_reporting

    incident = memory.latest_incident(
        request["incident_id"]
    )

    assessment = memory.get(request["assessment_id"])

    report = agent.generate_report(
        incident,
        assessment,
        [],
        ["missing-alert"],
        request["message_id"],
    )

    assert "Missing referenced alert: missing-alert" in report


def test_orchestrator_reporting_integration(setup_reporting):
    memory, agent, request = setup_reporting

    class MockAgent:
        def run(self, message, memory):
            pass

    orchestrator = Orchestrator(
        memory,
        MockAgent(),
        MockAgent(),
        agent,
    )

    orchestrator.processed.update(
        message["message_id"]
        for message in memory.read()
        if message["message_id"] != request["message_id"]
    )

    results = orchestrator.run_once()

    assert results["reports_processed"] == 1
    assert agent.reports[request["message_id"]].exists()
    
def test_report_contains_validation_status(setup_reporting):
    memory, agent, request = setup_reporting

    report = agent.run(request, memory).read_text(
        encoding="utf-8"
    )

    assert "Evidence Validation" in report
    assert "Stored-message validation: Passed" in report
    assert "Flow reference validation: Not performed" in report


def test_report_rejects_invalid_evidence(setup_reporting):
    memory, agent, request = setup_reporting

    agent.flow_ids = set()

    with pytest.raises(
        ValueError,
        match="Evidence validation failed"
    ):
        agent.run(request, memory)

    assert not list(agent.output_dir.glob("*.md"))


def test_report_with_verified_flows(setup_reporting):
    import csv

    memory, agent, request = setup_reporting

    with (FIX / "features_sample.csv").open(
        encoding="utf-8", newline=""
    ) as file:
        agent.flow_ids = {
            row["flow_id"]
            for row in csv.DictReader(file)
        }

    report = agent.run(request, memory).read_text(
        encoding="utf-8"
    )

    assert "Flow reference validation: Passed" in report