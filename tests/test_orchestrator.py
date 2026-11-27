
import json
from pathlib import Path

import pytest

from sentinelai.platform.shared_memory import SharedMemory
from sentinelai.platform.orchestrator import Orchestrator


FIX = Path(__file__).resolve().parents[1] / "fixtures"


def load_messages(filename):
    return json.loads(
        (FIX / filename).read_text(encoding="utf-8")
    )


class MockAgent:
    def __init__(self):
        self.calls = []

    def run(self, message, memory):
        self.calls.append(message["message_id"])


@pytest.fixture
def setup_system(tmp_path):
    memory = SharedMemory(tmp_path / "test.db")

    investigation = MockAgent()
    response = MockAgent()
    reporting = MockAgent()

    orchestrator = Orchestrator(
        memory,
        investigation,
        response,
        reporting,
    )

    return memory, orchestrator, investigation, response, reporting


def test_empty_workflow(setup_system):
    memory, orchestrator, _, _, _ = setup_system

    results = orchestrator.run_once()

    assert results == {
        "alerts_processed": 0,
        "incidents_processed": 0,
        "assessments_processed": 0,
        "reports_processed": 0,
        "errors": [],
    }


def test_alert_triggers_investigation(setup_system):
    memory, orchestrator, investigation, _, _ = setup_system

    alert = load_messages("alerts.json")[0]
    memory.write(alert)

    results = orchestrator.run_once()

    assert results["alerts_processed"] == 1
    assert investigation.calls == [alert["message_id"]]


def test_incident_triggers_response(setup_system):
    memory, orchestrator, _, response, _ = setup_system

    incident = load_messages("incident_updates.json")[0]
    memory.write(incident)

    results = orchestrator.run_once()

    assert results["incidents_processed"] == 1
    assert response.calls == [incident["message_id"]]


def test_assessment_triggers_reporting(setup_system):
    memory, orchestrator, _, _, reporting = setup_system

    assessment = load_messages("assessments.json")[0]
    memory.write(assessment)

    results = orchestrator.run_once()
    requests = memory.read("ReportRequest")

    assert results["assessments_processed"] == 1
    assert results["reports_processed"] == 1
    assert len(requests) == 1
    assert requests[0]["assessment_id"] == assessment["message_id"]
    assert reporting.calls == [requests[0]["message_id"]]


def test_no_duplicate_processing(setup_system):
    memory, orchestrator, investigation, _, _ = setup_system

    alert = load_messages("alerts.json")[0]
    memory.write(alert)

    orchestrator.run_once()
    results = orchestrator.run_once()

    assert results["alerts_processed"] == 0
    assert len(investigation.calls) == 1

def test_missing_agent_leaves_its_messages_for_a_later_run(tmp_path):
    memory = SharedMemory(tmp_path / "test.db")
    alert = load_messages("alerts.json")[0]
    memory.write(alert)
    orchestrator = Orchestrator(memory, None, MockAgent(), MockAgent())

    results = orchestrator.run_once()

    assert results["alerts_processed"] == 0
    assert results["errors"] == []

    investigation = MockAgent()
    orchestrator.investigation_agent = investigation

    assert orchestrator.run_once()["alerts_processed"] == 1
    assert investigation.calls == [alert["message_id"]]


class FailsOnceAgent(MockAgent):
    def __init__(self, failing_id):
        super().__init__()
        self.failing_id = failing_id

    def run(self, message, memory):
        if message["message_id"] == self.failing_id:
            self.failing_id = None
            raise RuntimeError("agent crashed")
        super().run(message, memory)


def test_failing_message_is_reported_and_retried(tmp_path):
    memory = SharedMemory(tmp_path / "test.db")
    first, second = load_messages("alerts.json")[:2]
    memory.write(first)
    memory.write(second)
    investigation = FailsOnceAgent(first["message_id"])
    orchestrator = Orchestrator(memory, investigation, MockAgent(), MockAgent())

    results = orchestrator.run_once()

    assert results["alerts_processed"] == 1
    assert investigation.calls == [second["message_id"]]
    assert results["errors"] == [{
        "message_id": first["message_id"],
        "message_type": "Alert",
        "error": "RuntimeError: agent crashed",
    }]

    retry = orchestrator.run_once()

    assert retry["alerts_processed"] == 1
    assert retry["errors"] == []
    assert investigation.calls == [second["message_id"], first["message_id"]]


class AlwaysFailsAgent:
    def run(self, message, memory):
        raise RuntimeError("agent crashed")


def test_many_failures_log_one_traceback(tmp_path, caplog):
    memory = SharedMemory(tmp_path / "test.db")
    for alert in load_messages("alerts.json")[:3]:
        memory.write(alert)
    orchestrator = Orchestrator(memory, AlwaysFailsAgent(), MockAgent(), MockAgent())

    with caplog.at_level("ERROR", logger="sentinelai.orchestrator"):
        results = orchestrator.run_once()

    assert len(results["errors"]) == 3
    assert sum(record.exc_info is not None for record in caplog.records) == 1
    assert "3 Alert messages failed" in caplog.text


def test_existing_report_request_not_duplicated(setup_system):
    memory, orchestrator, _, _, _ = setup_system

    assessment = load_messages("assessments.json")[0]
    memory.write(assessment)

    orchestrator.run_once()
    orchestrator.run_once()

    assert len(memory.read("ReportRequest")) == 1

class MockInvestigationAgent:
    def __init__(self, incident):
        self.incident = incident

    def run(self, message, memory):
        memory.write(self.incident)


class MockResponseAgent:
    def __init__(self, assessment):
        self.assessment = assessment

    def run(self, message, memory):
        memory.write(self.assessment)


class MockReportingAgent:
    def __init__(self):
        self.reports = []

    def run(self, message, memory):
        assessment = memory.get(message["assessment_id"])

        assert assessment is not None

        incident = memory.latest_incident(
            message["incident_id"]
        )

        assert incident is not None

        self.reports.append({
            "incident_id": incident["incident_id"],
            "assessment_id": assessment["message_id"],
            "request_id": message["message_id"],
        })


def test_complete_agent_workflow(tmp_path):
    memory = SharedMemory(tmp_path / "workflow.db")

    alert = load_messages("alerts.json")[0]

    assessment = load_messages("assessments.json")[0]

    incident = max(
        (
            item
            for item in load_messages("incident_updates.json")
            if item["incident_id"] == assessment["incident_id"]
        ),
        key=lambda item: item["version"],
    )

    investigation = MockInvestigationAgent(incident)
    response = MockResponseAgent(assessment)
    reporting = MockReportingAgent()

    orchestrator = Orchestrator(
        memory,
        investigation,
        response,
        reporting,
    )

    memory.write(alert)

    results = orchestrator.run_once()

    assert results == {
        "alerts_processed": 1,
        "incidents_processed": 1,
        "assessments_processed": 1,
        "reports_processed": 1,
        "errors": [],
    }

    assert len(memory.read("Alert")) == 1
    assert len(memory.read("IncidentUpdate")) == 1
    assert len(memory.read("Assessment")) == 1
    assert len(memory.read("ReportRequest")) == 1

    assert len(reporting.reports) == 1

    second_run = orchestrator.run_once()

    assert second_run == {
        "alerts_processed": 0,
        "incidents_processed": 0,
        "assessments_processed": 0,
        "reports_processed": 0,
        "errors": [],
    }

    assert len(reporting.reports) == 1