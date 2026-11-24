
import csv
import json
from pathlib import Path

import pytest

from sentinelai.platform.shared_memory import SharedMemory
from sentinelai.reporting.traceability import EvidenceValidator


FIX = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.fixture
def messages():
    result = []

    for filename in (
        "alerts.json",
        "incident_updates.json",
        "assessments.json",
        "report_requests.json",
    ):
        result.extend(
            json.loads(
                (FIX / filename).read_text(encoding="utf-8")
            )
        )

    return result


@pytest.fixture
def flow_ids():
    with (FIX / "features_sample.csv").open(
        encoding="utf-8", newline=""
    ) as file:
        return {
            row["flow_id"]
            for row in csv.DictReader(file)
        }


def create_memory(tmp_path, messages):
    memory = SharedMemory(tmp_path / "traceability.db")

    for message in messages:
        memory.write(message)

    return memory


def test_valid_evidence(tmp_path, messages, flow_ids):
    memory = create_memory(tmp_path, messages)

    result = EvidenceValidator().validate(memory, flow_ids)

    assert result["valid"], result["errors"]
    assert result["errors"] == []
    assert result["messages_checked"] == len(messages)


def test_missing_alert_detected(tmp_path, messages, flow_ids):
    incident = next(
        m for m in messages
        if m["message_type"] == "IncidentUpdate"
    )

    missing_id = incident["alert_ids"][0]

    messages = [
        m for m in messages
        if m["message_id"] != missing_id
    ]

    memory = create_memory(tmp_path, messages)

    result = EvidenceValidator().validate(memory, flow_ids)

    assert not result["valid"]
    assert any(
        missing_id in error for error in result["errors"]
    )


def test_missing_flow_detected(tmp_path, messages, flow_ids):
    memory = create_memory(tmp_path, messages)

    result = EvidenceValidator().validate(memory, set())

    assert not result["valid"]
    assert any(
        "flow:" in error for error in result["errors"]
    )


def test_missing_assessment_detected(
    tmp_path, messages, flow_ids
):
    request = next(
        m for m in messages
        if m["message_type"] == "ReportRequest"
    )

    missing_id = request["assessment_id"]

    messages = [
        m for m in messages
        if m["message_id"] != missing_id
    ]

    memory = create_memory(tmp_path, messages)

    result = EvidenceValidator().validate(memory, flow_ids)

    assert not result["valid"]
    assert any(
        missing_id in error for error in result["errors"]
    )


def test_invalid_incident_version(
    tmp_path, messages, flow_ids
):
    assessment = next(
        m for m in messages
        if m["message_type"] == "Assessment"
    )

    assessment["incident_version"] = 999

    memory = create_memory(tmp_path, messages)

    result = EvidenceValidator().validate(memory, flow_ids)

    assert not result["valid"]
    assert any(
        "incident version" in error
        for error in result["errors"]
    )


def test_flow_check_status(tmp_path, messages, flow_ids):
    memory = create_memory(tmp_path, messages)

    validator = EvidenceValidator()

    checked = validator.validate(memory, flow_ids)
    unchecked = validator.validate(memory)

    assert checked["flow_references_checked"] is True
    assert unchecked["flow_references_checked"] is False


def test_unrelated_alert_evidence(
    tmp_path, messages, flow_ids
):
    incident = next(
        m for m in messages
        if m["message_type"] == "IncidentUpdate"
        and m["candidate_techniques"]
    )

    unrelated_alert = next(
        m["message_id"]
        for m in messages
        if m["message_type"] == "Alert"
        and m["message_id"] not in incident["alert_ids"]
    )

    incident["candidate_techniques"][0]["evidence_refs"].append(
        f"alert:{unrelated_alert}"
    )

    memory = create_memory(tmp_path, messages)

    result = EvidenceValidator().validate(memory, flow_ids)

    assert not result["valid"]
    assert any(
        "does not belong to this incident" in error
        for error in result["errors"]
    )
