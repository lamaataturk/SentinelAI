
import copy
import json
import sqlite3
from pathlib import Path

import pytest

from sentinelai.platform.shared_memory import SharedMemory
from sentinelai.contracts.messages import MESSAGE_TYPES


FIX = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.fixture
def memory(tmp_path):
    return SharedMemory(tmp_path / "test.db")


@pytest.fixture
def messages():
    result = []

    for name in (
        "alerts.json",
        "incident_updates.json",
        "assessments.json",
        "report_requests.json",
    ):
        result.extend(
            json.loads((FIX / name).read_text(encoding="utf-8"))
        )

    return result


def test_empty_database(memory):
    assert memory.read() == []


def test_write_and_read_all_messages(memory, messages):
    for message in messages:
        memory.write(message)

    assert memory.read() == messages

    for message_type in MESSAGE_TYPES:
        expected = [
            m for m in messages
            if m["message_type"] == message_type
        ]

        assert expected
        assert memory.read(message_type) == expected


def test_get_message_by_id(memory, messages):
    message = messages[0]
    memory.write(message)

    assert memory.get(message["message_id"]) == message
    assert memory.get("nonexistent-id") is None


def test_database_persistence(tmp_path, messages):
    db_path = tmp_path / "persistent.db"

    memory = SharedMemory(db_path)
    memory.write(messages[0])

    reopened = SharedMemory(db_path)

    assert reopened.get(
        messages[0]["message_id"]
    ) == messages[0]


def test_invalid_message_rejected(memory, messages):
    invalid = copy.deepcopy(messages[0])
    invalid["producer"] = "unknown_agent"

    with pytest.raises(ValueError):
        memory.write(invalid)

    assert memory.read() == []


def test_duplicate_message_rejected(memory, messages):
    message = messages[0]
    memory.write(message)

    with pytest.raises(sqlite3.IntegrityError):
        memory.write(message)

    assert len(memory.read()) == 1


def test_latest_incident(memory, messages):
    updates = [
        m for m in messages
        if m["message_type"] == "IncidentUpdate"
    ]

    for update in reversed(updates):
        memory.write(update)

    for incident_id in {m["incident_id"] for m in updates}:
        expected = max(
            (
                m for m in updates
                if m["incident_id"] == incident_id
            ),
            key=lambda m: m["version"],
        )

        assert memory.latest_incident(incident_id) == expected

    assert memory.latest_incident("nonexistent") is None
