"""L-6.3: persistent human review decisions (ReviewStore)."""
import json
import sqlite3
from pathlib import Path

import pytest

from sentinelai.platform.reviews import ReviewError, ReviewStore, recommendation_fingerprint
from sentinelai.platform.shared_memory import SharedMemory

FIX = Path(__file__).resolve().parents[1] / "fixtures"


def load(name):
    return json.loads((FIX / name).read_text(encoding="utf-8"))


@pytest.fixture
def memory_and_store(tmp_path):
    db = tmp_path / "shared.db"
    memory = SharedMemory(str(db))
    for name in ("alerts.json", "incident_updates.json", "assessments.json"):
        for message in load(name):
            memory.write(message)
    return memory, ReviewStore(str(db)), db


def record(memory, store, **overrides):
    args = dict(assessment_id="assess-0001", recommendation_index=0, decision="approved",
                incident_version=2, comment="looks right", analyst="lama")
    args.update(overrides)
    return store.record(memory, **args)


def test_approval_is_recorded_with_context(memory_and_store):
    memory, store, _ = memory_and_store
    review, created = record(memory, store)
    assert created is True
    assert review["decision"] == "approved"
    assert review["incident_id"] == "inc-0001" and review["incident_version"] == 2
    assert review["recommendation_ref"] == "assess-0001#rec-0"
    recommendation = memory.get("assess-0001")["recommendations"][0]
    assert review["recommendation_action"] == recommendation["action"]
    assert review["recommendation_fingerprint"] == recommendation_fingerprint(recommendation)
    assert review["reviewed_at"].endswith("Z")


def test_rejection_is_recorded(memory_and_store):
    memory, store, _ = memory_and_store
    review, created = record(memory, store, recommendation_index=3, decision="rejected", comment="too broad")
    assert created and review["decision"] == "rejected" and review["comment"] == "too broad"


def test_decisions_survive_a_restart(memory_and_store):
    memory, store, db = memory_and_store
    record(memory, store)
    record(memory, store, recommendation_index=1, decision="rejected")
    reopened = ReviewStore(str(db))  # new object, same file = application restart
    current = reopened.current("assess-0001")
    assert current[0]["decision"] == "approved" and current[1]["decision"] == "rejected"
    summary = reopened.summary(memory.get("assess-0001"))
    assert summary == {"status": "partially_reviewed", "recommendations": 4,
                       "approved": 1, "rejected": 1, "pending": 2}


def test_changing_a_decision_keeps_the_history(memory_and_store):
    memory, store, _ = memory_and_store
    first, _ = record(memory, store)
    second, created = record(memory, store, decision="rejected", comment="changed my mind")
    assert created and second["supersedes"] == first["review_id"]
    history = store.history(assessment_id="assess-0001")
    assert [r["decision"] for r in history] == ["approved", "rejected"]
    assert store.current("assess-0001")[0]["decision"] == "rejected"


def test_duplicate_submission_does_not_add_a_row(memory_and_store):
    memory, store, _ = memory_and_store
    first, created_1 = record(memory, store)
    again, created_2 = record(memory, store)
    assert created_1 is True and created_2 is False
    assert again["review_id"] == first["review_id"]
    assert len(store.history()) == 1


@pytest.mark.parametrize("decision", ["approve", "APPROVED", "pending", "execute", ""])
def test_invalid_decisions_are_rejected(memory_and_store, decision):
    memory, store, _ = memory_and_store
    with pytest.raises(ReviewError) as err:
        record(memory, store, decision=decision)
    assert err.value.status == 422
    assert store.history() == []


def test_missing_assessment(memory_and_store):
    memory, store, _ = memory_and_store
    with pytest.raises(ReviewError) as err:
        record(memory, store, assessment_id="assess-9999")
    assert err.value.status == 404


def test_message_that_is_not_an_assessment(memory_and_store):
    memory, store, _ = memory_and_store
    with pytest.raises(ReviewError) as err:
        record(memory, store, assessment_id="alert-0001")
    assert err.value.status == 404


@pytest.mark.parametrize("index", [-1, 4, 99])
def test_invalid_recommendation_reference(memory_and_store, index):
    memory, store, _ = memory_and_store
    with pytest.raises(ReviewError) as err:
        record(memory, store, recommendation_index=index)
    assert err.value.status == 404


def test_version_the_analyst_saw_must_match(memory_and_store):
    memory, store, _ = memory_and_store
    with pytest.raises(ReviewError) as err:
        record(memory, store, incident_version=1)
    assert err.value.status == 409


def test_outdated_assessment_cannot_be_reviewed(memory_and_store):
    memory, store, _ = memory_and_store
    record(memory, store)  # accepted while v2 is the latest version
    v3 = dict(memory.latest_incident("inc-0001"))
    v3.update(message_id="incupd-0099", version=3, created_at="2026-01-10T09:30:00Z")
    memory.write(v3)
    with pytest.raises(ReviewError) as err:
        record(memory, store, recommendation_index=1)
    assert err.value.status == 409 and "outdated" in str(err.value)
    # the earlier decision stays in the audit log, tied to version 2
    assert [r["incident_version"] for r in store.history()] == [2]


def test_agent_messages_are_never_modified(memory_and_store):
    memory, store, db = memory_and_store
    before = memory.get("assess-0001")
    record(memory, store)
    after = memory.get("assess-0001")
    assert after == before and after["review_status"] == "pending"
    with sqlite3.connect(db) as conn:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"messages", "human_reviews"} <= tables


def test_comment_length_is_limited(memory_and_store):
    memory, store, _ = memory_and_store
    with pytest.raises(ReviewError):
        record(memory, store, comment="x" * 2001)


def test_assessment_without_recommendations_has_nothing_to_review(memory_and_store):
    memory, store, _ = memory_and_store
    assert store.summary(memory.get("assess-0003"))["status"] == "no_recommendations"
    with pytest.raises(ReviewError):
        record(memory, store, assessment_id="assess-0003", incident_version=1)
