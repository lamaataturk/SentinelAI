import copy
import json
from pathlib import Path

import pandas as pd
import pytest

from sentinelai.contracts.features import (
    add_ip_model_features, model_input_columns, validate_feature_frame,
)
from sentinelai.contracts.messages import validate_bundle, validate_message

FIX = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.fixture(scope="module")
def flows():
    return pd.read_csv(FIX / "features_sample.csv")


@pytest.fixture(scope="module")
def messages():
    out = []
    for name in ("alerts.json", "incident_updates.json", "assessments.json", "report_requests.json"):
        out += json.loads((FIX / name).read_text())
    return out


# ---------------------------------------------------------------- features
def test_feature_fixture_follows_contract(flows):
    assert validate_feature_frame(flows) == []


def test_ip_columns_are_kept(flows):
    assert "src_ip" in flows.columns and "dst_ip" in flows.columns
    assert flows["src_ip"].notna().all() and flows["dst_ip"].notna().all()


def test_ip_model_features_are_numeric(flows):
    df = add_ip_model_features(flows)
    for col in model_input_columns():
        assert pd.api.types.is_numeric_dtype(df[col]), col
    # originals are still there
    assert {"src_ip", "dst_ip"} <= set(df.columns)


def test_labels_are_never_model_inputs():
    assert "label" not in model_input_columns()
    assert "label_raw" not in model_input_columns()


def test_missing_column_is_caught(flows):
    assert validate_feature_frame(flows.drop(columns=["src_ip"]))


def test_fixture_has_both_classes(flows):
    assert set(flows["label"]) == {0, 1}


# ---------------------------------------------------------------- messages
def test_every_fixture_message_is_valid(messages):
    problems = [p for m in messages for p in validate_message(m)]
    assert problems == []


def test_bundle_references_resolve(messages, flows):
    assert validate_bundle(messages, set(flows["flow_id"])) == []


def test_all_four_types_present(messages):
    assert {m["message_type"] for m in messages} == {"Alert", "IncidentUpdate", "Assessment", "ReportRequest"}


def test_alert_without_ip_is_rejected(messages):
    a = copy.deepcopy(next(m for m in messages if m["message_type"] == "Alert"))
    a["src_ip"] = None
    assert validate_message(a)


def test_recommendation_must_need_human(messages):
    a = copy.deepcopy(next(m for m in messages if m["message_type"] == "Assessment" and m["recommendations"]))
    a["recommendations"][0]["requires_human_approval"] = False
    assert validate_message(a)


def test_technique_needs_evidence(messages):
    inc = copy.deepcopy(next(m for m in messages if m["message_type"] == "IncidentUpdate"
                             and m["candidate_techniques"]))
    inc["candidate_techniques"][0]["evidence_refs"] = []
    assert validate_message(inc)


def test_dangling_reference_is_caught(messages):
    broken = copy.deepcopy(messages)
    inc = next(m for m in broken if m["message_type"] == "IncidentUpdate")
    inc["alert_ids"].append("alert-9999")
    assert validate_bundle(broken)


def test_wrong_producer_is_rejected(messages):
    a = copy.deepcopy(next(m for m in messages if m["message_type"] == "Assessment"))
    a["producer"] = "detection_agent"
    assert validate_message(a)
