
"""M-5: Detection Agent using the shared SentinelAI feature and Alert contracts."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import hashlib

import joblib
import pandas as pd

from sentinelai.detection.data import FEATURE_COLUMNS
from sentinelai.detection.rules import detect_rule_hits
from sentinelai.contracts.messages import validate_message
from sentinelai.platform.shared_memory import SharedMemory


def _utc_timestamp(value):
    """Convert a contract timestamp into UTC ISO 8601 format."""
    timestamp = pd.to_datetime(value, utc=True)

    if pd.isna(timestamp):
        raise ValueError(f"Invalid flow timestamp: {value}")

    return timestamp.isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


class DetectionAgent:

    def __init__(
        self,
        model_path,
        memory,
        decision_policy="or",
        threshold_override=None,
    ):
        self.bundle = joblib.load(model_path)

        self.memory = (
            memory
            if hasattr(memory, "write") and hasattr(memory, "read")
            else SharedMemory(str(memory))
        )

        if decision_policy not in {"or", "and"}:
            raise ValueError("decision_policy must be 'or' or 'and'")

        self.decision_policy = decision_policy

        self.threshold = float(
            threshold_override
            if threshold_override is not None
            else self.bundle["threshold"]
        )

    def run(self, frame, memory=None):
        """Score runtime flows without labels and publish valid Alerts."""

        mem = memory or self.memory

        required = {
            "flow_id",
            "network",
            "start_time",
            "end_time",
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "protocol",
            *FEATURE_COLUMNS,
        }

        missing = sorted(required - set(frame.columns))

        if missing:
            raise ValueError(
                f"Detection Agent input missing fields: {missing}"
            )

        feature_columns = self.bundle["feature_columns"]

        missing_model_features = sorted(
            set(feature_columns) - set(frame.columns)
        )

        if missing_model_features:
            raise ValueError(
                "Model input columns missing: "
                f"{missing_model_features}"
            )

        X = frame[feature_columns].astype(float)

        probabilities = self.bundle["model"].predict_proba(X)[
            :, list(self.bundle["model"].classes_).index(1)
        ]

        existing = {
            message["message_id"]
            for message in mem.read("Alert")
        }

        written = []

        for (_, row), score in zip(frame.iterrows(), probabilities):

            hits = detect_rule_hits(row)

            rf_flag = float(score) >= self.threshold
            rule_flag = bool(hits)

            if self.decision_policy == "or":
                flagged = rf_flag or rule_flag
            else:
                flagged = rf_flag and rule_flag

            if not flagged:
                continue

            if rf_flag and rule_flag:
                detector = "hybrid"
            elif rf_flag:
                detector = "rf"
            else:
                detector = "rules"

            raw_id = str(row["flow_id"])
            suffix = hashlib.sha1(
                raw_id.encode()
            ).hexdigest()[:12]

            message_id = f"alert-{suffix}"

            if message_id in existing:
                continue

            first_seen = _utc_timestamp(row["start_time"])
            last_seen = _utc_timestamp(row["end_time"])

            protocol = int(row["protocol"])

            if protocol not in {6, 17}:
                raise ValueError(
                    f"Unsupported protocol for flow {raw_id}: {protocol}"
                )

            payload = {
                "message_id": message_id,
                "message_type": "Alert",
                "schema_version": "1.0",
                "created_at": (
                    datetime.now(timezone.utc)
                    .isoformat(timespec="seconds")
                    .replace("+00:00", "Z")
                ),
                "producer": "detection_agent",
                "evidence_refs": (
                    [f"flow:{raw_id}"]
                    + [f"rule:{rule}" for rule in hits]
                ),
                "network": str(row["network"]),
                "detector": detector,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "src_ip": str(row["src_ip"]),
                "dst_ip": str(row["dst_ip"]),
                "src_port": int(row["src_port"]),
                "dst_port": int(row["dst_port"]),
                "protocol": protocol,
                "rf_score": float(score) if rf_flag else None,
                "rule_hits": hits,
                "ids_source": None,
                "signature": None,
                "user": None,
                "hostname": None,
                "summary": (
                    f"{detector} detection for flow {raw_id}; "
                    f"rules={hits}; RF score={float(score):.4f}."
                ),
            }

            errors = validate_message(payload)

            if errors:
                raise ValueError(
                    "Generated Alert violates shared message contract: "
                    + "; ".join(errors)
                )

            mem.write(payload)
            existing.add(message_id)
            written.append(payload)

        return written
