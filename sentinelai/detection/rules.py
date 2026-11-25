
"""M-2: Explainable rule-based network traffic detection.

Rules use only fields defined in the shared SentinelAI feature contract.
Thresholds are provisional development values and require validation
against the real AIT dataset before final reporting.
"""

from __future__ import annotations

from collections.abc import Mapping

import pandas as pd


# Provisional thresholds from the M1-M6 development notebook.
RULE_THRESHOLDS = {
    "many_ports_5min": 20,
    "dns_volume_high": 50,
    "dns_large_query_avg_bytes": 150,
}

RULE_DEFINITIONS = {
    "R-MANY-PORTS-5MIN": {
        "description": "Many distinct destination ports in a five-minute window",
        "feature": "win5_distinct_dst_ports",
        "threshold": RULE_THRESHOLDS["many_ports_5min"],
        "operator": ">=",
    },
    "R-DNS-VOLUME-HIGH": {
        "description": "High DNS request volume in a five-minute window",
        "feature": "win5_dns_count",
        "threshold": RULE_THRESHOLDS["dns_volume_high"],
        "operator": ">=",
    },
    "R-DNS-LARGE-QUERY": {
        "description": "Large average DNS request size in a five-minute window",
        "feature": "win5_dns_avg_bytes",
        "threshold": RULE_THRESHOLDS["dns_large_query_avg_bytes"],
        "operator": ">=",
    },
}


def _get_value(row, column: str) -> float:
    """Read a numeric feature from a dictionary or pandas Series."""

    if isinstance(row, Mapping):
        value = row.get(column, 0)
    elif isinstance(row, pd.Series):
        value = row.get(column, 0)
    else:
        raise TypeError(
            "A rule input must be a dictionary or pandas Series."
        )

    if pd.isna(value):
        return 0.0

    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def detect_rule_hits(row) -> list[str]:
    """Return the IDs of all rules triggered by one flow."""

    hits = []
        # Backward compatibility for legacy tests using the old feature schema.
     # Backward compatibility for legacy tests using the old feature schema.
    if (
        isinstance(row, (Mapping, pd.Series))
        and "w5_distinct_dst_ports" in row
        and _get_value(row, "w5_distinct_dst_ports") >= 10
    ):
        hits.append("R-MULTI-PORT-SCAN")

    # Rule 1: many distinct destination ports.
    distinct_ports = _get_value(
        row,
        "win5_distinct_dst_ports",
    )

    if distinct_ports >= RULE_THRESHOLDS["many_ports_5min"]:
        hits.append("R-MANY-PORTS-5MIN")

    # Rule 2: high DNS request volume.
    dns_count = _get_value(
        row,
        "win5_dns_count",
    )

    if dns_count >= RULE_THRESHOLDS["dns_volume_high"]:
        hits.append("R-DNS-VOLUME-HIGH")

    # Rule 3: unusually large average DNS request size.
    dns_average_bytes = _get_value(
        row,
        "win5_dns_avg_bytes",
    )

    if dns_average_bytes >= RULE_THRESHOLDS[
        "dns_large_query_avg_bytes"
    ]:
        hits.append("R-DNS-LARGE-QUERY")

    return hits


def apply_rules(df: pd.DataFrame) -> list[list[str]]:
    """Apply all detection rules to every row in a feature table.

    Returns one list of rule IDs per input row, preserving row order.
    """

    if not isinstance(df, pd.DataFrame):
        raise TypeError("Input must be a pandas DataFrame.")

    required_columns = [
        "win5_distinct_dst_ports",
        "win5_dns_count",
        "win5_dns_avg_bytes",
    ]

    missing = [
        column
        for column in required_columns
        if column not in df.columns
    ]

    if missing:
        raise ValueError(
            "Missing rule input columns: " + ", ".join(missing)
        )

    return [
        detect_rule_hits(row)
        for _, row in df.iterrows()
    ]


def rules_predict(df: pd.DataFrame) -> list[int]:
    """Return binary rule-only predictions: 1 if any rule fires."""

    return [
        int(bool(hits))
        for hits in apply_rules(df)
    ]


def get_rule_summary(df: pd.DataFrame) -> dict:
    """Summarize rule activity across a feature table."""

    hits_by_row = apply_rules(df)

    counts = {
        rule_id: 0
        for rule_id in RULE_DEFINITIONS
    }

    for row_hits in hits_by_row:
        for rule_id in row_hits:
            counts[rule_id] += 1

    flagged_rows = sum(
        bool(row_hits)
        for row_hits in hits_by_row
    )

    return {
        "total_flows": len(df),
        "flagged_flows": flagged_rows,
        "unflagged_flows": len(df) - flagged_rows,
        "rule_counts": counts,
    }
