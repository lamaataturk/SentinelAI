"""ALL-1 (a): the feature table contract.

Every flow row that leaves Habiba's feature module and enters Malak's model
code must have exactly these columns. Change this file only after telling
the whole team; tests/test_contracts.py checks the fixtures against it.

IP addresses are KEPT in the table (team decision, 23 Nov 2026). They are
carried through so that alerts can name the hosts involved and the
Investigation Agent can link alerts by host. Whether they are also fed to
the Random Forest is controlled by USE_IP_AS_MODEL_INPUT below.
"""
from __future__ import annotations

import ipaddress

# --- Context columns: always kept, travel with every row and into alerts ---
ID_COLUMNS = [
    "flow_id",      # str, unique per flow, e.g. "f-000123"; alerts cite it as "flow:f-000123"
    "network",      # str, AIT network name (fox, harrison, ...); used for the split
    "start_time",   # ISO 8601 UTC, e.g. "2026-01-10T08:00:03Z"
    "end_time",     # ISO 8601 UTC
    "src_ip",       # str, IPv4/IPv6 text  -- KEPT
    "dst_ip",       # str, IPv4/IPv6 text  -- KEPT
    "src_port",     # int
]

# --- Numeric features the model reads (slide 10) ---
FLOW_FEATURES = [
    "duration_s",          # float >= 0
    "bytes",               # int >= 0, bytes in the flow
    "packets",             # int >= 0
    "bytes_per_packet",    # float >= 0 (0 when packets == 0)
    "dst_port",            # int 0-65535
    "protocol",            # int, 6 = TCP, 17 = UDP
]

# Per source host, computed ONLY from flows that started in the 5 minutes
# BEFORE this flow (past-only, so the model never sees the future).
WINDOW_FEATURES = [
    "win5_conn_count",          # int, connections from src_ip
    "win5_distinct_dst_ports",  # int, scans touch many ports
    "win5_distinct_dst_hosts",  # int
    "win5_dns_count",           # int, DNS flows (dst_port 53) from src_ip
    "win5_dns_avg_bytes",       # float, mean bytes of those DNS flows (0 if none)
]

# IP addresses as model inputs: encoded as numbers so the Random Forest can
# read them. Set to False to keep IPs in the table but out of the model.
USE_IP_AS_MODEL_INPUT = True
IP_MODEL_FEATURES = ["src_ip_int", "dst_ip_int", "src_is_private", "dst_is_private"]

# --- Labels: evaluation/training only, NEVER read at runtime by any agent ---
LABEL_COLUMNS = [
    "label_raw",   # str, AIT's own label, e.g. "service_scan", "mail", "dns"
    "label",       # int, 0 = normal, 1 = suspicious (rule in H-3)
]

ALL_COLUMNS = ID_COLUMNS + FLOW_FEATURES + WINDOW_FEATURES + LABEL_COLUMNS


def model_input_columns() -> list[str]:
    """Columns the Random Forest is trained on, in this order."""
    cols = FLOW_FEATURES + WINDOW_FEATURES
    if USE_IP_AS_MODEL_INPUT:
        cols = cols + IP_MODEL_FEATURES
    return cols


def ip_to_int(ip: str) -> int:
    return int(ipaddress.ip_address(ip))


def is_private(ip: str) -> int:
    return int(ipaddress.ip_address(ip).is_private)


def add_ip_model_features(df):
    """Adds the encoded IP columns to a pandas DataFrame (keeps the originals)."""
    df = df.copy()
    df["src_ip_int"] = df["src_ip"].map(ip_to_int)
    df["dst_ip_int"] = df["dst_ip"].map(ip_to_int)
    df["src_is_private"] = df["src_ip"].map(is_private)
    df["dst_is_private"] = df["dst_ip"].map(is_private)
    return df


def validate_feature_frame(df) -> list[str]:
    """Returns a list of problems; empty list means the frame follows the contract."""
    errors: list[str] = []
    missing = [c for c in ALL_COLUMNS if c not in df.columns]
    if missing:
        errors.append(f"missing columns: {missing}")
        return errors
    if df["flow_id"].duplicated().any():
        errors.append("flow_id values are not unique")
    for col in ("src_ip", "dst_ip"):
        bad = []
        for v in df[col]:
            try:
                ipaddress.ip_address(str(v))
            except ValueError:
                bad.append(v)
        if bad:
            errors.append(f"{col} has invalid IPs: {bad[:3]}")
    numeric = FLOW_FEATURES + WINDOW_FEATURES
    for col in numeric:
        if (df[col] < 0).any():
            errors.append(f"{col} has negative values")
    if not df["label"].isin([0, 1]).all():
        errors.append("label must be 0 or 1")
    if not df["protocol"].isin([6, 17]).all():
        errors.append("protocol must be 6 (TCP) or 17 (UDP)")
    if ((df["dst_port"] < 0) | (df["dst_port"] > 65535)).any():
        errors.append("dst_port out of range")
    for col in ("start_time", "end_time"):
        if not df[col].astype(str).str.endswith("Z").all():
            errors.append(f"{col} must be ISO 8601 UTC ending in 'Z'")
    return errors
