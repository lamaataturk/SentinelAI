"""R-1: load the AIT Alert Data Set (AIT-ADS) into one common alert table.

Two input formats:

1. The authors' CSV export (alerts_csv/<scenario>_alerts.txt from
   github.com/ait-aecid/alert-data-set). Has all 2,655,821 alerts with time,
   rule name, the IP and name of the host that raised the alert, and two labels.
   It has NO source/destination IPs.  -> load_alert_csv()

2. The raw Zenodo files (ait_ads.zip: <scenario>_wazuh.json, <scenario>_aminer.json,
   doi 10.5281/zenodo.8263181). Suricata alerts in them carry src/dest IPs and ports.
   -> iter_raw_wazuh(), iter_raw_aminer()   (written from the authors' analyze.py;
   check them on the real files before relying on them)

Labels are split off into a separate table on load, so the Investigation Agent
physically never receives them. Only evaluation code joins them back.
"""
from __future__ import annotations

import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

SCENARIOS = ["fox", "harrison", "russellmitchell", "santos", "shaw", "wardbeck", "wheeler", "wilson"]

# Attack phases as named by the dataset authors, in the order they happen.
ATTACK_PHASES = ["network_scans", "service_scans", "dirb", "wpscan", "webshell", "cracking",
                 "reverse_shell", "privilege_escalation", "service_stop", "dnsteal"]

ALERT_COLUMNS = ["alert_id", "network", "ts", "time", "ids_source", "signature", "short",
                 "host", "host_ip", "src_ip", "dst_ip", "src_port", "dst_port", "protocol"]
EVAL_COLUMNS = ["alert_id", "eval_phase", "eval_event_label"]


def _source_from_name(names: pd.Series) -> pd.Series:
    src = names.str.extract(r"^(Wazuh|Suricata|AMiner):", expand=False).str.lower()
    return src.fillna("aminer")


def _iso(ts: pd.Series) -> pd.Series:
    return pd.to_datetime(ts, unit="s", utc=True).dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def load_alert_csv(path: str | Path, scenario: str) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Reads one <scenario>_alerts.txt. Returns (alerts, eval_labels)."""
    raw = pd.read_csv(path, dtype={"name": "string", "ip": "string", "host": "string",
                                   "short": "string", "time_label": "string",
                                   "event_label": "string"})
    raw = raw.reset_index(drop=True)
    alerts = pd.DataFrame({
        "alert_id": [f"alert-{scenario}-{i:07d}" for i in range(len(raw))],
        "network": scenario,
        "ts": raw["time"].astype("int64"),
        "time": _iso(raw["time"]),
        "ids_source": _source_from_name(raw["name"]),
        "signature": raw["name"],
        "short": raw["short"],
        "host": raw["host"],
        "host_ip": raw["ip"],
        # Not in the CSV export. Filled by the raw-JSON reader when available.
        "src_ip": pd.Series([None] * len(raw), dtype="string"),
        "dst_ip": pd.Series([None] * len(raw), dtype="string"),
        "src_port": pd.Series([pd.NA] * len(raw), dtype="Int64"),
        "dst_port": pd.Series([pd.NA] * len(raw), dtype="Int64"),
        "protocol": pd.Series([None] * len(raw), dtype="string"),
    })
    eval_labels = pd.DataFrame({
        "alert_id": alerts["alert_id"],
        "eval_phase": raw["time_label"],          # phase by time window (noisy)
        "eval_event_label": raw["event_label"],   # exact label where known, else "-"
    })
    alerts = alerts.sort_values(["ts", "alert_id"], kind="stable").reset_index(drop=True)
    return alerts, eval_labels


def save_table(df: pd.DataFrame, path: Path) -> Path:
    """Parquet if pyarrow is installed, otherwise gzipped CSV."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        import pyarrow  # noqa: F401
        out = path.with_suffix(".parquet")
        df.to_parquet(out, index=False)
    except ImportError:
        out = path.with_suffix(".csv.gz")
        df.to_csv(out, index=False)
    return out


def read_table(path: Path) -> pd.DataFrame:
    for suffix in (".parquet", ".csv.gz"):
        p = path.with_suffix(suffix)
        if p.exists():
            return pd.read_parquet(p) if suffix == ".parquet" else pd.read_csv(p)
    raise FileNotFoundError(path)


# ------------------------------------------------------------------ phases
def load_phases(ait_repo: str | Path) -> pd.DataFrame:
    """Attack-phase start/end times per scenario, read from the authors' attacktimes.py.

    Same information as labels.csv on Zenodo. Evaluation only.
    Returns columns: scenario, phase, start, end, is_attack.
    """
    spec = importlib.util.spec_from_file_location("ait_attacktimes", Path(ait_repo) / "attacktimes.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    rows = []
    for scenario, phases in mod.phase.items():
        for name, (start, end) in phases.items():
            rows.append({"scenario": scenario, "phase": name,
                         "start": start.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                         "end": end.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                         "is_attack": name in ATTACK_PHASES})
    return pd.DataFrame(rows)


# ------------------------------------------------------------------ raw JSON (Zenodo)
def _wazuh_time(j: dict) -> float | None:
    """Timestamp of the original event, following the authors' analyze.py."""
    data, pre = j.get("data") or {}, j.get("predecoder") or {}
    try:
        if "timestamp" in data:
            return datetime.strptime(data["timestamp"], "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()
        if "timestamp" in pre:
            t = pre["timestamp"]
            fmt, t = ("%m/%d/%Y-%H:%M:%S.%f", t) if "/" in t else ("%Y %b %d %H:%M:%S", "2022 " + t)
            return datetime.strptime(t, fmt).replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        return None
    return None  # timestamp only inside full_log: needs the authors' timestampExtractor


def iter_raw_wazuh(path: str | Path, scenario: str):
    """Yields alert rows from <scenario>_wazuh.json (Wazuh + Suricata). Keeps every IP present."""
    with open(path) as fh:
        for n, line in enumerate(fh):
            if "The average number" in line:
                continue
            j = json.loads(line)
            desc = j["rule"]["description"]
            data = j.get("data") or {}
            ts = _wazuh_time(j)
            yield {
                "raw_line": n, "network": scenario, "ts": ts,
                "ids_source": "suricata" if desc.startswith("Suricata: ") else "wazuh",
                "signature": desc if desc.startswith("Suricata: ") else "Wazuh: " + desc,
                "host_ip": (j.get("agent") or {}).get("ip"),
                "src_ip": data.get("src_ip") or data.get("srcip"),
                "dst_ip": data.get("dest_ip") or data.get("dstip"),
                "src_port": data.get("src_port") or data.get("srcport"),
                "dst_port": data.get("dest_port") or data.get("dstport"),
                "protocol": data.get("proto") or data.get("protocol"),
            }


def iter_raw_aminer(path: str | Path, scenario: str):
    with open(path) as fh:
        for n, line in enumerate(fh):
            j = json.loads(line)
            yield {
                "raw_line": n, "network": scenario,
                "ts": j["LogData"]["DetectionTimestamp"][-1],
                "ids_source": "aminer",
                "signature": j["AnalysisComponent"]["AnalysisComponentName"],
                "host_ip": j["AMiner"]["ID"],  # authors map this ID to a host via server_configs
                "src_ip": None, "dst_ip": None, "src_port": None, "dst_port": None, "protocol": None,
            }


# ------------------------------------------------------------------ to messages
def to_alert_messages(alerts: pd.DataFrame) -> list[dict]:
    """Turns alert rows into contract Alert messages (producer ait_ids_loader)."""
    out = []
    for r in alerts.itertuples(index=False):
        def val(x):
            return None if pd.isna(x) else x
        out.append({
            "message_id": r.alert_id, "message_type": "Alert", "schema_version": "1.0",
            "created_at": r.time, "producer": "ait_ids_loader",
            "evidence_refs": [f"raw_log:{r.network}/{r.alert_id}"],
            "network": r.network, "detector": "ids",
            "first_seen": r.time, "last_seen": r.time,
            "host_ip": val(r.host_ip), "src_ip": val(r.src_ip), "dst_ip": val(r.dst_ip),
            "src_port": None if pd.isna(r.src_port) else int(r.src_port),
            "dst_port": None if pd.isna(r.dst_port) else int(r.dst_port),
            "protocol": val(r.protocol), "rf_score": None, "rule_hits": [],
            "ids_source": r.ids_source, "signature": val(r.signature),
            "user": None, "hostname": val(r.host), "summary": f"{r.short}: {r.signature}",
        })
    return out
