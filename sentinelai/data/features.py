"""H-4: feature module - AIT Netflow rows -> the ALL-1 feature table.

The output has exactly the columns of sentinelai/contracts/features.py
(ALL_COLUMNS, in that order). The same code runs for training and at runtime:

    Runtime:  ext = FlowFeatureExtractor(); row = ext.process(flow)   # flows in start-time order
    Training: build_feature_table(flows)  # sorts by start time, calls the SAME process() per row

Window features (win5_*) follow the contract: per source host (src_ip) in one
network, computed ONLY from flows that STARTED in the 5 minutes BEFORE this flow,
i.e. start time in [t - 300 s, t). Flows starting at exactly t (ties) and later
flows are never used. IPs are kept (team decision 23 Nov); the encoded IP model
inputs are added later by contracts.features.add_ip_model_features().

AIT -> contract mapping (Tstat logs, checked in H-1):
    src_ip/dst_ip/src_port/dst_port = c_ip / s_ip / c_port / s_port
    TCP:  start = first (ms epoch), end = last, duration = durat (ms)
    UDP:  start = min(c_first_abs, s_first_abs), end = max(first + durat);
          c_durat / s_durat are in SECONDS in Tstat's UDP log
    bytes = c_bytes_all + s_bytes_all, packets = c_pkts_all + s_pkts_all
    protocol = 6 for tcp_complete / tcp_nocomplete files, 17 for udp_complete
"""
from __future__ import annotations

import io
import re
import zipfile
from collections import Counter, deque
from pathlib import Path

import numpy as np
import pandas as pd

from sentinelai.contracts.features import ALL_COLUMNS, WINDOW_FEATURES
from .labeling import apply_rule, protocol_from_filename

FEATURE_MODULE_VERSION = "1.0"
WINDOW_MS = 300_000            # 5 minutes
DNS_PORT = 53
PROTOCOL_NUMBER = {"TCP": 6, "UDP": 17}

_TCP_COLS = ["c_ip", "c_port", "s_ip", "s_port", "c_pkts_all", "s_pkts_all", "c_bytes_all", "s_bytes_all",
             "first", "last", "durat", "label"]
_UDP_COLS = ["c_ip", "c_port", "s_ip", "s_port", "c_first_abs", "c_durat", "c_bytes_all", "c_pkts_all",
             "s_first_abs", "s_durat", "s_bytes_all", "s_pkts_all", "label"]
_TEXT_COLS = {"c_ip", "s_ip", "label"}


def clean_column(raw: str) -> str:
    """'#15#c_ip:1' -> 'c_ip', 'c_port:2' -> 'c_port', 'label' -> 'label' (same rule as H-1)."""
    return re.sub(r":\d+$", "", re.sub(r"^#(\d+#)?", "", raw))


def iso_utc(ms) -> np.ndarray:
    """ms since epoch -> '2022-01-15T01:12:33.960Z' (contract: ISO 8601 UTC ending in Z)."""
    t = pd.to_datetime(np.asarray(ms, dtype="float64").round().astype("int64"), unit="ms", utc=True)
    return (t.strftime("%Y-%m-%dT%H:%M:%S.%f").str[:-3] + "Z").to_numpy()


# ---------------------------------------------------------------------------
# 1. Raw Tstat rows -> one normalised flow table
# ---------------------------------------------------------------------------
def normalise_flows(raw: pd.DataFrame, source_file: str, network: str) -> pd.DataFrame:
    """One raw Tstat file (clean column names, all values as text) -> normalised flows."""
    proto = protocol_from_filename(source_file)
    need = _TCP_COLS if proto == "TCP" else _UDP_COLS
    missing = [c for c in need if c not in raw.columns]
    if missing:
        raise ValueError(f"{network}/{source_file}: missing columns {missing}")
    num = {}
    for c in need:
        if c in _TEXT_COLS:
            continue
        v = pd.to_numeric(raw[c], errors="coerce")
        bad = int(v.isna().sum())
        if bad:
            raise ValueError(f"{network}/{source_file}: {bad} non-numeric/empty values in column {c!r}")
        num[c] = v.to_numpy(dtype="float64")

    n = len(raw)
    if proto == "TCP":
        start, end = num["first"], num["last"]
    else:
        s_has = num["s_pkts_all"] > 0
        c_end = num["c_first_abs"] + num["c_durat"] * 1000.0
        s_end = np.where(s_has, num["s_first_abs"] + num["s_durat"] * 1000.0, -np.inf)
        start = np.where(s_has, np.minimum(num["c_first_abs"], num["s_first_abs"]), num["c_first_abs"])
        end = np.maximum(c_end, s_end)
    if np.any(end < start):
        raise ValueError(f"{network}/{source_file}: {int(np.sum(end < start))} flows end before they start")

    stem = Path(source_file).stem
    return pd.DataFrame({
        "flow_id": [f"f-{network}-{stem}-{i:07d}" for i in range(n)],   # i = 0-based data row in the CSV
        "network": network,
        "source_file": Path(source_file).name,
        "protocol_name": proto,
        "start_ms": start, "end_ms": end,
        "src_ip": raw["c_ip"].astype(str).to_numpy(),
        "dst_ip": raw["s_ip"].astype(str).to_numpy(),
        "src_port": num["c_port"].astype("int64"),
        "dst_port": num["s_port"].astype("int64"),
        "bytes": (num["c_bytes_all"] + num["s_bytes_all"]).astype("int64"),
        "packets": (num["c_pkts_all"] + num["s_pkts_all"]).astype("int64"),
        "label_raw": raw["label"].astype(str).to_numpy(),
    })


def read_network_zip(zip_path: str | Path, network: str) -> pd.DataFrame:
    """Stream the three CSVs out of one AIT archive (nothing extracted) -> normalised flows."""
    parts = []
    with zipfile.ZipFile(zip_path) as zf:
        for member in sorted(m for m in zf.namelist() if m.lower().endswith(".csv")):
            with zf.open(member) as f:
                header = io.TextIOWrapper(f, encoding="utf-8").readline().rstrip("\r\n").split(",")
            clean = [clean_column(h) for h in header]
            if len(set(clean)) != len(clean):
                raise ValueError(f"{member}: duplicate column names after cleaning")
            want = set(_TCP_COLS if protocol_from_filename(member) == "TCP" else _UDP_COLS)
            usecols = [h for h, c in zip(header, clean) if c in want]
            with zf.open(member) as f:
                raw = pd.read_csv(f, usecols=usecols, dtype=str, keep_default_na=False,
                                  na_filter=False, encoding="utf-8")
            raw.columns = [clean_column(c) for c in raw.columns]
            parts.append(normalise_flows(raw, Path(member).name, network))
    return pd.concat(parts, ignore_index=True)


# ---------------------------------------------------------------------------
# 2. Streaming window state (THE code used at runtime and in training)
# ---------------------------------------------------------------------------
class _HostWindow:
    """Flows of one source host that started in [t - W, t). Flows that started at
    the current time t wait in pending and only join once time moves past t."""
    __slots__ = ("events", "ports", "hosts", "dns_count", "dns_bytes", "pending_t", "pending")

    def __init__(self):
        self.events = deque()          # (start_ms, dst_port, dst_ip, is_dns, bytes)
        self.ports, self.hosts = Counter(), Counter()
        self.dns_count, self.dns_bytes = 0, 0
        self.pending_t, self.pending = None, []

    def _admit(self, ev):
        self.events.append(ev)
        self.ports[ev[1]] += 1
        self.hosts[ev[2]] += 1
        if ev[3]:
            self.dns_count += 1
            self.dns_bytes += ev[4]

    def _evict(self, ev):
        for counter, key in ((self.ports, ev[1]), (self.hosts, ev[2])):
            counter[key] -= 1
            if counter[key] == 0:
                del counter[key]
        if ev[3]:
            self.dns_count -= 1
            self.dns_bytes -= ev[4]

    def features_then_add(self, t, ev, window_ms):
        if self.pending_t is not None and self.pending_t < t:   # time moved on: ties become "past"
            for p in self.pending:
                self._admit(p)
            self.pending_t, self.pending = None, []
        while self.events and self.events[0][0] < t - window_ms:
            self._evict(self.events.popleft())
        feats = (len(self.events), len(self.ports), len(self.hosts), self.dns_count,
                 self.dns_bytes / self.dns_count if self.dns_count else 0.0)
        self.pending_t = t
        self.pending.append(ev)
        return feats


class FlowFeatureExtractor:
    """Feed flows in non-decreasing start time (per network); get one contract row back.
    A flow dict needs the normalise_flows() columns (flow_id, network, start_ms, end_ms,
    src_ip, dst_ip, src_port, dst_port, bytes, packets, protocol_name)."""

    def __init__(self, window_ms: int = WINDOW_MS):
        self.window_ms = window_ms
        self._hosts: dict[tuple, _HostWindow] = {}
        self._last_t: dict[str, float] = {}

    def process(self, flow: dict) -> dict:
        net, t = flow["network"], float(flow["start_ms"])
        if t < self._last_t.get(net, -np.inf):
            raise ValueError(f"flow {flow.get('flow_id')} arrived out of time order "
                             f"({t} < {self._last_t[net]}); sort or buffer flows by start time first")
        self._last_t[net] = t
        key = (net, flow["src_ip"])
        hw = self._hosts.get(key)
        if hw is None:
            hw = self._hosts[key] = _HostWindow()
        port, nbytes, npk = int(flow["dst_port"]), int(flow["bytes"]), int(flow["packets"])
        w = hw.features_then_add(t, (t, port, flow["dst_ip"], port == DNS_PORT, nbytes), self.window_ms)
        return {
            "duration_s": (float(flow["end_ms"]) - t) / 1000.0,
            "bytes": nbytes, "packets": npk,
            "bytes_per_packet": nbytes / npk if npk > 0 else 0.0,
            "dst_port": port,
            "protocol": PROTOCOL_NUMBER[flow["protocol_name"]],
            **dict(zip(WINDOW_FEATURES, w)),
        }


# ---------------------------------------------------------------------------
# 3. Batch (training) entry points - wrap the same streaming extractor
# ---------------------------------------------------------------------------
_INPUT = ["flow_id", "network", "start_ms", "end_ms", "src_ip", "dst_ip", "src_port", "dst_port",
          "bytes", "packets", "protocol_name"]
_INT_COLS = ["src_port", "bytes", "packets", "dst_port", "protocol", "win5_conn_count",
             "win5_distinct_dst_ports", "win5_distinct_dst_hosts", "win5_dns_count"]


def compute_features(flows: pd.DataFrame, window_ms: int = WINDOW_MS) -> pd.DataFrame:
    """Contract columns except the labels, one row per input flow, in input row order.
    Rows are processed in (network, start_ms, flow_id) order, so input order does not matter."""
    order = flows.sort_values(["network", "start_ms", "flow_id"], kind="mergesort").index
    pos = flows.index.get_indexer(order)
    cols = {c: flows[c].to_numpy() for c in _INPUT}
    ext = FlowFeatureExtractor(window_ms)
    rows = [None] * len(flows)
    for p in pos:
        rows[p] = ext.process({c: cols[c][p] for c in _INPUT})
    feats = pd.DataFrame.from_records(rows, index=flows.index)
    out = pd.DataFrame({
        "flow_id": flows["flow_id"], "network": flows["network"],
        "start_time": iso_utc(flows["start_ms"]), "end_time": iso_utc(flows["end_ms"]),
        "src_ip": flows["src_ip"], "dst_ip": flows["dst_ip"], "src_port": flows["src_port"],
    }, index=flows.index)
    out = pd.concat([out, feats], axis=1)
    for c in _INT_COLS:
        out[c] = out[c].astype("int64")
    return out


def build_feature_table(flows: pd.DataFrame, label_map: dict, window_ms: int = WINDOW_MS):
    """Features for ALL flows (unmapped ones still count in the windows), then the H-3
    rule. Returns (table with exactly ALL_COLUMNS, unmapped rows left out)."""
    feats = compute_features(flows, window_ms)
    label = pd.Series(pd.NA, index=flows.index, dtype="Int8")
    for proto in ("TCP", "UDP"):
        m = flows["protocol_name"] == proto
        if m.any():
            label[m] = apply_rule(flows.loc[m, "label_raw"], proto, label_map)["label"]
    feats["label_raw"] = flows["label_raw"].astype(str)
    feats["label"] = label
    miss = feats["label"].isna()
    unmapped = feats.loc[miss].copy()
    unmapped["source_file"] = flows.loc[miss, "source_file"]
    table = feats[feats["label"].notna()].copy()
    table["label"] = table["label"].astype("int64")
    return table[ALL_COLUMNS].reset_index(drop=True), unmapped
