#!/usr/bin/env python3
"""
SentinelAI H-2 - CSE-CIC-IDS2018 (backup dataset) verification scan.

Streams each of the 10 official "Processed Traffic Data for ML Algorithms" CSVs
from the public bucket s3://cse-cic-ids2018 (anonymous HTTPS) in chunks. Nothing
is written to disk except the summary outputs. For every file it records:
  * exact header, number of rows, physical line count (reconciliation)
  * repeated header lines inside the data (rows whose Label == "Label")
  * exact Label value counts (no stripping / case folding)
  * full-file checks on selected numeric columns (empty, non-numeric, inf, negative)
  * Timestamp range and Protocol values
and, on the first SAMPLE_ROWS rows of each file only, a full-column profile
(empty / non-numeric / infinite / negative cells, exact duplicate rows, constant columns).

Run: python scripts/h2_check_ids2018.py --out-dir data/processed/h2_outputs
"""
from __future__ import annotations

import argparse
import io
import json
import time
import urllib.parse
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd
import requests

BUCKET_URL = "https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/"
PREFIX = "Processed Traffic Data for ML Algorithms/"
CHUNK = 250_000
SAMPLE_ROWS = 200_000
# Columns checked over EVERY row (cheap). All exist in both header variants.
FULL_COLS = ["Dst Port", "Protocol", "Timestamp", "Flow Duration", "Flow Byts/s", "Flow Pkts/s",
             "Init Fwd Win Byts", "Label"]
NUMERIC_FULL = ["Dst Port", "Protocol", "Flow Duration", "Flow Byts/s", "Flow Pkts/s", "Init Fwd Win Byts"]


class LineCountingReader(io.RawIOBase):
    """Counts newline bytes as pandas reads the stream (row-count reconciliation)."""
    def __init__(self, raw):
        self.raw, self.newlines, self.nbytes, self.last = raw, 0, 0, b""
    def readable(self):
        return True
    def readinto(self, b):
        data = self.raw.read(len(b))
        n = len(data)
        if n:
            b[:n] = data
            self.newlines += data.count(b"\n"); self.nbytes += n; self.last = data[-1:]
        return n
    def physical_lines(self):
        return 0 if not self.nbytes else self.newlines + (0 if self.last == b"\n" else 1)


def list_csvs():
    """Anonymous S3 ListObjectsV2 for the processed-CSV prefix."""
    import xml.etree.ElementTree as ET
    ns = {"s3": "http://s3.amazonaws.com/doc/2006-03-01/"}
    r = requests.get(BUCKET_URL, params={"list-type": "2", "prefix": PREFIX}, timeout=60)
    r.raise_for_status()
    root = ET.fromstring(r.content)
    out = []
    for o in root.findall("s3:Contents", ns):
        k = o.find("s3:Key", ns).text
        if k.endswith(".csv"):
            out.append({"key": k, "bytes": int(o.find("s3:Size", ns).text),
                        "etag": o.find("s3:ETag", ns).text.strip('"')})
    return sorted(out, key=lambda d: d["key"])


def numeric_issues(s: pd.Series):
    """Counts for one string column: empty, non-numeric (excl. inf), +/-inf, negative."""
    empty = int((s == "").sum())
    low = s.str.lower()
    inf = int(low.isin(["inf", "infinity", "-inf", "-infinity"]).sum())
    num = pd.to_numeric(s.where(~low.isin(["inf", "infinity", "-inf", "-infinity"])), errors="coerce")
    nonnum = int(num.isna().sum()) - empty - inf
    neg = int((num < 0).sum())
    return empty, nonnum, inf, neg


def scan_file(key: str, source):
    """source: URL (str) or local path, for testing."""
    rec = {"file": key.split("/")[-1], "parse_error": ""}
    labels, protos = Counter(), Counter()
    fullchk = {c: [0, 0, 0, 0] for c in NUMERIC_FULL}
    rows = 0
    ts_min = ts_max = None
    sample_profile = None
    t0 = time.time()
    if isinstance(source, str) and source.startswith("http"):
        resp = requests.get(source, stream=True, timeout=(30, 600))
        resp.raise_for_status()
        resp.raw.decode_content = True
        raw = resp.raw
    else:
        raw = open(source, "rb")
    counter = LineCountingReader(raw)
    handle = io.BufferedReader(counter, buffer_size=1 << 22)
    try:
        header = handle.peek(1 << 16)[: 1 << 16].split(b"\n", 1)[0].decode("utf-8").rstrip("\r").split(",")
        rec["header"] = header
        reader = pd.read_csv(handle, dtype=str, keep_default_na=False, na_filter=False,
                             chunksize=CHUNK, on_bad_lines="error", encoding="utf-8")
        for i, ch in enumerate(reader):
            rows += len(ch)
            if i == 0:
                # ---- full-column profile on the first SAMPLE_ROWS rows (sample only) ----
                sm = ch.iloc[:SAMPLE_ROWS]
                sm = sm[sm["Label"] != "Label"]
                prof = {"rows": len(sm), "columns": {}}
                for c in sm.columns:
                    if c in ("Timestamp", "Label", "Flow ID", "Src IP", "Dst IP"):
                        continue
                    e, nn, inf, neg = numeric_issues(sm[c])
                    if e or nn or inf or neg:
                        prof["columns"][c] = {"empty": e, "non_numeric": nn, "inf": inf, "negative": neg}
                prof["exact_duplicate_rows"] = int(sm.duplicated().sum())
                feat = [c for c in sm.columns if c not in ("Timestamp", "Label", "Flow ID", "Src IP", "Dst IP", "Src Port")]
                prof["duplicate_rows_ignoring_timestamp"] = int(sm[feat + ["Label"]].duplicated().sum())
                fh = pd.util.hash_pandas_object(sm[feat], index=False)
                g = sm["Label"].groupby(fh.values).nunique()
                prof["feature_groups_with_conflicting_labels"] = int((g > 1).sum())
                prof["constant_columns"] = [c for c in sm.columns if sm[c].nunique() <= 1]
                sample_profile = prof
            labels.update(ch["Label"].value_counts().to_dict())
            body = ch[ch["Label"] != "Label"]                    # exclude repeated header lines
            protos.update(body["Protocol"].value_counts().to_dict())
            for c in NUMERIC_FULL:
                r = numeric_issues(body[c])
                fullchk[c] = [a + b for a, b in zip(fullchk[c], r)]
            ts = pd.to_datetime(body["Timestamp"], format="%d/%m/%Y %H:%M:%S", errors="coerce")
            if ts.notna().any():
                ts_min = min(filter(None, [ts_min, ts.min()]))
                ts_max = max(filter(None, [ts_max, ts.max()]))
            rec.setdefault("unparsed_timestamps", 0)
            rec["unparsed_timestamps"] += int(ts.isna().sum())
    except Exception as exc:
        rec["parse_error"] = f"{type(exc).__name__}: {exc}"
    while handle.read(1 << 22):
        pass
    rec["rows_parsed"] = rows
    rec["repeated_header_lines"] = int(labels.pop("Label", 0))
    rec["data_rows"] = rows - rec["repeated_header_lines"]
    rec["physical_lines"] = counter.physical_lines()
    rec["bytes_streamed"] = counter.nbytes
    rec["row_count_reconciles"] = counter.physical_lines() - 1 == rows
    rec["labels"] = dict(labels)
    rec["protocols"] = dict(protos)
    rec["full_file_numeric_checks"] = {c: dict(zip(["empty", "non_numeric", "inf", "negative"], v))
                                       for c, v in fullchk.items()}
    rec["timestamp_min"] = str(ts_min) if ts_min is not None else None
    rec["timestamp_max"] = str(ts_max) if ts_max is not None else None
    rec["sample_profile"] = sample_profile
    rec["seconds"] = round(time.time() - t0, 1)
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", default="data/processed/h2_outputs")
    ap.add_argument("--local-test", nargs="*", help="TESTING ONLY: local CSV paths instead of S3")
    a = ap.parse_args()
    out = Path(a.out_dir); out.mkdir(parents=True, exist_ok=True)
    if a.local_test:
        files = [{"key": PREFIX + Path(p).name, "bytes": Path(p).stat().st_size, "etag": "", "src": p} for p in a.local_test]
    else:
        files = list_csvs()
        for f in files:
            f["src"] = BUCKET_URL + urllib.parse.quote(f["key"])
    results = []
    for f in files:
        rec = scan_file(f["key"], f["src"])
        rec.update({"listed_bytes": f["bytes"], "etag": f["etag"],
                    "complete_download": rec["bytes_streamed"] == f["bytes"]})
        results.append(rec)
        print(f"[scan] {rec['file']}: rows={rec['data_rows']:,} repeated_headers={rec['repeated_header_lines']} "
              f"bytes_ok={rec['complete_download']} reconcile={rec['row_count_reconciles']} "
              f"labels={len(rec['labels'])} {rec['seconds']}s err={rec['parse_error'] or '-'}", flush=True)
        (out / "scan_results.json").write_text(json.dumps(results, indent=1, default=str))
    print("done")


if __name__ == "__main__":
    main()
