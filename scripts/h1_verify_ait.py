#!/usr/bin/env python3
"""
SentinelAI H-1 - AIT Netflow Data Set verification (v2, chunked).

What it does (read-only with respect to the dataset):
  1. Reads official file sizes + MD5s from the Zenodo REST API (record 13168643).
  2. Verifies every downloaded archive: byte size, MD5, ZIP CRC test (testzip).
  3. Parses label_info.txt into an exact, protocol-aware benign(0)/malicious(1) map.
  4. Streams every CSV straight out of its ZIP in chunks (no extraction, the
     original archives are never modified) and records: rows, columns, exact
     column names, label column, protocol, missing values, duplicates, parsing
     problems and exact label value counts.
  5. Writes the H-1 evidence files into --out-dir.

Unknown labels are NEVER treated as benign: anything that is not an exact
match to a label listed for that protocol in label_info.txt is "unmapped".

Run:  python scripts/h1_verify_ait.py --data-dir data/raw/ait --out-dir data/processed/h1_outputs
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import io
import json
import platform
import re
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import pandas as pd
import requests

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------
ZENODO_RECORD_ID = "13168643"                      # AIT Netflow Data Set v2 (2024-08-02)
ZENODO_DOI = "10.5281/zenodo.13168643"
ZENODO_API = f"https://zenodo.org/api/records/{ZENODO_RECORD_ID}"
NETWORKS = ["fox", "harrison", "russellmitchell", "santos",
            "shaw", "wardbeck", "wheeler", "wilson"]

# MD5s hardcoded in the ORIGINAL sentinelai_ait_verify.py, kept only so the
# report can show which of them were transcribed correctly.
SCRIPT_V1_MD5 = {
    "fox_netflows.zip": "d3024ef6033fbd45982464f6b6f50984",
    "harrison_netflows.zip": "840224491fb31d548e7ee0ecbd951db5",
    "russellmitchell_netflows.zip": "290aa5b8a0b9d0515b7e99329c467364",  # typo
    "santos_netflows.zip": "e217db1c0307a8966db9e79609789fcb",
    "shaw_netflows.zip": "25c5a62572d37f088353cf7bbd58f590",
    "wardbeck_netflows.zip": "3a73afcaef00a1bbe53f1c39060c2f17",
    "wheeler_netflows.zip": "2c45193c0babc8ec45f356f3e39118a6",
    "wilson_netflows.zip": "2c10183cf7aca03e9fb80408a360f34c",
}

CHUNK_ROWS = 200_000                                # rows per pandas chunk (RAM bound)
NA_TOKENS = ["NA", "N/A", "nan", "NaN", "null", "NULL", "None", "-"]  # reported, not converted
LABEL_COLUMN = "label"
# Columns that only exist in TCP Tstat logs; used to cross-check the protocol
# inferred from the file name against the actual schema.
TCP_ONLY_MARKERS = ("c_syn_cnt", "c_fin_cnt", "c_rst_cnt")


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def md5_file(path: Path) -> str:
    """MD5 of a file, read in 1 MiB blocks."""
    h = hashlib.md5()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def clean_column(raw: str) -> str:
    """Tstat headers look like '#15#c_ip:1' or 'c_port:2'.
    Return the bare field name ('c_ip', 'c_port') for readability.
    The raw names are ALWAYS reported as well."""
    name = re.sub(r"^#(\d+#)?", "", raw)
    name = re.sub(r":\d+$", "", name)
    return name


class LineCountingReader(io.RawIOBase):
    """Wraps a binary stream and counts newline bytes as pandas reads it, so we
    can reconcile pandas' row count against the physical line count in ONE pass."""

    def __init__(self, raw):
        self.raw = raw
        self.newlines = 0
        self.nbytes = 0
        self.last_byte = b""

    def readable(self):
        return True

    def readinto(self, b):
        data = self.raw.read(len(b))
        n = len(data)
        if n:
            b[:n] = data
            self.newlines += data.count(b"\n")
            self.nbytes += n
            self.last_byte = data[-1:]
        return n

    def physical_lines(self) -> int:
        if self.nbytes == 0:
            return 0
        return self.newlines + (0 if self.last_byte == b"\n" else 1)


def fetch_official_metadata():
    """Return {filename: {'md5':..., 'bytes':...}} from Zenodo, plus record info."""
    r = requests.get(ZENODO_API, timeout=60)
    r.raise_for_status()
    d = r.json()
    files = {}
    for f in d.get("files", []):
        algo, _, value = f["checksum"].partition(":")
        if algo != "md5":
            raise RuntimeError(f"Unexpected checksum algorithm {algo} for {f['key']}")
        files[f["key"]] = {"md5": value.lower(), "bytes": int(f["size"])}
    info = {"record_id": ZENODO_RECORD_ID, "doi": d.get("doi"),
            "title": d["metadata"].get("title"),
            "publication_date": d["metadata"].get("publication_date"),
            "api_url": ZENODO_API,
            "retrieved_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")}
    return files, info


def parse_label_info(path: Path):
    """Parse the four sections 'Benign/Malicious labels in TCP/UDP:'.
    Exact strings are kept (only the line terminator is removed).
    Returns {protocol: {label: 0|1}} and a list of problems found in the file."""
    text = path.read_bytes().decode("utf-8-sig")
    mapping: dict[str, dict[str, int]] = {"TCP": {}, "UDP": {}}
    problems = []
    current = None
    seen_sections = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if line.strip() == "":
            continue
        m = re.fullmatch(r"(Benign|Malicious) labels in (TCP|UDP):", line.strip())
        if m:
            current = (m.group(2), 0 if m.group(1) == "Benign" else 1)
            seen_sections.append(line.strip())
            continue
        if current is None:
            problems.append(f"line {lineno}: text before first section: {line!r}")
            continue
        if line != line.strip():
            problems.append(f"line {lineno}: label has leading/trailing whitespace: {line!r}")
        proto, y = current
        if line in mapping[proto] and mapping[proto][line] != y:
            problems.append(f"line {lineno}: {line!r} listed as both benign and malicious in {proto}")
        mapping[proto][line] = y
    if len(seen_sections) != 4:
        problems.append(f"expected 4 sections, found {len(seen_sections)}: {seen_sections}")
    return mapping, problems


# --------------------------------------------------------------------------
# Per-CSV inspection (streamed, chunked)
# --------------------------------------------------------------------------
def inspect_csv(zf: zipfile.ZipFile, member: str, protocol: str, label_map: dict):
    """Stream one CSV out of the ZIP and return (file_record, label_counter)."""
    rec = {"parse_error": ""}
    label_counts: Counter = Counter()
    row_hashes, feat_hashes, ybin = [], [], []
    missing = None
    na_tok = None
    rows = 0
    ts_min, ts_max = np.inf, -np.inf
    sample_types = {}

    with zf.open(member) as raw:
        counter = LineCountingReader(raw)
        handle = io.BufferedReader(counter, buffer_size=1 << 20)
        try:
            reader = pd.read_csv(handle, dtype=str, keep_default_na=False, na_filter=False,
                                 chunksize=CHUNK_ROWS, on_bad_lines="error",
                                 encoding="utf-8", skip_blank_lines=False)
            for i, chunk in enumerate(reader):
                if i == 0:
                    raw_cols = [str(c) for c in chunk.columns]
                    rec["columns_raw"] = raw_cols
                    rec["columns_clean"] = [clean_column(c) for c in raw_cols]
                    if len(set(raw_cols)) != len(raw_cols):
                        rec["parse_error"] += "duplicate column names; "
                    # Type profile on the first chunk only (cheap; labelled as a sample).
                    for c in raw_cols:
                        s = chunk[c]
                        nonempty = s[s != ""]
                        num = pd.to_numeric(nonempty, errors="coerce")
                        n_bad = int(num.isna().sum())
                        sample_types[clean_column(c)] = (
                            "empty" if len(nonempty) == 0 else
                            "numeric" if n_bad == 0 else
                            "text" if n_bad == len(nonempty) else
                            f"mixed({n_bad} non-numeric of {len(nonempty)})")
                    missing = pd.Series(0, index=raw_cols, dtype="int64")
                    na_tok = pd.Series(0, index=raw_cols, dtype="int64")
                    ts_col = next((c for c in raw_cols if clean_column(c) in ("first", "c_first_abs")), None)
                    rec["time_column"] = clean_column(ts_col) if ts_col else ""

                rows += len(chunk)
                missing += (chunk == "").sum()                     # truly empty cells
                na_tok += chunk.isin(NA_TOKENS).sum()              # textual NA-like tokens

                # Exact label value counts (no stripping, no case folding).
                labels = chunk[LABEL_COLUMN]
                label_counts.update(labels.value_counts().to_dict())

                # Row hashes for duplicate detection across the whole file.
                row_hashes.append(pd.util.hash_pandas_object(chunk, index=False).to_numpy())
                feat_hashes.append(pd.util.hash_pandas_object(
                    chunk.drop(columns=[LABEL_COLUMN]), index=False).to_numpy())
                ybin.append(labels.map(label_map).fillna(-1).to_numpy(dtype=np.int8))

                if ts_col:
                    t = pd.to_numeric(chunk[ts_col], errors="coerce")
                    if t.notna().any():
                        ts_min = min(ts_min, float(t.min()))
                        ts_max = max(ts_max, float(t.max()))
        except Exception as exc:                                   # record, never hide
            rec["parse_error"] += f"{type(exc).__name__}: {exc}"

        # Drain anything pandas did not consume so the line count is complete.
        while handle.read(1 << 20):
            pass

    rec["rows"] = rows
    rec["physical_lines_incl_header"] = counter.physical_lines()
    rec["uncompressed_bytes_read"] = counter.nbytes
    rec["row_count_reconciles"] = (counter.physical_lines() - 1 == rows)
    rec["missing"] = missing
    rec["na_tokens"] = na_tok
    rec["sample_types"] = sample_types
    rec["time_min"] = ts_min if np.isfinite(ts_min) else None
    rec["time_max"] = ts_max if np.isfinite(ts_max) else None

    if rows:
        rh = np.concatenate(row_hashes)
        fh = np.concatenate(feat_hashes)
        yb = np.concatenate(ybin)
        rec["exact_duplicate_rows"] = int(rows - np.unique(rh).size)
        # Identical feature values (all columns except label) but different binary label.
        g = pd.DataFrame({"f": fh, "y": yb}).groupby("f")["y"].agg(["nunique", "size"])
        conflict = g[g["nunique"] > 1]
        rec["conflicting_label_groups"] = int(len(conflict))
        rec["rows_in_conflicting_label_groups"] = int(conflict["size"].sum())
    else:
        rec["exact_duplicate_rows"] = 0
        rec["conflicting_label_groups"] = 0
        rec["rows_in_conflicting_label_groups"] = 0
    return rec, label_counts


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", default="data/raw/ait")
    ap.add_argument("--out-dir", default="data/processed/h1_outputs")
    ap.add_argument("--offline-test-metadata", default=None,
                    help="TESTING ONLY: JSON file replacing the Zenodo API call")
    args = ap.parse_args()
    downloads = Path(args.data_dir).resolve() / "downloads"
    out = Path(args.out_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)

    # ---- 1. Official metadata ------------------------------------------------
    if args.offline_test_metadata:                    # used only for local unit testing
        official = json.loads(Path(args.offline_test_metadata).read_text())
        record_info = {"record_id": "TEST", "doi": "TEST", "title": "TEST", "publication_date": "",
                       "api_url": "", "retrieved_utc": ""}
    else:
        official, record_info = fetch_official_metadata()
    print(f"[zenodo] {record_info['title']} | doi {record_info['doi']} | {len(official)} files listed")

    # ---- 2. Archive verification (all archives checked; no early abort) -----
    arch_rows = []
    verified = {}
    for fname in ["label_info.txt"] + [f"{n}_netflows.zip" for n in NETWORKS]:
        p = downloads / fname
        off = official.get(fname, {})
        row = {"file": fname,
               "network": fname.replace("_netflows.zip", "") if fname.endswith(".zip") else "",
               "official_md5": off.get("md5", ""), "official_bytes": off.get("bytes", ""),
               "exists": p.exists()}
        if p.exists():
            row["actual_md5"] = md5_file(p)
            row["actual_bytes"] = p.stat().st_size
        else:
            row["actual_md5"], row["actual_bytes"] = "", ""
        row["md5_match"] = bool(off) and row["actual_md5"] == off.get("md5")
        row["size_match"] = bool(off) and row["actual_bytes"] == off.get("bytes")
        row["zip_testzip"] = ""
        row["zip_members"] = ""
        zip_ok = True
        if fname.endswith(".zip") and p.exists():
            try:
                with zipfile.ZipFile(p) as zf:
                    bad = zf.testzip()                     # reads every member, checks CRC-32
                    row["zip_testzip"] = "OK (all CRCs valid)" if bad is None else f"BAD member: {bad}"
                    zip_ok = bad is None
                    row["zip_members"] = json.dumps(
                        [{"name": i.filename, "uncompressed_bytes": i.file_size} for i in zf.infolist()])
            except zipfile.BadZipFile as exc:
                row["zip_testzip"] = f"BadZipFile: {exc}"
                zip_ok = False
        elif fname.endswith(".zip"):
            zip_ok = False
        row["script_v1_expected_md5"] = SCRIPT_V1_MD5.get(fname, "")
        row["script_v1_md5_equals_official"] = (SCRIPT_V1_MD5.get(fname) == off.get("md5")) if fname in SCRIPT_V1_MD5 else ""
        row["verified"] = bool(row["md5_match"] and row["size_match"] and zip_ok)
        verified[fname] = row["verified"]
        arch_rows.append(row)
        print(f"[archive] {fname:<30} md5_match={row['md5_match']} size_match={row['size_match']} "
              f"zip={row['zip_testzip'] or 'n/a'} -> verified={row['verified']}")
    pd.DataFrame(arch_rows).to_csv(out / "archive_checksums.csv", index=False)

    if not verified["label_info.txt"]:
        sys.exit("label_info.txt failed verification - stopping before label mapping.")

    # ---- 3. Official label mapping -------------------------------------------
    label_map, label_problems = parse_label_info(downloads / "label_info.txt")
    for proto in ("TCP", "UDP"):
        b = sum(1 for v in label_map[proto].values() if v == 0)
        m = sum(1 for v in label_map[proto].values() if v == 1)
        print(f"[labels] {proto}: {b} benign, {m} malicious labels in label_info.txt")
    for pr in label_problems:
        print("[labels][problem]", pr)

    # ---- 4. CSV inspection ---------------------------------------------------
    file_rows, label_rows = [], []
    schema_ids: dict[tuple, str] = {}
    observed = {"TCP": Counter(), "UDP": Counter()}
    for net in NETWORKS:
        zname = f"{net}_netflows.zip"
        if not verified.get(zname):
            print(f"[skip] {zname} not verified - its CSVs are NOT inspected or counted")
            continue
        with zipfile.ZipFile(downloads / zname) as zf:
            members = [i.filename for i in zf.infolist() if i.filename.lower().endswith(".csv")]
            for member in sorted(members):
                base = Path(member).name.lower()
                protocol = "UDP" if base.startswith("udp") else "TCP" if base.startswith("tcp") else "UNKNOWN"
                completeness = "nocomplete" if "nocomplete" in base else "complete"
                pmap = label_map.get(protocol, {})
                rec, counts = inspect_csv(zf, member, protocol, pmap)
                cols = rec.get("columns_raw", [])
                clean = rec.get("columns_clean", [])
                sid = schema_ids.setdefault(tuple(cols), f"S{len(schema_ids) + 1}")

                # Protocol cross-check: TCP files must have TCP-only fields, UDP files must not.
                has_tcp_fields = all(m in clean for m in TCP_ONLY_MARKERS)
                proto_check = ("consistent" if (protocol == "TCP") == has_tcp_fields
                               else "INCONSISTENT with schema")

                normal = suspicious = unmapped = 0
                strip_variants = 0
                for value, n in sorted(counts.items(), key=lambda kv: -kv[1]):
                    y = pmap.get(value)
                    if y is None:
                        other = "UDP" if protocol == "TCP" else "TCP"
                        if value in label_map.get(other, {}):
                            cat = f"not listed for {protocol} (listed under {other})"
                        elif value.strip() in pmap:
                            cat = "unmapped: matches an official label only after whitespace strip"
                            strip_variants += n
                        else:
                            cat = "unmapped: not in label_info.txt"
                        unmapped += n
                    elif y == 0:
                        cat = "benign (label_info.txt)"; normal += n
                    else:
                        cat = "malicious (label_info.txt)"; suspicious += n
                    observed[protocol][value] += n
                    label_rows.append({"network": net, "file": Path(member).name, "protocol": protocol,
                                       "original_label": value, "official_category": cat,
                                       "binary_label": "" if y is None else y, "flow_count": n})

                miss = rec["missing"] if rec.get("missing") is not None else pd.Series(dtype="int64")
                natk = rec["na_tokens"] if rec.get("na_tokens") is not None else pd.Series(dtype="int64")
                file_rows.append({
                    "network": net, "file": Path(member).name, "protocol": protocol,
                    "flow_completeness": completeness,
                    "protocol_vs_schema_check": proto_check,
                    "rows": rec["rows"],
                    "physical_lines_incl_header": rec["physical_lines_incl_header"],
                    "row_count_reconciles": rec["row_count_reconciles"],
                    "n_columns": len(cols), "schema_id": sid,
                    "label_column": LABEL_COLUMN if LABEL_COLUMN in cols else "NOT FOUND",
                    "columns_raw_json": json.dumps(cols),
                    "columns_clean_json": json.dumps(clean),
                    "empty_cells_total": int(miss.sum()),
                    "columns_with_empty_cells": int((miss > 0).sum()),
                    "empty_cells_by_column_json": json.dumps({clean_column(k): int(v) for k, v in miss.items() if v}),
                    "na_token_cells_total": int(natk.sum()),
                    "na_tokens_by_column_json": json.dumps({clean_column(k): int(v) for k, v in natk.items() if v}),
                    "exact_duplicate_rows": rec["exact_duplicate_rows"],
                    "conflicting_label_groups": rec["conflicting_label_groups"],
                    "rows_in_conflicting_label_groups": rec["rows_in_conflicting_label_groups"],
                    "distinct_labels": len(counts),
                    "normal_flows": normal, "suspicious_flows": suspicious, "unmapped_flows": unmapped,
                    "labels_matching_only_after_strip": strip_variants,
                    "label_counts_sum_equals_rows": (normal + suspicious + unmapped) == rec["rows"],
                    "time_column": rec.get("time_column", ""),
                    "time_min": rec["time_min"], "time_max": rec["time_max"],
                    "mixed_or_text_columns_first_chunk_json": json.dumps(
                        {k: v for k, v in rec["sample_types"].items() if v != "numeric"}),
                    "uncompressed_bytes_read": rec["uncompressed_bytes_read"],
                    "parse_error": rec["parse_error"],
                })
                print(f"[csv] {net}/{Path(member).name}: rows={rec['rows']:,} cols={len(cols)} "
                      f"schema={sid} normal={normal:,} suspicious={suspicious:,} unmapped={unmapped:,} "
                      f"dups={rec['exact_duplicate_rows']:,} reconcile={rec['row_count_reconciles']} "
                      f"err={rec['parse_error'] or '-'}")

    fq = pd.DataFrame(file_rows)
    fq.to_csv(out / "csv_file_quality_report.csv", index=False)
    pd.DataFrame(label_rows).to_csv(out / "label_counts_by_file.csv", index=False)

    # ---- 5. Per-network attack counts ----------------------------------------
    net_rows = []
    for net in NETWORKS:
        d = fq[fq["network"] == net] if len(fq) else fq
        row = {"network": net, "archive_verified": verified.get(f"{net}_netflows.zip", False),
               "csv_files": len(d)}
        for key, sub in (("all", d),
                         ("tcp_complete", d[(d.protocol == "TCP") & (d.flow_completeness == "complete")]),
                         ("tcp_nocomplete", d[(d.protocol == "TCP") & (d.flow_completeness == "nocomplete")]),
                         ("tcp", d[d.protocol == "TCP"]), ("udp", d[d.protocol == "UDP"])):
            pre = "" if key == "all" else f"{key}_"
            row[f"{pre}total_flows"] = int(sub["rows"].sum())
            row[f"{pre}normal_flows"] = int(sub["normal_flows"].sum())
            row[f"{pre}suspicious_flows"] = int(sub["suspicious_flows"].sum())
            row[f"{pre}unmapped_flows"] = int(sub["unmapped_flows"].sum())
        row["suspicious_pct"] = round(100 * row["suspicious_flows"] / row["total_flows"], 4) if row["total_flows"] else None
        row["counts_reconcile"] = (row["normal_flows"] + row["suspicious_flows"] + row["unmapped_flows"]
                                   == row["total_flows"]) and len(d) > 0 and bool(d["row_count_reconciles"].all())
        net_rows.append(row)
    nt = pd.DataFrame(net_rows)
    total = {"network": "TOTAL", "archive_verified": bool(nt["archive_verified"].all()),
             "csv_files": int(nt["csv_files"].sum())}
    for c in nt.columns:
        if c.endswith("_flows"):
            total[c] = int(nt[c].sum())
    total["suspicious_pct"] = round(100 * total["suspicious_flows"] / total["total_flows"], 4) if total["total_flows"] else None
    total["counts_reconcile"] = bool(nt["counts_reconcile"].all())
    nt = pd.concat([nt, pd.DataFrame([total])], ignore_index=True)
    nt.to_csv(out / "ait_network_attack_counts.csv", index=False)

    # ---- 6. label_mapping.json -------------------------------------------------
    mapping_doc = {
        "source_file": "label_info.txt",
        "source_md5": next(r["actual_md5"] for r in arch_rows if r["file"] == "label_info.txt"),
        "source_record": record_info,
        "encoding": {"Normal": 0, "Suspicious": 1},
        "rules": [
            "Mapping is protocol-aware: TCP CSVs use the TCP sections, UDP CSVs use the UDP sections.",
            "Matching is exact (case- and whitespace-sensitive) against label_info.txt lines.",
            "Benign labels -> 0 (Normal); malicious labels -> 1 (Suspicious).",
            "Any other value is UNMAPPED and is never treated as benign.",
        ],
        "label_info_parse_problems": label_problems,
        "TCP": {"benign_0": sorted(k for k, v in label_map["TCP"].items() if v == 0),
                "malicious_1": sorted(k for k, v in label_map["TCP"].items() if v == 1)},
        "UDP": {"benign_0": sorted(k for k, v in label_map["UDP"].items() if v == 0),
                "malicious_1": sorted(k for k, v in label_map["UDP"].items() if v == 1)},
        "observed_in_csvs": {
            p: {"unmapped_labels": {k: v for k, v in observed[p].items() if k not in label_map[p]},
                "official_labels_never_observed": sorted(k for k in label_map[p] if k not in observed[p])}
            for p in ("TCP", "UDP")},
    }
    (out / "label_mapping.json").write_text(json.dumps(mapping_doc, indent=2, ensure_ascii=False), encoding="utf-8")

    # ---- 7. Run manifest (reproducibility) ------------------------------------
    manifest = {"run_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
                "script": Path(__file__).name, "script_md5": md5_file(Path(__file__)),
                "python": platform.python_version(), "pandas": pd.__version__, "numpy": np.__version__,
                "chunk_rows": CHUNK_ROWS, "zenodo": record_info,
                "schemas": {sid: {"n_columns": len(cols), "columns_raw": list(cols)} for cols, sid in schema_ids.items()}}
    (out / "run_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"\nDone. Outputs in {out}")


if __name__ == "__main__":
    main()
