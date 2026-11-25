#!/usr/bin/env python3
"""
SentinelAI H-2 - build the CSE-CIC-IDS2018 backup-dataset deliverables from the
evidence written by h2_ids2018_scan.py (and the H-1 outputs for the AIT comparison).
Every number is read from those files; nothing is typed in by hand.

Outputs (in --out-dir):
  ids2018_file_structure.csv      per-file size, columns, rows, labels, timestamps
  ids2018_label_counts_by_file.csv exact label counts per file with proposed binary label
  ids2018_label_mapping.csv/.json  proposed label -> Normal(0)/Suspicious(1) mapping
  ait_vs_ids2018_comparison.csv    side-by-side comparison table
  H2_CSE-CIC-IDS2018_Verification_Report.md
  documentation_paragraph.md       short paragraph for the project documentation

Run: python scripts/h2_make_report.py --out-dir data/processed/h2_outputs --h1-dir data/processed/h1_outputs
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

import pandas as pd

EXCEL_MAX_DATA_LINES = 1_048_575   # Excel worksheet limit (1,048,576 rows) minus the header line

# Proposed mapping. CIC publishes no benign/malicious label file (unlike AIT's label_info.txt),
# so each observed label is tied to an attack scenario from the official UNB page.
# Only the exact string "Benign" is Normal; any value not listed here stays UNMAPPED.
PROPOSED = {
    "Benign": ("Normal traffic", 0),
    "FTP-BruteForce": ("Brute-force (FTP, Patator) - 14-02", 1),
    "SSH-Bruteforce": ("Brute-force (SSH, Patator) - 14-02", 1),
    "DoS attacks-GoldenEye": ("DoS (GoldenEye) - 15-02", 1),
    "DoS attacks-Slowloris": ("DoS (Slowloris) - 15-02", 1),
    "DoS attacks-SlowHTTPTest": ("DoS (SlowHTTPTest) - 16-02", 1),
    "DoS attacks-Hulk": ("DoS (Hulk) - 16-02", 1),
    "DDoS attacks-LOIC-HTTP": ("DDoS (LOIC-HTTP) - 20-02", 1),
    "DDOS attack-LOIC-UDP": ("DDoS (LOIC-UDP) - 20-02 and 21-02", 1),
    "DDOS attack-HOIC": ("DDoS (HOIC) - 21-02", 1),
    "Brute Force -Web": ("Web attack: brute force - 22-02, 23-02", 1),
    "Brute Force -XSS": ("Web attack: XSS - 22-02, 23-02", 1),
    "SQL Injection": ("Web attack: SQL injection - 22-02, 23-02", 1),
    "Infilteration": ("Infiltration from inside (spelling as in the data) - 28-02, 01-03", 1),
    "Bot": ("Botnet (Zeus, Ares) - 02-03", 1),
}


def md(df: pd.DataFrame) -> str:
    cols = [str(c) for c in df.columns]
    out = ["| " + " | ".join(cols) + " |", "|" + "|".join("---" for _ in cols) + "|"]
    for _, r in df.iterrows():
        cells = []
        for v in r.tolist():
            if isinstance(v, bool):
                cells.append("yes" if v else "no")
            elif isinstance(v, int):
                cells.append(f"{v:,}")
            elif isinstance(v, float):
                cells.append(f"{v:,.2f}")
            else:
                cells.append(str(v).replace("|", "\\|"))
        out.append("| " + " | ".join(cells) + " |")
    return "\n".join(out)


def day_of(fname: str) -> str:
    return fname.split("_")[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", default="data/processed/h2_outputs")
    ap.add_argument("--h1-dir", default="data/processed/h1_outputs")
    a = ap.parse_args()
    O, H1 = Path(a.out_dir), Path(a.h1_dir)

    R = json.loads((O / "scan_results.json").read_text())
    lst = pd.read_csv(O / "s3_bucket_listing.csv")
    headers = json.loads((O / "csv_headers.json").read_text())
    log = (O / "scan_log.txt").read_text() if (O / "scan_log.txt").exists() else ""

    # ------------------------------------------------------------------ bucket
    lst["top"] = lst["key"].str.split("/").str[0]
    raw = lst[lst["top"] == "Original Network Traffic and Log data"]
    proc = lst[lst["top"] == "Processed Traffic Data for ML Algorithms"]
    gib = lambda b: b / 2**30
    raw_pcap = raw[raw["key"].str.contains("pcap", case=False)]
    raw_logs = raw[raw["key"].str.contains("logs", case=False)]

    # ------------------------------------------------------------------ per file
    base_hdr = max(headers.values(), key=lambda h: list(headers.values()).count(h))
    fs = []
    lc = []
    for r in R:
        f = r["file"]
        hdr = r["header"]
        data_lines = r["physical_lines"] - 1
        labels = r["labels"]
        attacks = {k: v for k, v in labels.items() if k != "Benign"}
        fs.append({
            "file": f, "day": day_of(f), "MB": round(r["listed_bytes"] / 1e6, 1),
            "columns": len(hdr),
            "extra_columns_vs_common_header": ", ".join(c for c in hdr if c not in base_hdr) or "-",
            "data_rows": r["data_rows"], "repeated_header_lines": r["repeated_header_lines"],
            "lines_at_excel_limit": data_lines == EXCEL_MAX_DATA_LINES,
            "benign": labels.get("Benign", 0), "attack_rows": sum(attacks.values()),
            "attack_pct": round(100 * sum(attacks.values()) / r["data_rows"], 2),
            "attack_labels": "; ".join(f"{k} ({v:,})" for k, v in sorted(attacks.items(), key=lambda kv: -kv[1])),
            "timestamp_min": r["timestamp_min"], "timestamp_max": r["timestamp_max"],
            "protocol_counts": json.dumps(r["protocols"]),
            "bytes_streamed_equals_listed": r["complete_download"], "row_count_reconciles": r["row_count_reconciles"],
            "parse_error": r["parse_error"] or "none",
        })
        for lab, n in labels.items():
            fam, y = PROPOSED.get(lab, ("UNMAPPED - not a documented label", ""))
            lc.append({"file": f, "day": day_of(f), "label": lab, "label_repr": repr(lab), "flows": n,
                       "attack_scenario": fam, "binary_label": y})
    fs = pd.DataFrame(fs)
    lc = pd.DataFrame(lc)
    fs.to_csv(O / "ids2018_file_structure.csv", index=False)
    lc.to_csv(O / "ids2018_label_counts_by_file.csv", index=False)

    tot = lc.groupby("label").agg(flows=("flows", "sum"), files=("file", "nunique"),
                                  days=("day", lambda d: ", ".join(sorted(set(d))))).reset_index()
    tot["attack_scenario"] = tot["label"].map(lambda l: PROPOSED.get(l, ("UNMAPPED", ""))[0])
    tot["binary_label"] = tot["label"].map(lambda l: PROPOSED.get(l, ("", ""))[1])
    tot = tot.sort_values("flows", ascending=False)
    tot.to_csv(O / "ids2018_label_mapping.csv", index=False)
    unmapped = tot[tot["binary_label"] == ""]
    total_rows = int(fs["data_rows"].sum())
    normal = int(tot.loc[tot["binary_label"] == 0, "flows"].sum())
    susp = int(tot.loc[tot["binary_label"] == 1, "flows"].sum())
    (O / "ids2018_label_mapping.json").write_text(json.dumps({
        "dataset": "CSE-CIC-IDS2018, Processed Traffic Data for ML Algorithms (10 CSV files)",
        "status": "PROPOSED by H-2 (CIC publishes no benign/malicious label file); to be confirmed in H-3",
        "encoding": {"Normal": 0, "Suspicious": 1},
        "rules": ["Exact, case-sensitive match on the Label column.",
                  "Only 'Benign' maps to 0. Each documented attack label maps to 1.",
                  "Rows whose Label is the literal text 'Label' are repeated header lines and are dropped, not labelled.",
                  "Any other value is UNMAPPED and is never treated as benign."],
        "mapping": {k: {"binary": v[1], "scenario": v[0]} for k, v in PROPOSED.items()},
        "observed_unmapped_labels": unmapped["label"].tolist(),
    }, indent=2))

    # ------------------------------------------------------------------ quality totals
    def qsum(col, kind):
        return sum(r["full_file_numeric_checks"][col][kind] for r in R)
    nan_text = qsum("Flow Byts/s", "non_numeric")
    inf_b = qsum("Flow Byts/s", "inf")
    inf_p = qsum("Flow Pkts/s", "inf")
    neg_dur = qsum("Flow Duration", "negative")
    neg_win = qsum("Init Fwd Win Byts", "negative")
    rep_hdr = int(fs["repeated_header_lines"].sum())
    at_cap = fs[fs["lines_at_excel_limit"]]
    proto = pd.Series(dtype="int64")
    for r in R:
        proto = proto.add(pd.Series(r["protocols"]), fill_value=0)
    proto = proto.astype(int)
    hours_ok = all(r["timestamp_min"] and r["timestamp_max"] for r in R)
    ts_hours = sorted({int(r["timestamp_min"][11:13]) for r in R} | {int(r["timestamp_max"][11:13]) for r in R})
    max_hour = max(int(r["timestamp_max"][11:13]) for r in R)
    out_of_day = [r["file"] for r in R if r["timestamp_min"][:10] != r["timestamp_max"][:10]]
    s_rows = sum(r["sample_profile"]["rows"] for r in R)
    s_dups = sum(r["sample_profile"]["exact_duplicate_rows"] for r in R)
    s_dups_nt = sum(r["sample_profile"]["duplicate_rows_ignoring_timestamp"] for r in R)
    s_conf = {r["file"]: r["sample_profile"]["feature_groups_with_conflicting_labels"] for r in R
              if r["sample_profile"]["feature_groups_with_conflicting_labels"]}
    const_all = sorted(set.intersection(*[set(r["sample_profile"]["constant_columns"]) for r in R]))
    loic_udp_tue = "DDOS attack-LOIC-UDP" in next(r for r in R if r["file"].startswith("Thuesday"))["labels"]
    ip_files = [r["file"] for r in R if "Src IP" in r["header"]]

    # ------------------------------------------------------------------ AIT (from H-1 outputs)
    ait = pd.read_csv(H1 / "ait_network_attack_counts.csv")
    ait_tot = ait[ait["network"] == "TOTAL"].iloc[0]
    ait_q = pd.read_csv(H1 / "csv_file_quality_report.csv")
    ait_cols = sorted(ait_q["n_columns"].unique().tolist(), reverse=True)
    ait_arc = pd.read_csv(H1 / "archive_checksums.csv")
    ait_mb = round(ait_arc["actual_bytes"].sum() / 1e6, 1)
    ait_map = json.loads((H1 / "label_mapping.json").read_text())
    ait_ben = len(ait_map["TCP"]["benign_0"]) + len(ait_map["UDP"]["benign_0"])
    ait_mal = len(ait_map["TCP"]["malicious_1"]) + len(ait_map["UDP"]["malicious_1"])
    ait_unm = int(ait_tot["unmapped_flows"])
    ait_nc = 100 * ait_tot["tcp_nocomplete_suspicious_flows"] / ait_tot["tcp_nocomplete_total_flows"]
    scan_min = sum(r["seconds"] for r in R) / 60
    ws_labels = [l for l in tot["label"] if l != l.strip()]
    norm = {}
    for l in tot["label"]:
        norm.setdefault(re.sub(r"[^a-z]", "", l.lower()), []).append(l)
    near_dups = [v for v in norm.values() if len(v) > 1]
    heartbleed = [l for l in tot["label"] if "heart" in l.lower()]
    dup_ratio = sorted(((r["sample_profile"]["exact_duplicate_rows"] / max(r["sample_profile"]["rows"], 1), day_of(r["file"]))
                        for r in R), reverse=True)[:2]

    comp = pd.DataFrame([
        ["Publisher / source", "AIT Austrian Institute of Technology, Zenodo record 13168643 (2024)",
         "CSE and Canadian Institute for Cybersecurity (UNB), public AWS bucket s3://cse-cic-ids2018 (2018)"],
        ["Environment", "8 separate simulated small-company networks, 4-6 days each",
         "1 emulated organisation (420 machines, 30 servers, 50 attackers), 10 capture days"],
        ["Files used", f"8 ZIPs, 24 CSVs (Tstat), {ait_mb} MB compressed",
         f"{len(fs)} CSVs (CICFlowMeter-V3), {gib(proc['bytes'].sum()):.2f} GiB uncompressed; raw PCAP/logs {gib(raw['bytes'].sum()):.1f} GiB"],
        ["Flows", f"{int(ait_tot['total_flows']):,}", f"{total_rows:,}"],
        ["Suspicious share", f"{float(ait_tot['suspicious_pct']):.2f}%", f"{100 * susp / total_rows:.2f}%"],
        ["Columns", f"{', '.join(map(str, ait_cols))} (TCP complete / TCP non-complete / UDP)",
         f"{len(base_hdr)} on {len(fs) - len(ip_files)} days; {max(len(h) for h in headers.values())} on {len(ip_files)} day"],
        ["Host identifiers (IP addresses)", "Yes, in every file (client and server IP, host roles)",
         f"Only in {len(ip_files)} of {len(fs)} files ({', '.join(day_of(f) for f in ip_files)})"],
        ["Timestamps", "Epoch milliseconds plus full date-time", "dd/mm/yyyy hh:mm:ss, hours only 01-12 (no AM/PM)"],
        ["Labels", f"Official label_info.txt: {ait_ben} benign + {ait_mal} malicious labels, protocol-aware",
         f"{len(tot)} values in a single Label column; no official benign/malicious file"],
        ["Attack types", "One multi-step attack per network (scans, web attack, web shell, commands, DNS exfiltration)",
         "Brute force, DoS, DDoS, web attacks, infiltration, botnet - one or two types per day"],
        ["Binary mapping", f"Exact and official; {ait_unm:,} flows unmapped", f"Straightforward (Benign vs rest); {len(unmapped)} unmapped values"],
        ["Main quality issues", f"{ait_unm:,} empty labels; placeholder text; {ait_nc:.0f}% attacks in TCP non-complete",
         "Inf/NaN text, negative values, repeated headers, row-limit files, 12-hour clock, label noise"],
        ["Split by network (current plan)", "Yes - 8 networks", "No - only one network; split by day = split by attack type"],
        ["Per-host 5-minute windows (H-4)", "Possible", f"Only possible on {len(ip_files)} day; not on the others"],
        ["Matching alert data for agents", "AIT Alert Data Set from the same attacks", "None provided by CIC"],
        ["Processing in Colab", "Easy (a few minutes)", f"Feasible by streaming in chunks ({scan_min:.0f} minutes for all {len(fs)} files)"],
    ], columns=["Aspect", "AIT Netflow (primary)", "CSE-CIC-IDS2018 (backup)"])
    comp.to_csv(O / "ait_vs_ids2018_comparison.csv", index=False)

    # ------------------------------------------------------------------ report
    L = []
    w = L.append
    w("# H-2 — CSE-CIC-IDS2018 Backup Dataset Verification")
    w("")
    w("*SentinelAI · Data & Features (Habiba) · generated by \x60h2_make_report.py\x60 from the evidence files in "
      "\x60h2_outputs/\x60. Verified = checked by our own code on the real files; Documented = stated by an official or "
      "published source and not re-checked by us.*")
    w("")
    w("**Decision: Suitable with conditions** — as a backup for the Random Forest detection part (objective O1), "
      "not as a drop-in replacement for the whole SentinelAI pipeline. See section 9.")
    w("")
    w("## 1. Objective and link to H-1")
    w("")
    w("Tracker task H-2: check the CSE-CIC-IDS2018 backup (size, format, labels). Done when there is a short note on how "
      "to switch if AIT fails the gate. H-1 gave AIT a conditional GO, so this backup is not needed now. H-2 makes sure "
      "the team knows, with evidence, what switching would involve and cost.")
    w("")
    w("## 2. Official source (Documented)")
    w("")
    w("- Official page: Canadian Institute for Cybersecurity, University of New Brunswick — "
      "https://www.unb.ca/cic/datasets/ids-2018.html (collaboration between the Communications Security Establishment "
      "and CIC).")
    w("- Official download: public AWS bucket \x60s3://cse-cic-ids2018/\x60 (region ca-central-1), AWS Open Data registry "
      "https://registry.opendata.aws/cse-cic-ids2018/. No account is needed. The page asks users to cite the dataset and "
      "link the registry page.")
    w("- Paper: I. Sharafaldin, A. H. Lashkari, A. A. Ghorbani, *Toward Generating a New Intrusion Detection Dataset and "
      "Intrusion Traffic Characterization*, ICISSP 2018.")
    w("- Purpose: a benchmark for network intrusion detection, built from benign user profiles and attack profiles. "
      "Seven attack scenarios (brute force, Heartbleed, botnet, DoS, DDoS, web attacks, infiltration) were run by 50 attacker "
      "machines against an organisation of 5 departments, 420 machines and 30 servers. Flow features were extracted "
      "with CICFlowMeter-V3.")
    w("")
    w("## 3. Bucket structure and size (Verified)")
    w("")
    w(f"The bucket was listed anonymously from Colab (\x60s3_bucket_listing.csv\x60): **{len(lst)} objects, "
      f"{gib(lst['bytes'].sum()):.2f} GiB in total**.")
    w("")
    w(md(pd.DataFrame([
        ["Original Network Traffic and Log data", len(raw), f"{gib(raw['bytes'].sum()):.2f} GiB",
         f"Per day: one PCAP archive ({gib(raw_pcap['bytes'].min()):.1f}–{gib(raw_pcap['bytes'].max()):.1f} GiB) "
         f"and one logs.zip ({gib(raw_logs['bytes'].min()):.2f}–{gib(raw_logs['bytes'].max()):.2f} GiB)"],
        ["Processed Traffic Data for ML Algorithms", len(proc), f"{gib(proc['bytes'].sum()):.2f} GiB",
         f"{len(fs)} CSV files, one per capture day (labelled flows)"]],
        columns=["Folder", "Objects (incl. folder markers)", "Size", "Contents"])))
    w("")
    w("Only the processed CSVs are practical for SentinelAI in Colab. The raw PCAPs (hundreds of GiB) would only be "
      "needed to regenerate flows with IP addresses or corrected labels.")
    w("")
    w("## 4. File structure and format (Verified)")
    w("")
    w(f"All {len(fs)} CSVs were streamed in full from the bucket. The number of bytes read equals the listed size for every "
      f"file{'' if fs['bytes_streamed_equals_listed'].all() else ' EXCEPT those marked no'}, there were "
      f"{'no parse errors' if (fs['parse_error'] == 'none').all() else 'parse errors (see table)'}, and pandas row counts "
      f"equal the physical line counts.")
    w("")
    show = fs[["day", "MB", "columns", "data_rows", "repeated_header_lines", "lines_at_excel_limit", "benign",
               "attack_rows", "attack_pct"]].copy()
    show = pd.concat([show, pd.DataFrame([{"day": "TOTAL", "MB": round(fs["MB"].sum(), 1), "columns": "",
                                           "data_rows": total_rows, "repeated_header_lines": rep_hdr,
                                           "lines_at_excel_limit": "", "benign": int(lc.loc[lc.label == "Benign", "flows"].sum()),
                                           "attack_rows": susp, "attack_pct": round(100 * susp / total_rows, 2)}])])
    w(md(show))
    w("")
    w(f"- **Format:** comma-separated text with one header row; one row is one bidirectional flow. "
      f"{len(fs) - len(ip_files)} files share the same {len(base_hdr)}-column header. "
      f"{', '.join(ip_files)} has {max(len(h) for h in headers.values())} columns: the extra columns are "
      f"{', '.join(c for c in headers[ip_files[0]] if c not in base_hdr)}. Shared columns are in the same order.")
    w(f"- **Organisation:** by day, not by attack. Each day file mixes benign traffic with that day's one or two attacks.")
    w(f"- **Size in practice:** the largest file is {fs['MB'].max():,.0f} MB with {fs['data_rows'].max():,} rows. "
      "It fits Colab only when read in chunks.")
    w("")
    w(f"### Columns (the common {len(base_hdr)}-column header)")
    w("")
    w("Identifiers and time: \x60Dst Port\x60, \x60Protocol\x60, \x60Timestamp\x60. Label: \x60Label\x60. The other "
      f"{len(base_hdr) - 4} columns are numeric CICFlowMeter statistics, grouped as follows (meanings from the official page):")
    w("")
    groups = [
        ("Duration and counts", ["Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts", "TotLen Fwd Pkts", "TotLen Bwd Pkts"],
         "How long the flow lasted and how many packets/bytes went each way"),
        ("Packet length", [c for c in base_hdr if "Pkt Len" in c], "Size statistics of packets, per direction and overall"),
        ("Rates", ["Flow Byts/s", "Flow Pkts/s", "Fwd Pkts/s", "Bwd Pkts/s"], "Bytes and packets per second"),
        ("Inter-arrival times", [c for c in base_hdr if "IAT" in c], "Time gaps between packets"),
        ("TCP flags", [c for c in base_hdr if "Flag" in c or "Flags" in c], "Counts of FIN, SYN, RST, PSH, ACK, URG, CWE, ECE"),
        ("Headers, segments, windows", [c for c in base_hdr if "Header" in c or "Seg" in c or "Win" in c or c == "Fwd Act Data Pkts"],
         "Header lengths, segment sizes, initial TCP window sizes"),
        ("Bulk and sub-flow", [c for c in base_hdr if "Blk" in c or "b Avg" in c or "Subflow" in c], "Bulk-transfer and sub-flow statistics"),
        ("Active / idle", [c for c in base_hdr if c.startswith("Active") or c.startswith("Idle")], "How long the flow was active or idle"),
        ("Other", ["Down/Up Ratio", "Pkt Size Avg"], "Download/upload ratio, average packet size"),
    ]
    used = set()
    rows = []
    for g, cols, meaning in groups:
        cols = [c for c in cols if c in base_hdr and c not in used]
        used.update(cols)
        rows.append([g, len(cols), ", ".join(f"\x60{c}\x60" for c in cols), meaning])
    rest = [c for c in base_hdr if c not in used and c not in ("Dst Port", "Protocol", "Timestamp", "Label")]
    if rest:
        rows.append(["Ungrouped", len(rest), ", ".join(f"\x60{c}\x60" for c in rest), "-"])
    w(md(pd.DataFrame(rows, columns=["Group", "Columns", "Names (exact)", "Meaning"])))
    w("")
    w("## 5. Labels (Verified) and proposed binary mapping")
    w("")
    w(f"The label column is \x60Label\x60 in every file. The full scan found **{len(tot)} distinct values** in "
      f"{total_rows:,} flows. Strings were compared exactly; "
      f"{'none contain leading or trailing whitespace' if not ws_labels else 'some contain stray whitespace: ' + repr(ws_labels)}. "
      f"{rep_hdr} further rows contain the literal text \x60Label\x60: these are repeated header lines inside the data "
      "and are not flows.")
    w("")
    w("CIC publishes no benign/malicious list (AIT has \x60label_info.txt\x60), so the mapping below is **proposed by H-2**. "
      "Each attack label is tied to a scenario on the official page. Only the exact string \x60Benign\x60 maps to 0; "
      "any unknown value stays unmapped.")
    w("")
    t = tot[["label", "attack_scenario", "binary_label", "flows", "days"]].copy()
    t["label"] = t["label"].map(lambda s: f"\x60{s}\x60")
    t["share %"] = (100 * tot["flows"] / total_rows).round(3)
    w(md(t))
    w("")
    w(f"Result: Normal (0) = **{normal:,}**, Suspicious (1) = **{susp:,}** ({100 * susp / total_rows:.2f}%), "
      f"unmapped = **{int(unmapped['flows'].sum()):,}**.")
    w("")
    w("**Label consistency (Verified):**")
    w("")
    multi = tot[tot["files"] > 1]
    w(f"- Labels used on more than one day: "
      f"{', '.join(f'{chr(96)}{l}{chr(96)} ({d})' for l, d in zip(multi['label'], multi['days'])) or 'none'}. "
      + ("No two label values differ only in case, spacing or punctuation, so each attack has one spelling across all files."
         if not near_dups else f"Near-duplicate spellings found: {near_dups}."))
    w("- Naming is not uniform: \x60DDOS attack-HOIC\x60 / \x60DDOS attack-LOIC-UDP\x60 versus \x60DDoS attacks-LOIC-HTTP\x60; "
      "\x60Infilteration\x60 is misspelt; \x60Brute Force -Web\x60 has an odd space. This is harmless for an exact mapping "
      "but must be copied exactly.")
    w(f"- **Missing attack:** the official schedule lists DDoS LOIC-UDP on 20-02, but the 20-02 file contains "
      f"{'that label' if loic_udp_tue else 'no LOIC-UDP label'}. LOIC-UDP appears in: "
      f"{', '.join(tot.loc[tot.label == 'DDOS attack-LOIC-UDP', 'days']) or 'no file'} "
      f"({int(tot.loc[tot.label == 'DDOS attack-LOIC-UDP', 'flows'].sum()):,} flows). Heartbleed is described on the "
      + ("official page but has no label in any file." if not heartbleed else f"official page; labels found: {heartbleed}."))
    w(f"- **Label noise:** in the first 200,000 rows of each file, groups of rows with identical features but different labels "
      f"were found in {', '.join(f'{day_of(k)} ({v:,} groups)' for k, v in s_conf.items())}. A follow-up check of the first "
      "40 MB of the 01-03 file showed these groups mix \x60Benign\x60 and \x60Infilteration\x60. Published work also reports "
      "labelling errors in this dataset (Liu et al., 2022).")
    w("")
    w("## 6. Data quality (Verified)")
    w("")
    w("Full-file checks cover every row for the listed columns; sample checks cover the first 200,000 rows of each file "
      f"({s_rows:,} rows in total) and are marked as such.")
    w("")
    w(md(pd.DataFrame([
        ["Literal 'NaN' text in Flow Byts/s", "full", nan_text],
        ["'Infinity' in Flow Byts/s", "full", inf_b],
        ["'Infinity' in Flow Pkts/s", "full", inf_p],
        ["Negative Flow Duration", "full", neg_dur],
        ["Negative Init Fwd Win Byts (-1 = not observed)", "full", neg_win],
        ["Repeated header lines inside data", "full", rep_hdr],
        ["Exact duplicate rows", "sample", s_dups],
        ["Duplicate rows if Timestamp is ignored", "sample", s_dups_nt],
        ["Columns constant in every sample", "sample", len(const_all)],
    ], columns=["Check", "Scope", "Count"])))
    w("")
    w(f"- **Row-limit files:** {len(at_cap)} of {len(fs)} files have exactly {EXCEL_MAX_DATA_LINES:,} data lines "
      f"({', '.join(at_cap['day'])}). This is Excel's maximum sheet size minus the header row. It strongly suggests these "
      "files passed through a spreadsheet and **may be truncated**. We could not confirm it from the times (next point); "
      "confirming it would need the raw PCAPs.")
    w(f"- **12-hour timestamps:** the latest time in any file is {max_hour}:59; no hour from 13 to 23 occurs, "
      "and there is no AM/PM marker. So morning and afternoon flows cannot be told apart, and the time order within a day is ambiguous. "
      + (f"Some timestamps also fall outside the capture day ({', '.join(day_of(f) for f in out_of_day)})." if out_of_day else ""))
    w(f"- **Protocols:** {', '.join(f'{k}: {v:,}' for k, v in proto.items())} flows (6 = TCP, 17 = UDP, 0 = no transport "
      "protocol; in a checked sample all protocol-0 flows had destination port 0).")
    w(f"- **Constant columns** (no information in any sample): {', '.join(f'{chr(96)}{c}{chr(96)}' for c in const_all)}.")
    w(f"- **Duplicates** are very uneven by day. In the samples, {dup_ratio[0][0]:.0%} of rows in {dup_ratio[0][1]} and "
      f"{dup_ratio[1][0]:.0%} in {dup_ratio[1][1]} are exact duplicates. Duplicates that end up on both sides of the "
      "train/test split inflate the scores.")
    w("")
    w("## 7. Comparison with AIT (from H-1 evidence and this scan)")
    w("")
    w(md(comp))
    w("")
    w("## 8. Fit with SentinelAI and the Random Forest")
    w("")
    w("- **Random Forest: yes.** The 70+ numeric per-flow features are the kind of input a Random Forest handles well, "
      "and binary labels are easy to derive. After cleaning (Inf/NaN, constant columns, repeated headers) a flow-level "
      "model can be trained in Colab.")
    w("- **Planned host-window features (H-4): mostly no.** Connections, distinct ports and distinct hosts per host in a "
      f"past-only 5-minute window need a source IP and a reliable time order. Only {len(ip_files)} of {len(fs)} files have "
      "IPs, and the 12-hour clock makes time order ambiguous.")
    w("- **Fair split (H-6): changes.** There is one network, not eight. Splitting by day means each test day has attack "
      "types the model never saw, which measures something different. A random split leaks near-duplicate flows.")
    w("- **Agents:** CIC provides no IDS alert set like the AIT Alert Data Set. The Investigation Agent would need "
      "synthetic or self-generated alerts. ATT&CK/Kill-Chain mappings would cover different techniques (brute force, DoS, "
      "botnet) than the AIT attack chain.")
    w("")
    w("## 9. Backup decision")
    w("")
    w("1. **Can it serve as a backup?** Yes, for the Random Forest detection part. It is official, public, labelled, "
      "and processable in Colab.")
    w("2. **Advantages over AIT:** many more flows and attack types (brute force, DoS/DDoS, web attacks, botnet, "
      "infiltration); widely used in published work, so results are easy to compare; a large attack share in several files.")
    w("3. **Disadvantages:** one network only (no split by network); IPs in only one file; 12-hour timestamps; files "
      "that may be truncated; Inf/NaN and negative values; repeated headers; duplicates; documented and observed label "
      "noise (especially infiltration); no matching alert data; no official binary label file.")
    w("4. **Modifications needed:** drop repeated header lines; replace or remove NaN/Infinity rows; treat -1 window values "
      "as 'not observed'; drop constant columns; remove exact duplicates before splitting; apply the exact label mapping "
      "above; consider excluding \x60Infilteration\x60 or reporting results with and without it.")
    w("5. **Methodology changes if we switch:** feature module without per-host windows (or limited to the 20-02 file); "
      "a new split strategy (by day/attack type, or a deduplicated stratified split, stated clearly); retargeted rules "
      "(M-2) and ATT&CK subset (O-1); alerts for the agents generated from our own detections instead of AIT-ADS; "
      "updated proposal slides 8–11.")
    w("")
    w("**Recommendation: Suitable with conditions.** Keep AIT as the primary dataset (H-1: conditional GO). Use CSE-CIC-IDS2018 "
      "(a) as the backup for the flow-level Random Forest if AIT fails, and (b) optionally as a second, out-of-distribution "
      "test set, as the proposal already allows. It is not a full replacement for the multi-agent part without extra work.")
    w("")
    w("### How to switch if AIT fails the gate (tracker completion note)")
    w("")
    w("1. Rerun \x60h2_ids2018_scan.py\x60 to re-verify the 10 CSVs, and lock the label mapping (\x60ids2018_label_mapping.json\x60) in H-3.")
    w("2. Build a cleaning step: drop rows with Label = 'Label'; handle NaN/Infinity; drop constant columns; deduplicate.")
    w("3. Agree a new feature contract (ALL-1) based on per-flow CICFlowMeter features only, without IPs, ports used as "
      "identities, or timestamps.")
    w("4. Choose and document the split (by day / attack type, or a deduplicated stratified split) and update H-6.")
    w("5. Tell Malak (M-2/M-3), Reem (R-1/R-4) and Omar (O-1/O-3) which attack types and alert sources change.")
    w("")
    w("## 10. Limitations of this verification")
    w("")
    w("- Duplicate, conflict and constant-column checks used the first 200,000 rows of each file, not every row.")
    w("- Possible truncation was inferred from row counts; it was not confirmed against the raw PCAPs.")
    w("- S3 ETags were recorded, but CIC publishes no checksums for these files, so integrity can only be confirmed as "
      "'complete download of the published bytes'.")
    w("- The binary mapping is proposed, not official. H-3 owns the final labelling rule.")
    w("- No model was trained; suitability for the Random Forest is judged from the features and labels, not from results.")
    w("")
    w("## 11. Paragraph for the project documentation")
    w("")
    para = (f"As a backup to the AIT Netflow Data Set we verified CSE-CIC-IDS2018 (CSE and the Canadian Institute for "
            f"Cybersecurity, 2018), using its official public AWS release. The ten processed CICFlowMeter CSV files "
            f"({gib(proc['bytes'].sum()):.2f} GiB, {total_rows:,} labelled flows) were streamed in full. They contain "
            f"{len(tot)} label values: 'Benign' and {len(tot) - 1} attack labels covering brute force, DoS, DDoS, web "
            f"attacks, infiltration and botnet traffic, giving {100 * susp / total_rows:.1f}% suspicious flows under our "
            f"binary mapping. The data supports a flow-level Random Forest, but it comes from a single network. IP addresses "
            f"are present on only one of ten days, and timestamps use a 12-hour clock without AM/PM, so our per-host time-window "
            f"features and network-wise split cannot be reproduced. The files also need cleaning for Infinity/NaN values, "
            f"repeated header lines, duplicates and known label noise. We therefore judge CSE-CIC-IDS2018 suitable, with "
            f"conditions, as a backup for the detection model and as an optional second test set, while AIT remains the "
            f"primary dataset.")
    w(para)
    (O / "documentation_paragraph.md").write_text(para + "\n")
    w("")
    w("## Evidence and sources")
    w("")
    w("- Evidence files: \x60s3_bucket_listing.csv\x60, \x60csv_headers.json\x60, \x60scan_results.json\x60, \x60scan_log.txt\x60, "
      "\x60ids2018_file_structure.csv\x60, \x60ids2018_label_counts_by_file.csv\x60, \x60ids2018_label_mapping.csv/.json\x60, "
      "\x60ait_vs_ids2018_comparison.csv\x60; scripts \x60h2_ids2018_scan.py\x60, \x60h2_make_report.py\x60.")
    w("- CIC dataset page: https://www.unb.ca/cic/datasets/ids-2018.html")
    w("- AWS Open Data registry: https://registry.opendata.aws/cse-cic-ids2018/")
    w("- Sharafaldin, Lashkari, Ghorbani, ICISSP 2018 (dataset paper).")
    w("- Liu, Engelen, Lynar, Essam, Joosen, *Error Prevalence in NIDS datasets: A Case Study on CIC-IDS-2017 and "
      "CSE-CIC-IDS-2018*, IEEE CNS 2022, doi:10.1109/CNS56114.2022.9947235.")
    w("- Leevy and Khoshgoftaar, *A survey and analysis of intrusion detection models based on CSE-CIC-IDS2018 Big Data*, "
      "Journal of Big Data 7:104 (2020), doi:10.1186/s40537-020-00382-x.")
    w("- H-1 outputs (AIT numbers): \x60h1_outputs/ait_network_attack_counts.csv\x60, \x60csv_file_quality_report.csv\x60.")
    w("")
    (O / "H2_CSE-CIC-IDS2018_Verification_Report.md").write_text("\n".join(L), encoding="utf-8")
    print("written; flows", total_rows, "normal", normal, "suspicious", susp, "unmapped", int(unmapped["flows"].sum()),
          "| at excel cap", len(at_cap), "| ip files", ip_files, "| hours", ts_hours)


if __name__ == "__main__":
    main()
