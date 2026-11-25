#!/usr/bin/env python3
"""
SentinelAI H-1 - build H1_AIT_Verification_Report.md from the evidence files
written by h1_ait_verify.py. Every number in the report is read from those files
(or recomputed here from the original ZIPs); nothing is typed in by hand.

Run:  python scripts/h1_make_report.py --data-dir data/raw/ait --out-dir data/processed/h1_outputs
"""
from __future__ import annotations

import argparse
import json
import re
import zipfile
from pathlib import Path

import pandas as pd

UNMAPPED_MAX_SHARE = 0.001      # GO criterion: unmapped flows must be < 0.1 % of all flows


def clean(c: str) -> str:
    """'#15#c_ip:1' -> 'c_ip' (same rule as the verifier)."""
    return re.sub(r":\d+$", "", re.sub(r"^#(\d+#)?", "", c))


def md_table(df: pd.DataFrame) -> str:
    """Minimal Markdown table writer (no extra dependency such as tabulate)."""
    cols = [str(c) for c in df.columns]
    lines = ["| " + " | ".join(cols) + " |", "|" + "|".join("---" for _ in cols) + "|"]
    for _, r in df.iterrows():
        cells = []
        for v in r.tolist():
            if isinstance(v, bool):
                cells.append("yes" if v else "**NO**")
            elif isinstance(v, int) or (isinstance(v, float) and v.is_integer() and abs(v) >= 1000):
                cells.append(f"{int(v):,}")
            elif isinstance(v, float):
                cells.append(f"{v:.2f}")
            else:
                cells.append(str(v).replace("|", "\\|"))
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


def pct(a, b):
    return 100.0 * a / b if b else float("nan")


def profile_unmapped(downloads: Path, lab: pd.DataFrame):
    """For every file that has unmapped labels, re-read it from the ZIP (chunked)
    and describe the unmapped rows plus how the SAME client/server/port tuples
    are labelled elsewhere in the file. Context only - nothing is relabelled."""
    out = []
    um = lab[lab["binary_label"] == ""]
    for (net, fname), g in um.groupby(["network", "file"]):
        bad_values = set(g["original_label"])
        rows, tuples = [], []
        with zipfile.ZipFile(downloads / f"{net}_netflows.zip") as z, z.open(fname) as f:
            for ch in pd.read_csv(f, dtype=str, keep_default_na=False, na_filter=False, chunksize=200_000):
                ch.columns = [clean(c) for c in ch.columns]
                rows.append(ch[ch["label"].isin(bad_values)])
                tuples.append(ch[["c_ip", "s_ip", "s_port", "label"]])
        R = pd.concat(rows)
        T = pd.concat(tuples)
        keys = R[["c_ip", "s_ip", "s_port"]].drop_duplicates()
        same = T.merge(keys, on=["c_ip", "s_ip", "s_port"])
        tcol = "first" if "first" in R.columns else "c_first_abs"
        t = pd.to_datetime(pd.to_numeric(R[tcol], errors="coerce"), unit="ms", utc=True)
        out.append({
            "network": net, "file": fname, "rows": len(R),
            "label_values": sorted(repr(v) for v in bad_values),
            "time_first": str(t.min()), "time_last": str(t.max()),
            "s_port": R["s_port"].value_counts().head(5).to_dict(),
            "c_ip": R["c_ip"].value_counts().head(5).to_dict(),
            "s_ip": R["s_ip"].value_counts().head(5).to_dict(),
            "role_serv": R["role_serv"].value_counts().head(5).to_dict() if "role_serv" in R else {},
            "same_tuple_labels": same["label"].map(lambda v: repr(v) if v in bad_values else v)
                                              .value_counts().to_dict(),
        })
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", default="data/raw/ait")
    ap.add_argument("--out-dir", default="data/processed/h1_outputs")
    args = ap.parse_args()
    downloads = Path(args.data_dir).resolve() / "downloads"
    O = Path(args.out_dir).resolve()

    arc = pd.read_csv(O / "archive_checksums.csv", keep_default_na=False)
    fq = pd.read_csv(O / "csv_file_quality_report.csv", keep_default_na=False)
    lab = pd.read_csv(O / "label_counts_by_file.csv", keep_default_na=False, dtype={"binary_label": str})
    nt = pd.read_csv(O / "ait_network_attack_counts.csv", keep_default_na=False)
    mapping = json.loads((O / "label_mapping.json").read_text())
    man = json.loads((O / "run_manifest.json").read_text())
    for c in ("rows", "normal_flows", "suspicious_flows", "unmapped_flows", "exact_duplicate_rows",
              "empty_cells_total", "na_token_cells_total", "conflicting_label_groups", "n_columns"):
        fq[c] = pd.to_numeric(fq[c])
    lab["flow_count"] = pd.to_numeric(lab["flow_count"])
    to_bool = lambda s: s.astype(str).str.lower().eq("true")
    for c in ("md5_match", "size_match", "verified"):
        arc[c] = to_bool(arc[c])
    fq["row_count_reconciles"] = to_bool(fq["row_count_reconciles"])
    fq["label_counts_sum_equals_rows"] = to_bool(fq["label_counts_sum_equals_rows"])
    nt["counts_reconcile"] = to_bool(nt["counts_reconcile"])

    zips = arc[arc["file"].str.endswith(".zip")]
    tot = nt[nt["network"] == "TOTAL"].iloc[0]
    nets = nt[nt["network"] != "TOTAL"].copy()
    total_flows = int(tot["total_flows"])
    unmapped_total = int(tot["unmapped_flows"])
    schemas = man["schemas"]

    # ------------------------------------------------------------ criteria
    crit = []
    crit.append(("All 8 archives and label_info.txt match the Zenodo MD5 and byte size, and every ZIP passes the CRC test",
                 bool(arc["verified"].all()) and len(zips) == 8))
    crit.append(("All 24 CSVs parsed with no errors and pandas row counts equal the physical line counts",
                 len(fq) == 24 and (fq["parse_error"] == "").all() and fq["row_count_reconciles"].all()))
    by_type = fq.groupby(["protocol", "flow_completeness"])["schema_id"].nunique()
    crit.append(("Each file type has one identical schema across all 8 networks, and every file has the label column",
                 (by_type == 1).all() and (fq["label_column"] == "label").all()
                 and (fq["protocol_vs_schema_check"] == "consistent").all()))
    crit.append(("label_info.txt parses into 4 sections with no conflicts, and every official label is observed",
                 mapping["label_info_parse_problems"] == []
                 and not mapping["observed_in_csvs"]["TCP"]["official_labels_never_observed"]
                 and not mapping["observed_in_csvs"]["UDP"]["official_labels_never_observed"]))
    crit.append((f"Unmapped flows are below {UNMAPPED_MAX_SHARE:.1%} of all flows and are reported, not guessed",
                 unmapped_total / total_flows < UNMAPPED_MAX_SHARE))
    crit.append(("Every network contains both Normal (0) and Suspicious (1) flows (needed for the H-6 network split)",
                 bool(((nets["normal_flows"].astype(int) > 0) & (nets["suspicious_flows"].astype(int) > 0)).all())))
    crit.append(("Per-network label counts sum to total flows (normal + suspicious + unmapped = rows)",
                 bool(nt["counts_reconcile"].all()) and fq["label_counts_sum_equals_rows"].all()))
    go = all(ok for _, ok in crit)

    unm = profile_unmapped(downloads, lab)

    # most common http_res values in the first chunk of one TCP-complete file (context for placeholders)
    http_top = {}
    with zipfile.ZipFile(downloads / "fox_netflows.zip") as zz, zz.open("tcp_complete.csv") as fh:
        first = next(pd.read_csv(fh, dtype=str, keep_default_na=False, na_filter=False, chunksize=200_000))
        first.columns = [clean(c) for c in first.columns]
        if "http_res" in first.columns:
            http_top = first["http_res"].value_counts().head(5).to_dict()

    # ------------------------------------------------------------ derived numbers
    by_kind = fq.groupby(["protocol", "flow_completeness"])[["rows", "normal_flows", "suspicious_flows", "unmapped_flows"]].sum()
    by_kind["suspicious_%"] = 100 * by_kind["suspicious_flows"] / by_kind["rows"]
    by_kind = by_kind.reset_index()
    nocomp = by_kind[(by_kind.protocol == "TCP") & (by_kind.flow_completeness == "nocomplete")].iloc[0]
    tcpc = by_kind[(by_kind.protocol == "TCP") & (by_kind.flow_completeness == "complete")].iloc[0]
    susp_share_from_nocomp = pct(nocomp["suspicious_flows"], int(tot["suspicious_flows"]))
    dup_total = int(fq["exact_duplicate_rows"].sum())
    dup_by_proto = fq.groupby("protocol")["exact_duplicate_rows"].sum().to_dict()
    conflicts = int(fq["conflicting_label_groups"].sum())
    na_cols = sorted(set().union(*[json.loads(x).keys() for x in fq["na_tokens_by_column_json"]]))
    na_total = int(fq["na_token_cells_total"].sum())
    empty_cols = sorted(set().union(*[json.loads(x).keys() for x in fq["empty_cells_by_column_json"]]))
    empty_total = int(fq["empty_cells_total"].sum())
    nets["suspicious_pct"] = pd.to_numeric(nets["suspicious_pct"])
    lo = nets.loc[nets["suspicious_pct"].idxmin()]
    hi = nets.loc[nets["suspicious_pct"].idxmax()]

    mal_by_net = lab[lab["binary_label"] == "1"].pivot_table(index="original_label", columns="network",
                                                              values="flow_count", aggfunc="sum", fill_value=0)

    # time span per network (TCP 'first' and UDP 'c_first_abs' are epoch milliseconds)
    fq["time_min"] = pd.to_numeric(fq["time_min"], errors="coerce")
    fq["time_max"] = pd.to_numeric(fq["time_max"], errors="coerce")
    span = fq.groupby("network").agg(t0=("time_min", "min"), t1=("time_max", "max"))
    span["first_flow_utc"] = pd.to_datetime(span["t0"], unit="ms", utc=True).dt.strftime("%Y-%m-%d %H:%M")
    span["last_flow_utc"] = pd.to_datetime(span["t1"], unit="ms", utc=True).dt.strftime("%Y-%m-%d %H:%M")
    span["days"] = ((span["t1"] - span["t0"]) / 86_400_000).round(2)

    # ------------------------------------------------------------ write report
    L = []
    w = L.append
    w("# H-1 — AIT Netflow Data Set Verification Report")
    w("")
    w(f"*SentinelAI · Data & Features · generated by `h1_make_report.py` from the evidence files of the "
      f"verification run at {man['run_utc']} (UTC).*")
    w("")
    w(f"**Recommendation: {'GO' if go else 'NO-GO'}"
      f"{' — with the conditions in section 10' if go else ' — see the failed criteria in section 10'}.**")
    w("")
    w("## 1. Objective")
    w("")
    w("Task H-1 (tracker): download AIT Netflow (8 networks); confirm the CSV columns and `label_info.txt`; "
      "count attack flows per network. Done when there is a column table, an attack-count table and a GO/NO-GO "
      "decision on AIT (the Phase 1 gate). The project uses binary labels: **Normal = 0, Suspicious = 1**.")
    w("")
    w("## 2. Dataset source")
    w("")
    z = man["zenodo"]
    w(f"- **{z['title']}**, AIT Austrian Institute of Technology, Zenodo record {z['record_id']} "
      f"(DOI [{z['doi']}](https://doi.org/{z['doi']})), published {z['publication_date']}.")
    w(f"- Official file list, sizes and MD5 checksums read from the Zenodo REST API (`{z['api_url']}`) "
      f"at {z['retrieved_utc']}.")
    w("- Files used: `label_info.txt` and `<network>_netflows.zip` for fox, harrison, russellmitchell, santos, "
      "shaw, wardbeck, wheeler and wilson. Each ZIP holds `tcp_complete.csv`, `tcp_nocomplete.csv` and "
      "`udp_complete.csv` (Tstat flow logs with labels added by the publisher).")
    w("")
    w("## 3. Verification methodology")
    w("")
    w(f"Run environment: Google Colab, Python {man['python']}, pandas {man['pandas']}, numpy {man['numpy']}. "
      f"Verifier `h1_ait_verify.py` (MD5 `{man['script_md5']}`), chunk size {man['chunk_rows']:,} rows.")
    w("")
    w("1. **Archives**: the verifier computed the MD5 and byte size of every downloaded file and compared them with the values "
      "Zenodo lists. It ran `zipfile.testzip()`, which reads every member and checks its CRC-32. "
      "All files are checked, and a failure is recorded rather than stopping the run.")
    w("2. **CSVs**: each CSV was streamed straight out of its ZIP with `pandas.read_csv(chunksize=200000, dtype=str, "
      "na_filter=False, on_bad_lines='error')`. The archives were never modified and only one chunk was in memory at a time. "
      "Newlines were counted in the same pass, so the pandas row count can be reconciled against the physical line count.")
    w("3. **Labels**: `label_info.txt` was parsed into its four sections (Benign/Malicious × TCP/UDP). The mapping is "
      "**exact** (case- and whitespace-sensitive) and **protocol-aware**: TCP files use the TCP sections and UDP files "
      "use the UDP sections. Any other value is *unmapped* and is never counted as benign.")
    w("4. **Quality**: per file, the verifier counted empty cells and NA-like tokens (`NA`, `N/A`, `nan`, `NaN`, `null`, `NULL`, "
      "`None`, `-`), exact duplicate rows, and groups of rows with identical features but different binary labels "
      "(both via 64-bit row hashes over the full file). It also cross-checked the protocol in each filename against "
      "the schema and recorded the timestamp range.")
    w("5. **Report**: this file is generated from the CSV/JSON outputs by `h1_make_report.py`. The unmapped-row profile in "
      "section 7 is recomputed from the original ZIP.")
    w("")
    w("### Corrections to the original `sentinelai_ait_verify.py`")
    w("")
    rm = arc[arc["file"] == "russellmitchell_netflows.zip"].iloc[0]
    diffpos = [i + 1 for i, (x, y) in enumerate(zip(rm["script_v1_expected_md5"], rm["official_md5"])) if x != y]
    others_ok = arc[(arc["file"] != "russellmitchell_netflows.zip") & arc["file"].str.endswith(".zip")]
    others_ok = (others_ok["script_v1_md5_equals_official"].astype(str).str.lower() == "true").all()
    w(f"- **Checksum transcription error (line 32).** The script expected `{rm['script_v1_expected_md5']}`, "
      f"but Zenodo lists `{rm['official_md5']}` and the downloaded file hashes to `{rm['actual_md5']}`. "
      + (f"They differ only at character positions {diffpos}: two characters were swapped "
         f"(`{rm['script_v1_expected_md5'][diffpos[0]-1:diffpos[1]]}` instead of `{rm['official_md5'][diffpos[0]-1:diffpos[1]]}`). "
         if len(diffpos) == 2 and sorted(rm['script_v1_expected_md5']) == sorted(rm['official_md5'])
         else f"They differ at character positions {diffpos}. ")
      + f"{'The archive was correct and the script was wrong. ' if rm['md5_match'] else ''}"
      "The constant was corrected with a comment, and the untouched original is kept as `sentinelai_ait_verify.ORIGINAL.py`. "
      f"{'The other seven hard-coded MD5s equal the official values.' if others_ok else 'Other hard-coded MD5s also differ; see section 4.'}")
    w("- **Abort on first mismatch.** The original raised an exception at the first failing archive, so no output files "
      "were written and the later archives were never reported. v2 checks and records every archive.")
    w("- **Whole-file reads.** The original loaded each CSV fully with `pd.read_csv`. v2 streams in chunks.")
    w("- **Non-exact label matching.** The original applied `.str.strip()` before mapping, and pandas' default NA parsing "
      "can silently turn text such as `NA` or `null` into missing values. v2 matches exactly, reports "
      "whitespace-only variants separately and disables NA conversion.")
    w("- **Checksums not read from the publisher; sizes not checked.** v2 reads both from the Zenodo API at run time.")
    w("")
    w("## 4. Archive verification results")
    w("")
    a = arc[["file", "official_bytes", "actual_bytes", "official_md5", "actual_md5", "md5_match", "size_match",
             "zip_testzip", "verified"]].copy()
    a["official_bytes"] = pd.to_numeric(a["official_bytes"]); a["actual_bytes"] = pd.to_numeric(a["actual_bytes"])
    a["zip_testzip"] = a["zip_testzip"].replace("", "n/a (text file)")
    w(md_table(a))
    w("")
    w(f"Result: **{int(arc['verified'].sum())} of {len(arc)} files verified**; "
      f"{'no failed or unresolved archive checks' if arc['verified'].all() else 'see rows marked NO'}.")
    w("")
    w("## 5. CSV structure and columns")
    w("")
    sch_rows = []
    for sid, g in fq.groupby("schema_id"):
        sch_rows.append({"schema": sid, "file": ", ".join(sorted(g["file"].unique())),
                         "protocol": ", ".join(sorted(g["protocol"].unique())),
                         "networks": g["network"].nunique(), "columns": int(g["n_columns"].iloc[0]),
                         "label column": ", ".join(sorted(g["label_column"].unique())),
                         "protocol vs schema": ", ".join(sorted(g["protocol_vs_schema_check"].unique()))})
    w(md_table(pd.DataFrame(sch_rows)))
    w("")
    w(f"There are {fq['schema_id'].nunique()} distinct header layouts. Files of the same type share one layout across "
      f"{'all 8 networks' if (by_type == 1).all() else 'SOME networks only (inconsistent)'}; the layouts of different file types "
      "differ, so the schemas are **not identical across file types**. Header names are Tstat-style "
      "(`#15#c_ip:1`, `c_port:2`, …): a `#…#` prefix on the first field and a `:N` position suffix on most "
      "fields. Below, `clean name` removes those decorations; the exact raw names are in "
      "`csv_file_quality_report.csv` (`columns_raw_json`) and `run_manifest.json`.")
    w("")
    for cols_raw, sid in sorted(((tuple(v["columns_raw"]), k) for k, v in schemas.items()), key=lambda x: x[1]):
        files = ", ".join(sorted(fq[fq["schema_id"] == sid]["file"].unique()))
        w(f"<details><summary><b>{sid}</b> — {files}: {len(cols_raw)} columns (click to expand)</summary>")
        w("")
        w("| # | raw header | clean name |")
        w("|---|---|---|")
        for i, c in enumerate(cols_raw, 1):
            w(f"| {i} | `{c}` | `{clean(c)}` |")
        w("")
        w("</details>")
        w("")
    w("### Per-file inspection")
    w("")
    f = fq[["network", "file", "rows", "n_columns", "schema_id", "label_column", "row_count_reconciles",
            "empty_cells_total", "na_token_cells_total", "exact_duplicate_rows", "conflicting_label_groups",
            "parse_error"]].copy()
    f["parse_error"] = f["parse_error"].replace("", "none")
    w(md_table(f))
    w("")
    w("## 6. Official label mapping (`label_info.txt`)")
    w("")
    w(f"Source MD5 `{mapping['source_md5']}` (matches Zenodo). Parse problems: "
      f"{mapping['label_info_parse_problems'] or 'none'}. Mapping file: `label_mapping.json`.")
    w("")
    for p in ("TCP", "UDP"):
        w(f"- **{p} benign → 0** ({len(mapping[p]['benign_0'])}): " + ", ".join(f"`{x}`" for x in mapping[p]["benign_0"]))
        w(f"- **{p} malicious → 1** ({len(mapping[p]['malicious_1'])}): " + ", ".join(f"`{x}`" for x in mapping[p]["malicious_1"]))
    w("")
    never = {p: mapping["observed_in_csvs"][p]["official_labels_never_observed"] for p in ("TCP", "UDP")}
    w("Observed in the CSVs: " + ("every official label occurs at least once. " if not (never["TCP"] or never["UDP"])
      else f"official labels never observed: {never}. ")
      + "Labels that occur but are not in `label_info.txt` for that protocol:")
    w("")
    um_lab = lab[lab["binary_label"] == ""][["network", "file", "protocol", "original_label", "official_category", "flow_count"]].copy()
    um_lab["original_label"] = um_lab["original_label"].map(repr)
    w(md_table(um_lab) if len(um_lab) else "_none_")
    w("")
    w("## 7. Attack counts per network")
    w("")
    w("Counts include **all three files per network**: complete TCP flows, non-complete TCP flows and UDP flows. "
      "*Suspicious* means the label is in a *Malicious* section of `label_info.txt`; *unmapped* rows are not in either class.")
    w("")
    t1 = nt[["network", "total_flows", "normal_flows", "suspicious_flows", "unmapped_flows", "suspicious_pct",
             "tcp_total_flows", "tcp_suspicious_flows", "udp_total_flows", "udp_suspicious_flows", "counts_reconcile"]].copy()
    for c in t1.columns[1:-1]:
        t1[c] = pd.to_numeric(t1[c])
    t1 = t1.rename(columns={"suspicious_pct": "suspicious %"})
    w(md_table(t1))
    w("")
    w("Split by file type:")
    w("")
    t2 = nt[["network", "tcp_complete_total_flows", "tcp_complete_suspicious_flows", "tcp_nocomplete_total_flows",
             "tcp_nocomplete_suspicious_flows", "udp_total_flows", "udp_suspicious_flows"]].copy()
    for c in t2.columns[1:]:
        t2[c] = pd.to_numeric(t2[c])
    w(md_table(t2))
    w("")
    w("Totals by file type:")
    w("")
    w(md_table(by_kind.rename(columns={"flow_completeness": "completeness"})))
    w("")
    w("Suspicious flows by original attack label (all networks):")
    w("")
    mt = mal_by_net.copy()
    mt["TOTAL"] = mt.sum(axis=1)
    mt = mt.sort_values("TOTAL", ascending=False).reset_index().rename(columns={"original_label": "label"})
    w(md_table(mt))
    w("")
    if unm:
        w("### Unmapped rows — investigation (context only, not relabelled)")
        w("")
        for u in unm:
            w(f"- **{u['network']}/{u['file']}**: {u['rows']:,} rows with label value(s) {', '.join(u['label_values'])}. "
              f"Server port(s) {u['s_port']}; client IPs {u['c_ip']}; server IP {u['s_ip']}; server role {u['role_serv']}. "
              f"Time range {u['time_first']} → {u['time_last']}.")
            w(f"  - Labels of all rows in the same file with the same (client IP, server IP, server port): {u['same_tuple_labels']}.")
            mal_labels = set(mapping["TCP"]["malicious_1"]) | set(mapping["UDP"]["malicious_1"])
            if any(k in mal_labels for k in u["same_tuple_labels"]):
                w("  - Interpretation: the same client/server/port combinations also carry a **malicious** label, so treating "
                  "these rows as benign would be an unsupported assumption. They stay unmapped.")
            else:
                w("  - Interpretation: there is no evidence that fixes their class, so they stay unmapped.")
        w("")
    w("## 8. Data quality findings")
    w("")
    w("**Verified findings**")
    w("")
    w(f"- Missing values: {empty_total:,} empty cells in the whole dataset, all in column(s) {empty_cols}. These are the "
      f"{'unmapped rows in section 7. No feature column has empty cells.' if empty_cols in ([], ['label']) else 'see csv_file_quality_report.csv for the per-column breakdown.'}")
    w(f"- Placeholder tokens: {na_total:,} cells hold an NA-like token, all in the text columns {na_cols} "
      "(Tstat writes `-` when a field does not apply, e.g. no TLS SNI). "
      + (f"`http_res` mixes numeric HTTP status codes with text; its most common values in the first "
         f"200,000 rows of fox/tcp_complete.csv are {http_top}. " if http_top else "")
      + "These are placeholders, not corruption. Feature engineering (H-4) must handle them explicitly.")
    w(f"- Duplicates: {dup_total:,} exact duplicate rows in total (by protocol: {dup_by_proto}), i.e. "
      f"{pct(dup_total, total_flows):.4f}% of flows. "
      f"There are {conflicts} groups of rows with identical features but different binary labels.")
    w(f"- Columns: {'each file type has one consistent schema across networks' if (by_type == 1).all() else 'schemas are NOT consistent across networks'}. "
      f"There are {fq['schema_id'].nunique()} distinct schemas in total (see section 5).")
    w(f"- Unexpected labels: {unmapped_total:,} unmapped flows ({pct(unmapped_total, total_flows):.4f}% of all flows), "
      "only in the file(s) listed in section 6. "
      + ("No label appeared in the wrong protocol's list." if not lab["official_category"].str.contains("listed under").any()
         else "Some labels appear in the wrong protocol's list (see section 6)."))
    w(f"- Class balance: overall {pct(int(tot['suspicious_flows']), total_flows):.2f}% suspicious. "
      f"By file type: TCP-complete {tcpc['suspicious_%']:.2f}%, TCP-non-complete {nocomp['suspicious_%']:.2f}%, "
      f"UDP {by_kind[by_kind.protocol == 'UDP']['suspicious_%'].iloc[0]:.2f}%. "
      f"Non-complete TCP flows account for {susp_share_from_nocomp:.1f}% of all suspicious flows.")
    w(f"- Differences between networks: the suspicious share ranges from {lo['suspicious_pct']:.2f}% ({lo['network']}) "
      f"to {hi['suspicious_pct']:.2f}% ({hi['network']}). "
      + ("Every network contains both classes." if crit[5][1] else "NOT every network contains both classes."))
    w("")
    w("Capture period per network (from the `first` / `c_first_abs` epoch-millisecond columns):")
    w("")
    w(md_table(span[["first_flow_utc", "last_flow_utc", "days"]].reset_index()))
    w("")
    w("**Assumptions**")
    w("")
    w("- The publisher's labels are taken as ground truth. H-1 checked that they are consistent and complete, not that each "
      "label is correct.")
    w("- The protocol comes from the file name (`tcp_*` / `udp_*`) and was cross-checked against the schema "
      "(TCP files contain `c_syn_cnt`, `c_fin_cnt` and `c_rst_cnt`; UDP files do not).")
    w("- Duplicate and conflict detection relies on 64-bit hashes of full rows. The collision probability at this "
      "scale is negligible but not zero.")
    w("")
    w("**Recommendations for later tasks** (not done in H-1)")
    w("")
    w(f"- H-3: exclude the {unmapped_total:,} unmapped flows (or ask the publisher) and state this in the labelling rule. "
      "Never map them to 0.")
    if nocomp["suspicious_%"] > 90:
        w(f"- H-3/H-4: decide explicitly whether `tcp_nocomplete` flows are used. They are {nocomp['suspicious_%']:.1f}% "
          "suspicious, so a model that can tell which file a flow came from (or can see the features that define "
          "‘non-complete’) gets a near-trivial shortcut. Report results with and without them.")
    w(f"- H-4: the {fq['schema_id'].nunique()} schemas need either a common feature subset or per-protocol handling. Treat `-`/`---` "
      "placeholders as categorical ‘not applicable’ values. Drop IPs and timestamps, as the tracker already requires.")
    w(f"- M-3/H-6: the classes are imbalanced and vary by network ({lo['suspicious_pct']:.1f}%–{hi['suspicious_pct']:.1f}%). "
      "Use class weights and report per-network metrics.")
    w("")
    w("## 9. Limitations")
    w("")
    w("- MD5 proves the files are identical to what Zenodo publishes. It does not protect against a malicious publisher, "
      "and MD5 is not collision-resistant. SHA-256 was not available from the record.")
    w("- The numeric type profile (`mixed_or_text_columns_first_chunk_json`) covers only the first 200,000 rows of each "
      "file. Empty-cell, NA-token, duplicate and label counts cover every row.")
    w("- Only exact duplicates *within* a file were counted; cross-file and cross-network duplicates were not.")
    w("- H-1 did not check whether labels are correct in time against the attack schedule; that belongs to label "
      "auditing (H-3) and Reem's R-6.")
    w("")
    w("## 10. GO / NO-GO")
    w("")
    w("Criteria applied (set by this verification, not defined in the tracker):")
    w("")
    for txt, ok in crit:
        w(f"- [{'x' if ok else ' '}] {txt} — **{'PASS' if ok else 'FAIL'}**")
    w("")
    if go:
        w(f"**Decision: GO.** The AIT Netflow data is verified, complete and labelled well enough for the "
          f"Normal(0)/Suspicious(1) task. {total_flows - unmapped_total:,} of {total_flows:,} flows map to a binary "
          "label, and every network has attacks for a network-wise split. Conditions carried into Phase 2:")
        w("")
        w(f"1. Exclude (do not relabel) the {unmapped_total:,} unmapped flows, and document this in H-3.")
        k = 2
        if nocomp["suspicious_%"] > 90:
            k += 1
            w("2. Make an explicit, documented decision on `tcp_nocomplete` flows because of the label shortcut described in section 8.")
        w(f"{k}. Handle the {fq['schema_id'].nunique()} different schemas and the placeholder tokens in the feature contract (ALL-1/H-4).")
    else:
        w("**Decision: NO-GO.** One or more criteria failed (unchecked above). Resolve them before Phase 2, or switch to the "
          "CSE-CIC-IDS2018 backup (H-2).")
    w("")
    w("## Evidence files")
    w("")
    for fn in ("archive_checksums.csv", "csv_file_quality_report.csv", "label_counts_by_file.csv",
               "ait_network_attack_counts.csv", "label_mapping.json", "run_manifest.json", "run_log.txt"):
        w(f"- `{fn}`")
    w("- Scripts: `h1_ait_verify.py`, `h1_make_report.py`. Original script kept as `sentinelai_ait_verify.ORIGINAL.py`.")
    w("")
    (O / "H1_AIT_Verification_Report.md").write_text("\n".join(L), encoding="utf-8")
    print("GO" if go else "NO-GO")
    for txt, ok in crit:
        print(("PASS " if ok else "FAIL ") + txt)
    print("written", O / "H1_AIT_Verification_Report.md")


if __name__ == "__main__":
    main()
