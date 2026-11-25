#!/usr/bin/env python3
"""H-5: build the feature table for one or more AIT networks.

    python scripts/build_features.py --data-dir path/to/downloads --networks fox
    python scripts/build_features.py --data-dir path/to/downloads --networks all

--data-dir holds the AIT files exactly as downloaded from Zenodo record 13168643
(<network>_netflows.zip and label_info.txt). Output per network goes to
data/processed/ (git-ignored):
    features_<network>.csv.gz      the contract table (sentinelai/contracts/features.py)
    features_<network>.summary.json  counts, checks and checksum
    unmapped_<network>.csv         rows left out by the H-3 rule (empty/unknown labels)

Every run checks: archive MD5 = official value, the table passes
validate_feature_frame(), labeled + unmapped rows = rows in the CSVs, and the
windows stay the same when all later flows are removed (no future).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sentinelai.contracts.features import ALL_COLUMNS, validate_feature_frame  # noqa: E402
from sentinelai.data import features as F  # noqa: E402
from sentinelai.data.labeling import RULE_VERSION, load_label_info  # noqa: E402

NETWORKS = ["fox", "harrison", "russellmitchell", "santos", "shaw", "wardbeck", "wheeler", "wilson"]
# Official MD5s from the Zenodo API, record 13168643 (checked in H-1).
OFFICIAL_MD5 = {
    "fox": "d3024ef6033fbd45982464f6b6f50984",
    "harrison": "840224491fb31d548e7ee0ecbd951db5",
    "russellmitchell": "290aa5b8b0a9d0515b7e99329c467364",
    "santos": "e217db1c0307a8966db9e79609789fcb",
    "shaw": "25c5a62572d37f088353cf7bbd58f590",
    "wardbeck": "3a73afcaef00a1bbe53f1c39060c2f17",
    "wheeler": "2c45193c0babc8ec45f356f3e39118a6",
    "wilson": "2c10183cf7aca03e9fb80408a360f34c",
}


def md5(path: Path) -> str:
    h = hashlib.md5()
    with path.open("rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def no_future_check(flows: pd.DataFrame, full: pd.DataFrame, n_cuts: int) -> list[dict]:
    """Recompute on flows that started before a cut; earlier rows must not change."""
    full = full.set_index("flow_id")
    checks = []
    for q in sorted(np.random.default_rng(42).uniform(0.1, 0.9, n_cuts)):
        cut = float(flows["start_ms"].quantile(q))
        part = F.compute_features(flows[flows["start_ms"] < cut]).set_index("flow_id")
        same = part.equals(full.loc[part.index, part.columns])
        checks.append({"cut_utc": str(pd.to_datetime(cut, unit="ms", utc=True)),
                       "rows_before_cut": len(part), "identical": bool(same)})
    return checks


def build_one(net: str, data_dir: Path, out_dir: Path, label_map: dict, n_cuts: int) -> dict:
    t0 = time.time()
    zip_path = data_dir / f"{net}_netflows.zip"
    got = md5(zip_path)
    if got != OFFICIAL_MD5[net]:
        raise SystemExit(f"[STOP] {zip_path.name}: md5 {got} != official {OFFICIAL_MD5[net]}")
    flows = F.read_network_zip(zip_path, net)
    table, unmapped = F.build_feature_table(flows, label_map)

    problems = validate_feature_frame(table)
    if list(table.columns) != ALL_COLUMNS:
        problems.append("column order differs from ALL_COLUMNS")
    if len(table) + len(unmapped) != len(flows):
        problems.append("labeled + unmapped rows != rows read")
    checks = no_future_check(flows, F.compute_features(flows), n_cuts)
    if not all(c["identical"] for c in checks):
        problems.append("window features changed when later flows were removed")
    if problems:
        raise SystemExit(f"[STOP] {net}: " + "; ".join(problems))

    out_dir.mkdir(parents=True, exist_ok=True)
    fpath = out_dir / f"features_{net}.csv.gz"
    table.to_csv(fpath, index=False)
    unmapped[["flow_id", "source_file", "label_raw"]].to_csv(out_dir / f"unmapped_{net}.csv", index=False)
    by_file = flows.assign(label=pd.concat([table.set_index("flow_id")["label"],
                                            unmapped.set_index("flow_id")["label"]]).loc[flows["flow_id"]].to_numpy())
    summary = {
        "network": net, "file": fpath.name, "sha256": hashlib.sha256(fpath.read_bytes()).hexdigest(),
        "rows": len(table), "normal": int((table.label == 0).sum()), "suspicious": int((table.label == 1).sum()),
        "unmapped_left_out": len(unmapped),
        "per_source_file": {f: {"rows": len(g), "normal": int((g.label == 0).sum()),
                                "suspicious": int((g.label == 1).sum()), "unmapped": int(g.label.isna().sum())}
                            for f, g in by_file.groupby("source_file")},
        "no_future_checks": checks, "source_archive_md5": got,
        "feature_module_version": F.FEATURE_MODULE_VERSION, "labeling_rule_version": RULE_VERSION,
        "time_range_utc": [table.start_time.min(), table.start_time.max()],
        "runtime_s": round(time.time() - t0, 1),
    }
    (out_dir / f"features_{net}.summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--data-dir", required=True, type=Path, help="folder with <network>_netflows.zip + label_info.txt")
    ap.add_argument("--networks", nargs="+", default=["fox"], help="network names, or 'all'")
    ap.add_argument("--out-dir", type=Path, default=ROOT / "data" / "processed")
    ap.add_argument("--future-checks", type=int, default=3)
    a = ap.parse_args(argv)
    nets = NETWORKS if a.networks == ["all"] else a.networks
    unknown = set(nets) - set(NETWORKS)
    if unknown:
        raise SystemExit(f"unknown network(s): {sorted(unknown)}")
    label_map = load_label_info(a.data_dir / "label_info.txt")      # refuses a non-official copy
    for net in nets:
        s = build_one(net, a.data_dir, a.out_dir, label_map, a.future_checks)
        print(f"[ok] {net}: {s['rows']:,} rows ({s['normal']:,} normal, {s['suspicious']:,} suspicious), "
              f"{s['unmapped_left_out']:,} unmapped left out, no-future checks passed, "
              f"{s['runtime_s']} s -> {a.out_dir / s['file']}")
        for f, c in s["per_source_file"].items():
            print(f"       {f:<20} rows={c['rows']:>8,} normal={c['normal']:>8,} "
                  f"suspicious={c['suspicious']:>8,} unmapped={c['unmapped']:>5,}")


if __name__ == "__main__":
    main()
