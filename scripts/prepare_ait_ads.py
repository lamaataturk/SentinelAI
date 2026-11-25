"""R-1: turn the AIT-ADS CSV export into one alerts table and one answers table per network.

Download alerts_csv.zip from https://github.com/ait-aecid/alert-data-set and unzip it, then:

    python scripts/prepare_ait_ads.py --csv-dir data/raw/alerts_csv --out data/processed/ait_ads

Writes <network>_alerts.parquet (what the agent may read) and <network>_eval.parquet
(the answers, read only by evaluation).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sentinelai.investigation.ait_ads import SCENARIOS, load_alert_csv, save_table  # noqa: E402


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--csv-dir", type=Path, default=ROOT / "data" / "raw" / "alerts_csv")
    ap.add_argument("--out", type=Path, default=ROOT / "data" / "processed" / "ait_ads")
    ap.add_argument("--networks", nargs="*", default=SCENARIOS)
    args = ap.parse_args(argv)
    for net in args.networks:
        alerts, labels = load_alert_csv(args.csv_dir / f"{net}_alerts.txt", net)
        a = save_table(alerts, args.out / f"{net}_alerts")
        e = save_table(labels, args.out / f"{net}_eval")
        print(f"{net}: {len(alerts):,} alerts -> {a.name}, {e.name}")


if __name__ == "__main__":
    main()
