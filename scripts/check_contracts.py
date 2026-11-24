"""ALL-3: contract checker for integration week (and for every pull request).

Checks a feature CSV and/or message JSON files against the team contracts,
including that every evidence reference points to something that exists.

    python scripts/check_contracts.py                       # checks fixtures/
    python scripts/check_contracts.py --features out/features.csv \
        --messages out/alerts.json out/incident_updates.json

Exit code 0 = everything follows the contract, 1 = problems were printed.
Also accepts a SQLite file exported by the shared memory (--sqlite), as long
as it has a table `messages` with a column `body` holding each message's JSON.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sentinelai.contracts.features import validate_feature_frame  # noqa: E402
from sentinelai.contracts.messages import validate_bundle  # noqa: E402

FIXTURES = ROOT / "fixtures"
DEFAULT_MESSAGES = ["alerts.json", "incident_updates.json", "assessments.json", "report_requests.json"]


def load_messages(paths, sqlite_path=None):
    msgs = []
    for p in paths:
        data = json.loads(Path(p).read_text())
        msgs += data if isinstance(data, list) else [data]
    if sqlite_path:
        con = sqlite3.connect(sqlite_path)
        msgs += [json.loads(row[0]) for row in con.execute("SELECT body FROM messages")]
        con.close()
    return msgs


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--features")
    ap.add_argument("--messages", nargs="*")
    ap.add_argument("--sqlite")
    args = ap.parse_args(argv)

    use_fixtures = not (args.features or args.messages or args.sqlite)
    features = args.features or (str(FIXTURES / "features_sample.csv") if use_fixtures else None)
    messages = args.messages if args.messages is not None else (
        [str(FIXTURES / m) for m in DEFAULT_MESSAGES] if use_fixtures else [])

    problems = []
    flow_ids = None
    if features:
        import pandas as pd
        df = pd.read_csv(features)
        problems += [f"features: {e}" for e in validate_feature_frame(df)]
        flow_ids = set(df["flow_id"]) if "flow_id" in df.columns else None
        print(f"checked {len(df)} flows from {features}")
    msgs = load_messages(messages, args.sqlite)
    if msgs:
        problems += validate_bundle(msgs, flow_ids)
        print(f"checked {len(msgs)} messages")

    if problems:
        print(f"\n{len(problems)} problem(s):")
        for p in problems:
            print("  -", p)
        return 1
    print("OK: everything follows the contract")
    return 0


if __name__ == "__main__":
    sys.exit(main())
