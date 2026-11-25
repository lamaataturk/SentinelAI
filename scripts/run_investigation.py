"""Run the Investigation Agent on AIT-ADS networks or the demo scenarios.

    python scripts/run_investigation.py --tuning      # russellmitchell, santos, shaw
    python scripts/run_investigation.py --test        # R-6 final test: fox, harrison, wardbeck, wheeler, wilson
    python scripts/run_investigation.py --scenarios   # demo scenarios 1 and 2

Writes out/investigation/incident_updates_<network>.jsonl (the messages for the
Response Agent) and, for real networks, a results CSV scored against the answers.
Needs data/processed/ait_ads from scripts/prepare_ait_ads.py, and Omar's O-3 mapper.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sentinelai.contracts.messages import validate_message  # noqa: E402
from sentinelai.investigation.ait_ads import read_table  # noqa: E402
from sentinelai.investigation.correlation import CorrelationConfig, investigate  # noqa: E402
from sentinelai.investigation.evaluate import evaluate  # noqa: E402
from sentinelai.investigation.incident_updates import incident_updates  # noqa: E402
from sentinelai.investigation.scenarios import EXTERNAL_SOURCES, write_scenarios  # noqa: E402

TUNE = ["russellmitchell", "santos", "shaw"]
TEST = ["fox", "harrison", "wardbeck", "wheeler", "wilson"]   # never used for design or tuning


def write_jsonl(msgs: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for m in msgs:
            f.write(json.dumps(m) + "\n")


def run_network(net: str, data: Path, out: Path, cfg: CorrelationConfig) -> dict:
    alerts = read_table(data / f"{net}_alerts")
    a, g, links, inc = investigate(alerts, cfg)                      # agent: no answers
    msgs = incident_updates(a, g, links, inc, net)
    problems = [p for m in msgs for p in validate_message(m)]
    write_jsonl(msgs, out / f"incident_updates_{net}.jsonl")
    labels = read_table(data / f"{net}_eval")                        # evaluation only
    return evaluate(net, a, links, inc, msgs, labels, problems)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Run the Investigation Agent")
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("--tuning", action="store_true")
    group.add_argument("--test", action="store_true")
    group.add_argument("--scenarios", action="store_true")
    group.add_argument("--networks", nargs="+")
    ap.add_argument("--data", type=Path, default=ROOT / "data" / "processed" / "ait_ads")
    ap.add_argument("--out", type=Path, default=ROOT / "out" / "investigation")
    args = ap.parse_args(argv)
    cfg = CorrelationConfig()

    if args.scenarios:
        for name, (alerts_s, _truth) in write_scenarios(args.out / "scenarios").items():
            a, g, links, inc = investigate(alerts_s, cfg)
            msgs = incident_updates(a, g, links, inc, name, external_sources=EXTERNAL_SOURCES)
            write_jsonl(msgs, args.out / f"incident_updates_{name}.jsonl")
            print(f"{name}: {len(msgs)} incidents")
        return

    nets = TUNE if args.tuning else TEST if args.test else args.networks
    results = pd.DataFrame([run_network(n, args.data, args.out, cfg) for n in nets])
    name = "tuning_results.csv" if args.tuning else "final_test_results.csv" if args.test else "results.csv"
    results.to_csv(args.out / name, index=False)
    with pd.option_context("display.max_colwidth", 60, "display.width", 200):
        print(results.set_index("network").T.to_string())
    print(f"\nwritten: {args.out / name}")


if __name__ == "__main__":
    main()
