"""O-7: compare the framework mapping with the ground truth of the two demo scenarios.

    python scripts/mapping_agreement.py                 # print the Markdown report
    python scripts/mapping_agreement.py --out report.md # also write it to a file

The comparison covers two small, hand-written scenarios. It is not a measure of
general accuracy. See docs/frameworks/o7-mapping-agreement.md.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sentinelai.frameworks.agreement import agreement_report  # noqa: E402


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, help="also write the report to this file")
    args = parser.parse_args(argv)
    report = agreement_report()
    print(report, end="")
    if args.out:
        args.out.write_text(report, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
