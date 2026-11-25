"""L-6: build (or refresh) the persistent demo database from the fixtures.

    python scripts/init_demo.py            # safe to run again: nothing is duplicated
    python scripts/init_demo.py --reset    # delete the DEMO database and reports first

What it does
1. Opens data/platform/demo/sentinelai_demo.db (or --db).
2. Refuses to touch a database that holds data not marked as demo fixtures.
3. Writes every fixture message through SharedMemory.write() (contract-checked).
   Messages already stored with the same content are skipped.
4. Loads flow IDs from fixtures/features_sample.csv for flow evidence checks.
5. Runs the existing EvidenceValidator, then the existing Reporting Agent for each
   ReportRequest whose assessment matches the latest incident version.

Fixture data is invented. Its Random Forest scores are hand-written, not model output.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sentinelai.platform.config import FIXTURES_DIR, Settings, load_flow_ids  # noqa: E402
from sentinelai.platform.metadata import get_meta, message_count, set_meta, utc_now  # noqa: E402
from sentinelai.platform.reviews import ReviewStore  # noqa: E402
from sentinelai.platform.shared_memory import SharedMemory  # noqa: E402
from sentinelai.reporting.reporting_agent import ReportingAgent  # noqa: E402
from sentinelai.reporting.traceability import EvidenceValidator  # noqa: E402

FIXTURE_FILES = ("alerts.json", "incident_updates.json", "assessments.json", "report_requests.json")


class InitError(RuntimeError):
    pass


def initialise(db_path: Path, reports_dir: Path, fixtures_dir: Path = FIXTURES_DIR,
               reset: bool = False, log=print) -> dict:
    db_path, reports_dir = Path(db_path), Path(reports_dir)

    source = get_meta(db_path, "data_source")
    stored = message_count(db_path)
    if stored and source != "fixtures":
        raise InitError(
            f"{db_path} already holds {stored} message(s) that are not marked as demo fixtures. "
            "It will not be changed. Use another --db path for the demo."
        )

    if reset:
        if db_path.exists():
            db_path.unlink()
            log(f"Removed demo database {db_path.name}")
        if reports_dir.is_dir():
            old = list(reports_dir.glob("repreq-*.md"))
            for report in old:
                report.unlink()
            log(f"Removed {len(old)} generated demo report(s)")

    db_path.parent.mkdir(parents=True, exist_ok=True)
    memory = SharedMemory(str(db_path))
    ReviewStore(str(db_path))  # create the review table so the API finds it
    set_meta(db_path, "data_source", "fixtures")

    added = skipped = 0
    for filename in FIXTURE_FILES:
        for message in json.loads((fixtures_dir / filename).read_text(encoding="utf-8")):
            existing = memory.get(message["message_id"])
            if existing is not None:
                if existing != message:
                    raise InitError(
                        f"{message['message_id']} is stored with different content than {filename}. "
                        "Run with --reset to rebuild the demo database."
                    )
                skipped += 1
                continue
            memory.write(message)
            added += 1
    log(f"Fixture messages: {added} added, {skipped} already present")

    flow_ids = load_flow_ids(fixtures_dir / "features_sample.csv")
    log(f"Flow IDs available for evidence checks: {len(flow_ids or ())}")

    validation = EvidenceValidator().validate(memory, flow_ids)
    log(f"Evidence validation: {'passed' if validation['valid'] else 'FAILED'} "
        f"({validation['messages_checked']} messages checked)")
    for error in validation["errors"]:
        log(f"  - {error}")

    generated, not_current = [], []
    if validation["valid"]:
        agent = ReportingAgent(reports_dir, flow_ids=flow_ids)
        for request in memory.read("ReportRequest"):
            assessment = memory.get(request["assessment_id"])
            incident = memory.latest_incident(request["incident_id"])
            if not assessment or not incident or assessment["incident_version"] != incident["version"]:
                not_current.append(request["message_id"])
                continue
            path = agent.run(request, memory)
            generated.append(path.name)
            log(f"Report generated: {path.name}")
    for request_id in not_current:
        log(f"Skipped {request_id}: its assessment is not for the latest incident version")

    set_meta(db_path, "initialised_at", utc_now())
    return {"added": added, "skipped": skipped, "reports": generated,
            "validation_passed": validation["valid"], "flow_ids": len(flow_ids or ())}


def main(argv=None) -> int:
    demo = Settings.for_mode("demo")
    parser = argparse.ArgumentParser(description="Initialise the SentinelAI demo database from fixtures.")
    parser.add_argument("--db", type=Path, default=demo.db_path, help="demo database file")
    parser.add_argument("--reports-dir", type=Path, default=demo.reports_dir, help="demo reports folder")
    parser.add_argument("--reset", action="store_true", help="delete the demo database and reports first")
    args = parser.parse_args(argv)

    live = Settings.for_mode("live")
    if args.db.resolve() == Path(live.db_path).resolve():
        print("Refusing to load fixtures into the live database.", file=sys.stderr)
        return 2
    try:
        result = initialise(args.db, args.reports_dir, reset=args.reset)
    except InitError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(f"\nDemo database ready: {args.db}")
    print(f"Reports folder:      {args.reports_dir}")
    print("All demo data is synthetic (fixtures), not real agent output.")
    return 0 if result["validation_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
