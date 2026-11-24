
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import csv

from sentinelai.platform.shared_memory import SharedMemory
from sentinelai.reporting.reporting_agent import ReportingAgent


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"


def main():

    with TemporaryDirectory() as temp_dir:

        memory = SharedMemory(
            Path(temp_dir) / "reporting_demo.db"
        )

        for filename in (
            "alerts.json",
            "incident_updates.json",
            "assessments.json",
            "report_requests.json",
        ):
            messages = json.loads(
                (FIXTURES / filename).read_text(
                    encoding="utf-8"
                )
            )

            for message in messages:
                memory.write(message)

        with (FIXTURES / "features_sample.csv").open(
            encoding="utf-8", newline=""
        ) as file:
            flow_ids = {
                row["flow_id"]
                for row in csv.DictReader(file)
            }

        agent = ReportingAgent(
            ROOT / "reports",
            flow_ids=flow_ids,
        )
        
        generated = 0

        for request in memory.read("ReportRequest"):

            assessment = memory.get(
                request["assessment_id"]
            )

            incident = memory.latest_incident(
                request["incident_id"]
            )

            if assessment is None or incident is None:
                continue

            if (
                assessment["incident_version"]
                != incident["version"]
            ):
                continue

            report_path = agent.run(request, memory)

            print(f"Report generated: {report_path}")

            generated += 1

        print(f"\nTotal reports generated: {generated}")


if __name__ == "__main__":
    main()
    