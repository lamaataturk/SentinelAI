"""Exercise assessment writes and the handoff through SQLite shared memory."""

import csv
import json
import tempfile
import unittest
from pathlib import Path

from sentinelai.contracts.messages import validate_bundle
from sentinelai.platform.orchestrator import Orchestrator
from sentinelai.platform.shared_memory import SharedMemory
from sentinelai.reporting.reporting_agent import ReportingAgent
from sentinelai.response.response_agent import ResponseAgent


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def read_fixture(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class ResponseIntegrationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.tmp_path = Path(directory.name)
        self.db_path = self.tmp_path / "messages.db"
        self.memory = SharedMemory(self.db_path)
        self.response = ResponseAgent()
        self.initial, self.latest = read_fixture("incident_updates.json")[:2]
        for alert in read_fixture("alerts.json"):
            self.memory.write(alert)

    def test_skips_stale_queue_item_and_writes_latest_assessment(self):
        self.memory.write(self.initial)
        self.memory.write(self.latest)

        self.assertIsNone(self.response.run(self.initial, self.memory))
        self.assertEqual(self.memory.read("Assessment"), [])

        assessment = self.response.run(self.latest, self.memory)
        self.assertEqual(assessment["incident_id"], self.latest["incident_id"])
        self.assertEqual(assessment["incident_version"], self.latest["version"])
        self.assertEqual(assessment["severity"], "High")
        self.assertEqual(assessment["review_status"], "pending")
        self.assertEqual(self.memory.read("Assessment"), [assessment])
        self.assertEqual(validate_bundle(self.memory.read()), [])

    def test_retries_reuse_assessment_and_new_version_is_assessed(self):
        self.memory.write(self.initial)
        first = self.response.run(self.initial, self.memory)
        self.assertEqual(first["incident_version"], self.initial["version"])

        # Create fresh agent and store handles to exercise persisted state.
        restarted_response = ResponseAgent()
        reopened_memory = SharedMemory(self.db_path)
        self.assertEqual(restarted_response.run(self.initial, reopened_memory), first)

        reopened_memory.write(self.latest)
        second = restarted_response.run(self.latest, reopened_memory)
        self.assertNotEqual(first["message_id"], second["message_id"])
        self.assertEqual(second["incident_version"], self.latest["version"])
        self.assertEqual(restarted_response.run(self.latest, reopened_memory), second)
        self.assertIsNone(restarted_response.run(self.initial, reopened_memory))
        self.assertEqual(reopened_memory.read("Assessment"), [first, second])

    def test_reuses_existing_assessment_with_legacy_message_id(self):
        self.memory.write(self.initial)
        self.memory.write(self.latest)
        legacy = read_fixture("assessments.json")[0]
        self.memory.write(legacy)

        self.assertEqual(self.response.run(self.latest, self.memory), legacy)
        self.assertEqual(self.memory.read("Assessment"), [legacy])

    def test_orchestrator_submits_assessment_to_reporting_agent(self):
        self.memory.write(self.initial)
        self.memory.write(self.latest)
        with (FIXTURES / "features_sample.csv").open(
            encoding="utf-8", newline=""
        ) as stream:
            flow_ids = {row["flow_id"] for row in csv.DictReader(stream)}
        reporter = ReportingAgent(output_dir=self.tmp_path / "reports", flow_ids=flow_ids)
        orchestrator = Orchestrator(self.memory, None, self.response, reporter)
        # The fixture incidents were already constructed by the investigation step.
        orchestrator.processed.update(
            alert["message_id"] for alert in self.memory.read("Alert")
        )

        results = orchestrator.run_once()
        self.assertEqual(results["incidents_processed"], 2)
        self.assertEqual(results["assessments_processed"], 1)
        self.assertEqual(results["reports_processed"], 1)

        assessment, = self.memory.read("Assessment")
        request, = self.memory.read("ReportRequest")
        self.assertEqual(request["assessment_id"], assessment["message_id"])
        self.assertEqual(assessment["incident_version"], self.latest["version"])
        self.assertEqual(assessment["severity"], "High")
        path = reporter.reports[request["message_id"]]
        report = path.read_text(encoding="utf-8")
        self.assertIn("**Incident version:** 2", report)
        self.assertIn("**Assigned severity:** High", report)
        self.assertIn("Flow reference validation: Passed", report)
        self.assertEqual(validate_bundle(self.memory.read(), flow_ids), [])

        self.assertEqual(orchestrator.run_once()["reports_processed"], 0)
        self.assertEqual(list(reporter.output_dir.glob("*.md")), [path])


if __name__ == "__main__":
    unittest.main()
