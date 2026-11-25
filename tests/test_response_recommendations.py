"""Verify evidence-backed recommendations and their reporting handoff."""

import json
import tempfile
import unittest
from pathlib import Path

from sentinelai.contracts.messages import validate_bundle
from sentinelai.platform.orchestrator import Orchestrator
from sentinelai.platform.shared_memory import SharedMemory
from sentinelai.reporting.reporting_agent import ReportingAgent
from sentinelai.response.response_agent import ResponseAgent, recommendations_for


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
TECHNIQUES = {
    "T1595": "Active Scanning",
    "T1190": "Exploit Public-Facing Application",
    "T1505.003": "Server Software Component: Web Shell",
    "T1059": "Command and Scripting Interpreter",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1548.003": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
}
RECOMMENDATION_KEYS = {"action", "reason", "technique_id", "requires_human_approval"}


def read_fixture(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def candidate(technique, support, *evidence_refs):
    return {
        "technique_id": technique,
        "name": TECHNIQUES.get(technique, "Unknown technique"),
        "support": support,
        "evidence_refs": list(evidence_refs),
    }


class ResponseRecommendationTests(unittest.TestCase):
    def setUp(self):
        self.incident = read_fixture("incident_updates.json")[1]

    def test_supported_techniques_offer_distinct_advice_for_strong_and_weak_evidence(self):
        for technique in TECHNIQUES:
            with self.subTest(technique=technique):
                records = {}
                for support, evidence_ref in (
                    ("weak", "alert:alert-0001"),
                    ("strong", "raw_log:reviewed-observation"),
                ):
                    self.incident["candidate_techniques"] = [
                        candidate(technique, support, evidence_ref)
                    ]
                    record, = recommendations_for(self.incident)
                    self.assertEqual(set(record), RECOMMENDATION_KEYS)
                    self.assertEqual(record["technique_id"], technique)
                    self.assertIs(record["requires_human_approval"], True)
                    self.assertTrue(record["action"].strip())
                    self.assertIn(evidence_ref, record["reason"])
                    records[support] = record

                self.assertNotEqual(records["weak"]["action"], records["strong"]["action"])

    def test_single_weak_alert_produces_advice_for_human_review(self):
        incident = read_fixture("incident_updates.json")[2]
        self.assertEqual(len(incident["alert_ids"]), 1)
        advice, = recommendations_for(incident)
        self.assertEqual(advice["technique_id"], "T1595")
        self.assertIs(advice["requires_human_approval"], True)
        self.assertIn(f"alert:{incident['alert_ids'][0]}", advice["reason"])

    def test_reviewed_logs_are_cited_before_alerts_and_flows(self):
        self.incident["candidate_techniques"] = [candidate(
            "T1190", "strong", "flow:f-000001", "alert:alert-0004", "alert:alert-0003",
            "alert:alert-0002", "raw_log:reviewed-observation",
        )]
        advice, = recommendations_for(self.incident)
        self.assertIn(
            "Evidence includes raw_log:reviewed-observation, alert:alert-0002, alert:alert-0003.",
            advice["reason"],
        )

    def test_unmapped_unknown_and_unsubstantiated_candidates_produce_no_advice(self):
        self.incident["candidate_techniques"] = [
            candidate("T1595", "unmapped", "alert:alert-0001"),
            candidate("T9999", "strong", "alert:alert-0002"),
            candidate("T1190", "weak", "rule:example"),
            candidate("T1059", "strong", "alert:alert-0010"),
        ]
        self.assertEqual(recommendations_for(self.incident), [])

    def test_strongest_candidate_wins_and_order_is_deterministic(self):
        strong = candidate("T1595", "strong", "raw_log:reviewed-scan")
        weak = candidate("T1595", "weak", "alert:alert-0001")
        other = candidate("T1048", "weak", "alert:alert-0007")
        self.incident["candidate_techniques"] = [strong]
        expected, = recommendations_for(self.incident)

        self.incident["candidate_techniques"] = [weak, other, strong]
        first = recommendations_for(self.incident)
        self.incident["candidate_techniques"] = [strong, other, weak]
        second = recommendations_for(self.incident)

        self.assertEqual(first, second)
        self.assertEqual(len(first), 2)
        actual, = [record for record in first if record["technique_id"] == "T1595"]
        self.assertEqual(actual, expected)

    def test_orchestrator_report_renders_written_recommendations(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            memory = SharedMemory(root / "messages.db")
            alerts = read_fixture("alerts.json")
            for alert in alerts:
                memory.write(alert)
            memory.write(self.incident)

            reporting = ReportingAgent(output_dir=root / "reports")
            orchestrator = Orchestrator(memory, None, ResponseAgent(), reporting)
            # The fixture IncidentUpdate already contains the investigated alerts.
            orchestrator.processed.update(alert["message_id"] for alert in alerts)
            results = orchestrator.run_once()
            self.assertEqual(results["reports_processed"], 1)
            self.assertEqual(validate_bundle(memory.read()), [])

            assessment, = memory.read("Assessment")
            request, = memory.read("ReportRequest")
            self.assertEqual(request["assessment_id"], assessment["message_id"])
            recommendations = assessment["recommendations"]
            self.assertCountEqual(
                [record["technique_id"] for record in recommendations],
                [item["technique_id"] for item in self.incident["candidate_techniques"]],
            )
            report = reporting.reports[request["message_id"]].read_text(encoding="utf-8")
            self.assertEqual(report.count("Human approval required: Yes"), len(recommendations))
            for record in recommendations:
                self.assertIn(record["action"], report)
                self.assertIn(record["reason"], report)


if __name__ == "__main__":
    unittest.main()
