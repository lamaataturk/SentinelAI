"""O-6 regression checks for the Response Agent severity decision table."""

import json
import random
import unittest
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory

from sentinelai.platform.shared_memory import SharedMemory
from sentinelai.response.response_agent import (
    ExploitationConfirmation,
    ResponseAgent,
    assess_severity,
)


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
CRITICAL_INVENTORY = {"fixture-net": {"host:wordpress": "critical"}}
EXPLOITATION_PROOF = ExploitationConfirmation(
    "alert-0004", "host:wordpress", "raw_log:reviewed-exploitation"
)


class ResponseSeverityTests(unittest.TestCase):
    def setUp(self):
        self.updates = json.loads((FIXTURES / "incident_updates.json").read_text(encoding="utf-8"))
        self.attack = self.updates[1]

    def assert_policy(self, incident, severity, rule_id, **context):
        decision = assess_severity(incident, **context)
        self.assertEqual((decision.severity, decision.rule_id), (severity, rule_id))
        self.assertTrue(decision.reasons)
        self.assertIn(f"incident:{incident['incident_id']}", decision.evidence_refs)
        return decision

    def restrict_stages(self, *names, support=None):
        self.attack["candidate_techniques"] = []
        stages = [stage for stage in self.attack["stage_hypotheses"] if stage["stage"] in names]
        if support is not None:
            for stage in stages:
                stage["support"] = support
        self.attack["stage_hypotheses"] = stages
        return {stage["stage"]: stage for stage in stages}

    def test_fixture_expectations(self):
        expected = {
            "incupd-0001": ("Medium", "SEV-STRONG-EVIDENCE"),
            "incupd-0002": ("High", "SEV-MULTISTAGE-OBJECTIVE"),
            "incupd-0003": ("Low", "SEV-SINGLE-WEAK"),
            "incupd-0004": ("Low", "SEV-SINGLE-UNMAPPED"),
            "incupd-0005": ("Low", "SEV-SINGLE-UNMAPPED"),
        }
        by_id = {update["message_id"]: update for update in self.updates}
        for message_id, (severity, rule_id) in expected.items():
            with self.subTest(message_id=message_id):
                self.assert_policy(by_id[message_id], severity, rule_id)

    def test_repeated_reordered_or_duplicated_evidence_gives_same_decision(self):
        snapshot = deepcopy(self.attack)
        expected = assess_severity(self.attack)
        self.assertEqual(assess_severity(self.attack), expected)
        for seed in range(5):
            with self.subTest(seed=seed):
                randomizer = random.Random(seed)
                reordered = deepcopy(self.attack)
                for key in ("alert_ids", "candidate_techniques", "stage_hypotheses", "link_reasons"):
                    randomizer.shuffle(reordered[key])
                for items in reordered["entities"].values():
                    randomizer.shuffle(items)
                for finding in reordered["candidate_techniques"] + reordered["stage_hypotheses"]:
                    randomizer.shuffle(finding["evidence_refs"])
                    finding["evidence_refs"] += finding["evidence_refs"][:1]
                reordered["link_reasons"].append(deepcopy(reordered["link_reasons"][0]))
                reordered["alert_ids"].append(reordered["alert_ids"][0])
                self.assertEqual(assess_severity(reordered), expected)
        self.assertEqual(self.attack, snapshot)

    def test_two_weak_stages_need_two_linked_supporting_alerts(self):
        stages = self.restrict_stages("command_and_control", "actions_on_objectives", support="weak")
        self.attack["link_reasons"] = [
            link for link in self.attack["link_reasons"] if link["alert_id"] == "alert-0007"
        ]
        decision = self.assert_policy(self.attack, "Medium", "SEV-MULTISTAGE-WEAK")
        self.assertTrue(any("weak alert link" in reason for reason in decision.reasons))

        stages["actions_on_objectives"]["evidence_refs"] = ["alert:alert-0006"]
        self.assert_policy(self.attack, "Low", "SEV-LIMITED-EVIDENCE")

    def test_links_through_an_unrelated_alert_cannot_join_stages(self):
        self.restrict_stages("command_and_control", "actions_on_objectives", support="weak")
        bridge = next(link for link in self.attack["link_reasons"] if link["alert_id"] == "alert-0007")
        self.attack["link_reasons"] = [
            {**bridge, "alert_id": "alert-9999", "linked_to": "alert-0006"},
            {**bridge, "alert_id": "alert-0007", "linked_to": "alert-9999"},
        ]
        self.assert_policy(self.attack, "Low", "SEV-LIMITED-EVIDENCE")

    def test_high_requires_three_distinct_linked_stages(self):
        self.restrict_stages("exploitation", "command_and_control", "actions_on_objectives")
        self.assert_policy(self.attack, "High", "SEV-MULTISTAGE-OBJECTIVE")
        self.attack["stage_hypotheses"] = [
            stage for stage in self.attack["stage_hypotheses"] if stage["stage"] != "command_and_control"
        ]
        self.attack["stage_hypotheses"].append(deepcopy(self.attack["stage_hypotheses"][-1]))
        self.assert_policy(self.attack, "Medium", "SEV-STRONG-EVIDENCE")

    def test_high_requires_strong_objective_evidence_in_the_linked_group(self):
        objective = next(stage for stage in self.attack["stage_hypotheses"]
                         if stage["stage"] == "actions_on_objectives")
        objective["support"] = "weak"
        self.assert_policy(self.attack, "Medium", "SEV-STRONG-EVIDENCE")

        objective["support"] = "strong"
        self.attack["link_reasons"] = [
            link for link in self.attack["link_reasons"] if link["alert_id"] != "alert-0007"
        ]
        # A weak observation in the main chain cannot borrow strength from a separate one.
        self.attack["stage_hypotheses"].append(
            {**objective, "support": "weak", "evidence_refs": ["alert:alert-0006"]}
        )
        self.assert_policy(self.attack, "Medium", "SEV-STRONG-EVIDENCE")

    def test_only_observational_refs_count_as_evidence(self):
        self.restrict_stages("reconnaissance", "exploitation", "actions_on_objectives")
        for stage in self.attack["stage_hypotheses"]:
            stage["evidence_refs"] = ["rule:O1-T1595", "alert:alert-9999"]
        decision = self.assert_policy(self.attack, "Low", "SEV-LIMITED-EVIDENCE")
        self.assertEqual(decision.evidence_refs, ("incident:inc-0001",))

        for stage, reference in zip(self.attack["stage_hypotheses"], (
            "raw_log:case/recon", "flow:f-000025", "raw_log:case/objectives",
        )):
            stage["evidence_refs"] = [reference]
        self.assert_policy(self.attack, "Medium", "SEV-STRONG-EVIDENCE")

    def test_critical_takes_precedence_and_cites_reviewed_evidence(self):
        decision = self.assert_policy(
            self.attack, "Critical", "SEV-CRITICAL-ASSET-EXPLOIT",
            asset_inventory=CRITICAL_INVENTORY,
            exploitation_confirmations=(EXPLOITATION_PROOF,),
        )
        self.assertIn(EXPLOITATION_PROOF.raw_log_ref, decision.evidence_refs)
        self.assertTrue(any(EXPLOITATION_PROOF.asset in reason for reason in decision.reasons))

        second_proof = ExploitationConfirmation(
            EXPLOITATION_PROOF.alert_id, EXPLOITATION_PROOF.asset, "raw_log:second-review"
        )
        for proofs in ((EXPLOITATION_PROOF, second_proof), (second_proof, EXPLOITATION_PROOF)):
            self.assertEqual(
                assess_severity(self.attack, asset_inventory=CRITICAL_INVENTORY,
                                exploitation_confirmations=proofs),
                decision,
            )

    def test_critical_rejects_incomplete_or_mismatched_confirmation(self):
        cases = (
            ("no confirmation", CRITICAL_INVENTORY, ()),
            ("high asset", {"fixture-net": {"host:wordpress": "high"}}, (EXPLOITATION_PROOF,)),
            ("different network", {"elsewhere": {"host:wordpress": "critical"}}, (EXPLOITATION_PROOF,)),
            ("different asset", {"fixture-net": {"host:other": "critical"}},
             (ExploitationConfirmation("alert-0004", "host:other", "raw_log:review"),)),
            ("wrong alert", CRITICAL_INVENTORY,
             (ExploitationConfirmation("alert-0001", "host:wordpress", "raw_log:review"),)),
            ("missing log ID", CRITICAL_INVENTORY,
             (ExploitationConfirmation("alert-0004", "host:wordpress", "raw_log:"),)),
            ("unsupported log type", CRITICAL_INVENTORY,
             (ExploitationConfirmation("alert-0004", "host:wordpress", "rule:example"),)),
        )
        for case, inventory, confirmations in cases:
            with self.subTest(case=case):
                decision = self.assert_policy(
                    self.attack, "High", "SEV-MULTISTAGE-OBJECTIVE",
                    asset_inventory=inventory, exploitation_confirmations=confirmations,
                )
                self.assertNotIn("raw_log:review", decision.evidence_refs)

        stage = next(stage for stage in self.attack["stage_hypotheses"]
                     if stage["stage"] == "exploitation")
        stage["support"] = "weak"
        self.assert_policy(
            self.attack, "High", "SEV-MULTISTAGE-OBJECTIVE",
            asset_inventory=CRITICAL_INVENTORY,
            exploitation_confirmations=(EXPLOITATION_PROOF,),
        )

    def test_reviewed_exploitation_is_scoped_to_its_incident_version(self):
        key = self.attack["incident_id"], self.attack["version"]
        agent = ResponseAgent(
            asset_inventory=CRITICAL_INVENTORY,
            exploitation_confirmations={key: (EXPLOITATION_PROOF,)},
        )
        latest = {**self.attack, "message_id": "incupd-o6-v3", "version": self.attack["version"] + 1}

        with TemporaryDirectory() as directory:
            memory = SharedMemory(Path(directory) / "messages.db")
            memory.write(self.attack)
            self.assertEqual(agent.run(self.attack, memory)["severity"], "Critical")
            memory.write(latest)
            self.assertEqual(agent.run(latest, memory)["severity"], "High")


if __name__ == "__main__":
    unittest.main()
