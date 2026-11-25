"""Validate the O-1 data and its IncidentUpdate projections."""
import json
import unittest
from pathlib import Path

from sentinelai.contracts.messages import (
    KILL_CHAIN_STAGES,
    SCHEMA_VERSION,
    SUPPORT_LEVELS,
    validate_bundle,
)

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "sentinelai" / "frameworks"
FIXTURES = ROOT / "fixtures"


def read_json(directory, name):
    return json.loads((directory / name).read_text(encoding="utf-8"))


class KnowledgeBaseTests(unittest.TestCase):
    def setUp(self):
        self.techniques = read_json(DATA, "attack_techniques.json")
        self.stages = read_json(DATA, "kill_chain_stages.json")
        self.mapping = read_json(DATA, "technique_stage_mapping.json")
        self.alerts = read_json(FIXTURES, "alerts.json")

    def test_catalog_scope_and_provenance(self):
        records = self.techniques["techniques"]
        self.assertCountEqual(
            [record["technique_id"] for record in records],
            ["T1595", "T1190", "T1505.003", "T1059", "T1048", "T1548.003"],
        )
        for record in records:
            with self.subTest(technique=record["technique_id"]):
                path = record["technique_id"].replace(".", "/")
                self.assertEqual(record["source_url"], f"https://attack.mitre.org/techniques/{path}/")
                self.assertTrue(record["description"])
                self.assertTrue(record["source_version"])
        stages = self.stages["stages"]
        self.assertEqual(tuple(row["stage"] for row in stages), KILL_CHAIN_STAGES)
        self.assertEqual([row["order"] for row in stages], list(range(1, 8)))
        self.assertTrue(all(row["description"] for row in stages))
        self.assertTrue(self.stages["source_url"].startswith("https://www.lockheedmartin.com/"))

    def test_mapping_references_and_evidence_guidance(self):
        self.assertEqual(self.mapping["message_schema_version"], SCHEMA_VERSION)
        self.assertCountEqual(self.mapping["support_levels"], SUPPORT_LEVELS)
        self.assertEqual(set(self.mapping["support_policy"]), SUPPORT_LEVELS)
        self.assertEqual(set(self.mapping["stage_support_policy"]), SUPPORT_LEVELS)
        self.assertTrue(all(self.mapping["stage_support_policy"].values()))
        for data in (self.techniques, self.stages, self.mapping):
            self.assertEqual(data["schema_version"], "1.0")
        rules = self.mapping["rules"]
        self.assertCountEqual(
            [row["technique_id"] for row in rules],
            [row["technique_id"] for row in self.techniques["techniques"]],
        )
        self.assertEqual(len({row["mapping_rule_id"] for row in rules}), len(rules))
        fixture_rule_ids = {rule for alert in self.alerts for rule in alert["rule_hits"]}
        for row in rules:
            with self.subTest(rule=row["mapping_rule_id"]):
                self.assertLessEqual(set(row["detection_rule_ids"]), fixture_rule_ids)
                self.assertEqual(set(row["technique_evidence"]), {"weak", "strong", "limitations"})
                self.assertTrue(all(row["technique_evidence"].values()))
                for hypothesis in row["stage_hypotheses"]:
                    self.assertIn(hypothesis["stage"], KILL_CHAIN_STAGES)
                    self.assertTrue(hypothesis["requires"])

    def test_sudo_entry_keeps_privilege_escalation_without_a_kill_chain_stage(self):
        record = next(row for row in self.techniques["techniques"] if row["technique_id"] == "T1548.003")
        rule = next(row for row in self.mapping["rules"] if row["technique_id"] == "T1548.003")
        self.assertEqual(record["parent_technique_id"], "T1548")
        self.assertEqual(record["tactics"], ["Privilege Escalation"])
        self.assertEqual(rule["mapping_rule_id"], "O1-T1548.003")
        self.assertEqual(rule["stage_hypotheses"], [])

    def test_projection_uses_existing_message_contract(self):
        incidents = read_json(FIXTURES, "incident_updates.json")
        incident = next(item for item in incidents if item["message_id"] == "incupd-0002")
        records = {row["technique_id"]: row for row in self.techniques["techniques"]}
        rules = {row["technique_id"]: row for row in self.mapping["rules"]}
        for candidate in incident["candidate_techniques"]:
            technique = candidate["technique_id"]
            self.assertEqual(candidate["name"], records[technique]["name"])
            candidate["evidence_refs"].append(f"rule:{rules[technique]['mapping_rule_id']}")
        known_stages = {row["stage"] for row in self.stages["stages"]}
        for hypothesis in incident["stage_hypotheses"]:
            self.assertIn(hypothesis["stage"], known_stages)
            self.assertTrue(hypothesis["evidence_refs"])
        self.assertEqual(validate_bundle(self.alerts + incidents), [])
