"""O-7: mapping agreement on the two demo scenarios (a small set, not general accuracy)."""
import unittest

from sentinelai.frameworks.agreement import (
    SCOPE_NOTE,
    compare_labels,
    compare_scenario,
    format_report,
)
from sentinelai.investigation.scenarios import EXPECTED

NO_LABELS = {"agree": [], "missed": [], "extra": []}


class MappingAgreementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.results = {name: compare_scenario(name) for name in ("scenario1", "scenario2")}

    def incident(self, scenario, ground_truth):
        return next(item for item in self.results[scenario]["incidents"]
                    if ground_truth in item["ground_truth"])

    def test_compare_labels_splits_agreement_missed_and_extra(self):
        self.assertEqual(compare_labels({"T1", "T2"}, {"T2", "T3"}),
                         {"agree": ["T2"], "missed": ["T1"], "extra": ["T3"]})
        order = ("reconnaissance", "installation")
        self.assertEqual(compare_labels({"installation", "reconnaissance"}, set(), order)["missed"],
                         ["reconnaissance", "installation"])

    def test_ground_truth_matches_the_scenario_author_technique_lists(self):
        for name, result in self.results.items():
            for ground_truth, truth in EXPECTED[name]["ground_truth"].items():
                if "true_techniques" in truth:
                    with self.subTest(scenario=name, ground_truth=ground_truth):
                        found = {step["technique"] for step in result["steps"]
                                 if step["ground_truth"] == ground_truth}
                        self.assertEqual(found, set(truth["true_techniques"]))

    def test_scenario_1_attack_techniques_and_stages(self):
        attack = self.incident("scenario1", "GT-1")
        self.assertEqual(attack["ground_truth"], ["GT-1", "GT-2"])
        self.assertEqual(attack["techniques"], {
            "agree": ["T1048", "T1059", "T1190", "T1548.003", "T1595"],
            "missed": ["T1505.003"],
            "extra": [],
        })
        self.assertEqual(attack["stages"], {
            "agree": ["reconnaissance", "actions_on_objectives"],
            "missed": ["exploitation", "installation", "command_and_control"],
            "extra": [],
        })
        supports = list(attack["technique_support"].values()) + list(attack["stage_support"].values())
        self.assertTrue(supports and all(level == "weak" for level in supports))
        self.assertEqual((attack["severity"], attack["expected_severity"]), ("Medium", "High"))

    def test_scenario_1_innocent_login_stays_unlabelled(self):
        typo = self.incident("scenario1", "benign-1")
        self.assertEqual((typo["techniques"], typo["stages"]), (NO_LABELS, NO_LABELS))
        self.assertEqual((typo["severity"], typo["expected_severity"]), ("Low", "Low"))

    def test_scenario_1_steps_show_which_alerts_the_labels_cite(self):
        cited = {step["step"]: (step["cited"], step["alerts"]) for step in self.results["scenario1"]["steps"]}
        self.assertEqual(cited, {
            "network_scan": (20, 20), "service_scan": (5, 55), "wordlist_scan": (0, 200),
            "upload_exploit": (2, 2), "web_shell": (0, 1), "commands": (5, 5),
            "privilege_escalation": (3, 4), "dns_exfiltration": (45, 45),
        })

    def test_scenario_2_only_the_admin_sudo_gets_a_label(self):
        result = self.results["scenario2"]
        extra = {item["ground_truth"][0]: item["techniques"]["extra"] for item in result["incidents"]}
        self.assertEqual(extra, {"benign-backup-1": [], "benign-backup-2": [],
                                 "benign-update": ["T1548.003"], "benign-av-refresh": []})
        self.assertEqual(self.incident("scenario2", "benign-update")["technique_support"],
                         {"T1548.003": "weak"})
        self.assertTrue(all(item["stages"] == NO_LABELS for item in result["incidents"]))
        self.assertTrue(all(item["severity"] == "Low" for item in result["incidents"]))
        monitoring = next(item for item in result["ground_truth"] if item["ground_truth"] == "benign-monitoring")
        self.assertEqual((monitoring["incidents"], monitoring["routine_alerts"]), ([], monitoring["alerts"]))

    def test_report_states_its_scope_and_the_disagreements(self):
        report = format_report(self.results.values())
        self.assertIn(SCOPE_NOTE, report)
        self.assertIn("| scenario1 | 5 | 1 | 0 | 2 | 3 | 0 |", report)
        self.assertIn("| scenario2 | 0 | 0 | 1 | 0 | 0 | 0 |", report)
        self.assertIn("Wazuh: Suspicious URL access.", report)


if __name__ == "__main__":
    unittest.main()
