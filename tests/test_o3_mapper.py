"""Exercise the mapper against the shared SentinelAI alert fixtures."""

import copy
import csv
import json
import unittest
from pathlib import Path

from sentinelai.contracts.messages import validate_bundle
from sentinelai.frameworks.mapper import EvidenceObservation, _check_stage_coverage, map_alerts


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"
MAPPING = ROOT / "sentinelai" / "frameworks" / "technique_stage_mapping.json"
EXTERNAL_SOURCE = "203.0.113.66"


def read_fixture(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class MapperTests(unittest.TestCase):
    def setUp(self):
        self.alerts = {
            alert["message_id"]: alert for alert in read_fixture("alerts.json")
        }

    def select(self, *numbers):
        return [self.alerts[f"alert-{number:04d}"] for number in numbers]

    def test_corroborated_external_scan(self):
        result = map_alerts(self.select(1, 2), external_sources={EXTERNAL_SOURCE})
        technique, = result["candidate_techniques"]
        stage, = result["stage_hypotheses"]
        self.assertEqual(technique["technique_id"], "T1595")
        self.assertEqual(technique["name"], "Active Scanning")
        self.assertEqual(technique["support"], "strong")
        self.assertEqual(stage["stage"], "reconnaissance")
        self.assertEqual(stage["support"], "strong")
        for label in (technique, stage):
            self.assertLessEqual(
                {
                    "alert:alert-0001", "alert:alert-0002",
                    "rule:R-MANY-PORTS-5MIN", "rule:O1-T1595",
                },
                set(label["evidence_refs"]),
            )

    def test_duplicate_alert_cannot_corroborate_scan(self):
        single = map_alerts(self.select(1), external_sources={EXTERNAL_SOURCE})
        repeated = map_alerts(self.select(1, 1), external_sources={EXTERNAL_SOURCE})
        self.assertEqual(single, repeated)
        self.assertEqual(single["candidate_techniques"][0]["support"], "weak")

    def test_scan_alerts_sharing_flow_cannot_corroborate_each_other(self):
        alerts = copy.deepcopy(self.select(1, 2))
        alerts[1]["evidence_refs"] = alerts[0]["evidence_refs"].copy()
        result = map_alerts(alerts, external_sources={EXTERNAL_SOURCE})
        self.assertEqual(result["candidate_techniques"][0]["support"], "weak")

    def test_repeated_scan_of_one_destination_stays_weak(self):
        alerts = copy.deepcopy(self.select(1, 2))
        alerts[1]["dst_ip"] = alerts[0]["dst_ip"]
        result = map_alerts(alerts, external_sources={EXTERNAL_SOURCE})
        self.assertEqual(result["candidate_techniques"][0]["support"], "weak")

    def test_conflicting_alert_identity_and_mixed_networks_are_rejected(self):
        first, second = self.select(1, 2)
        with self.assertRaises(ValueError):
            map_alerts([first, {**first, "dst_ip": second["dst_ip"]}])
        with self.assertRaises(ValueError):
            map_alerts([first, {**second, "network": "separate-network"}])

    def test_monitoring_scan_has_weak_support_without_context(self):
        result = map_alerts(self.select(9))
        technique, = result["candidate_techniques"]
        self.assertEqual(technique["technique_id"], "T1595")
        self.assertEqual(technique["support"], "weak")
        self.assertEqual(result["stage_hypotheses"], [])

    def test_explicitly_authorized_scan_remains_unmapped(self):
        result = map_alerts(self.select(9), authorized_scan_sources={"10.0.1.5"})
        self.assertEqual(result, {"candidate_techniques": [], "stage_hypotheses": []})

    def test_dns_indicators_leave_exfiltration_weak_and_stage_unmapped(self):
        result = map_alerts(self.select(7, 8))
        technique, = result["candidate_techniques"]
        self.assertEqual(technique["technique_id"], "T1048")
        self.assertEqual(technique["support"], "weak")
        self.assertLessEqual(
            {"rule:R-DNS-VOLUME-HIGH", "rule:R-DNS-LARGE-QUERY", "rule:O1-T1048"},
            set(technique["evidence_refs"]),
        )
        self.assertEqual(result["stage_hypotheses"], [])

    def test_dns_rule_pair_requires_dns_transport_and_destination(self):
        alert, = self.select(7)
        for changes in (
            {"rule_hits": ["R-DNS-VOLUME-HIGH"]},
            {"dst_port": 443},
            {"protocol": 1},
        ):
            with self.subTest(changes=changes):
                self.assertEqual(
                    map_alerts([{**alert, **changes}])["candidate_techniques"], []
                )

    def test_stage_cannot_reuse_a_dns_alert_log(self):
        alert, = copy.deepcopy(self.select(7))
        reference = "raw_log:dns-alert"
        alert["evidence_refs"].append(reference)
        observation = EvidenceObservation("data_theft_objective", alert["message_id"], reference)
        result = map_alerts([alert], observations=[observation])
        self.assertEqual(result["candidate_techniques"][0]["support"], "weak")
        self.assertEqual(result["stage_hypotheses"], [])

    def test_http_and_benign_traffic_do_not_infer_missing_evidence(self):
        for number in (3, 4, 5, 6, 10, 11):
            with self.subTest(alert_number=number):
                result = map_alerts(self.select(number))
                self.assertEqual(
                    result, {"candidate_techniques": [], "stage_hypotheses": []}
                )

    def test_technique_and_stage_require_their_own_evidence(self):
        cases = (
            (4, "public_app_exploit_verified", "exploitation_stage", "T1190", "exploitation"),
            (5, "web_shell_verified", "web_shell_installation", "T1505.003", "installation"),
            (6, "interpreter_verified", "remote_tasking", "T1059", "command_and_control"),
            (7, "alternative_exfiltration_verified", "data_theft_objective", "T1048",
             "actions_on_objectives"),
        )
        for number, kind, stage_kind, technique_id, stage_name in cases:
            with self.subTest(technique=technique_id):
                alert_id = self.select(number)[0]["message_id"]
                technique_obs = EvidenceObservation(kind, alert_id, "raw_log:technique")
                stage_obs = EvidenceObservation(stage_kind, alert_id, "raw_log:stage")
                alone = map_alerts(self.select(number), observations=[technique_obs])
                technique, = alone["candidate_techniques"]
                self.assertEqual(technique["technique_id"], technique_id)
                self.assertEqual(technique["support"], "strong")
                self.assertIn("raw_log:technique", technique["evidence_refs"])
                self.assertEqual(alone["stage_hypotheses"], [])

                linked = map_alerts(self.select(number), observations=[technique_obs, stage_obs])
                stage, = linked["stage_hypotheses"]
                self.assertEqual(stage["stage"], stage_name)
                self.assertIn(f"rule:O1-{technique_id}", stage["evidence_refs"])
                self.assertIn("raw_log:stage", stage["evidence_refs"])

    def test_stage_cannot_borrow_unrelated_alerts_or_raise_weak_support(self):
        technique = EvidenceObservation(
            "interpreter_suspected", "alert-0006", "raw_log:possible-interpreter"
        )
        unrelated = EvidenceObservation("remote_tasking", "alert-0005", "raw_log:other-alert")
        mismatched = map_alerts(self.select(5, 6), observations=[technique, unrelated])
        self.assertEqual(mismatched["stage_hypotheses"], [])

        reused = EvidenceObservation("remote_tasking", "alert-0006", technique.evidence_ref)
        same_ref = map_alerts(self.select(6), observations=[technique, reused])
        self.assertEqual(same_ref["stage_hypotheses"], [])

        linked = EvidenceObservation("remote_tasking", "alert-0006", "raw_log:linked-tasking")
        result = map_alerts(self.select(6), observations=[technique, linked])
        self.assertEqual(result["candidate_techniques"][0]["support"], "weak")
        self.assertEqual(result["stage_hypotheses"][0]["support"], "weak")

    def test_projection_validates_and_is_deterministic(self):
        incident = read_fixture("incident_updates.json")[1]
        grouped = [self.alerts[alert_id] for alert_id in incident["alert_ids"]]
        preserved = copy.deepcopy(grouped)
        result = map_alerts(grouped, external_sources={EXTERNAL_SOURCE})
        reverse = map_alerts(reversed(grouped), external_sources={EXTERNAL_SOURCE})
        self.assertEqual(result, reverse)
        self.assertEqual(grouped, preserved)
        incident.update(result)
        with (FIXTURES / "features_sample.csv").open(encoding="utf-8", newline="") as stream:
            flow_ids = {row["flow_id"] for row in csv.DictReader(stream)}
        self.assertEqual(validate_bundle(grouped + [incident], flow_ids), [])

    # ---- added 24 Nov: integration with the Investigation Agent (AIT-ADS IDS alerts) ----
    def ids_alert(self, number=1, **changes):
        """A fixture alert turned into an IDS alert from the AIT-ADS CSV export:
        only the reporting host's IP is known, no detector rule hits."""
        alert = copy.deepcopy(self.select(number)[0])
        alert.update({"detector": "ids", "ids_source": "suricata", "rf_score": None,
                      "rule_hits": [], "src_ip": None, "dst_ip": None, "host_ip": "10.0.1.1",
                      "src_port": None, "dst_port": None, "protocol": None,
                      "evidence_refs": [f"raw_log:ids/{alert['message_id']}"]})
        alert.update(changes)
        return alert

    def test_alert_without_src_ip_does_not_crash(self):
        self.assertEqual(map_alerts([self.ids_alert()]),
                         {"candidate_techniques": [], "stage_hypotheses": []})
        # even with a scan rule hit, a missing source address is skipped, not a crash
        hit = self.ids_alert(rule_hits=["R-MANY-PORTS-5MIN"])
        self.assertEqual(map_alerts([hit])["candidate_techniques"], [])

    def test_ids_scan_observation_gives_weak_active_scanning(self):
        alert = self.ids_alert()
        obs = EvidenceObservation("active_scanning_suspected", alert["message_id"],
                                  f"raw_log:ids/{alert['message_id']}")
        technique, = map_alerts([alert], observations=[obs])["candidate_techniques"]
        self.assertEqual((technique["technique_id"], technique["support"]), ("T1595", "weak"))
        self.assertIn("rule:O1-T1595", technique["evidence_refs"])
        stage = EvidenceObservation("target_discovery", alert["message_id"], "raw_log:ids/other-scan")
        result = map_alerts([alert], observations=[obs, stage])
        hypothesis, = result["stage_hypotheses"]
        self.assertEqual((hypothesis["stage"], hypothesis["support"]), ("reconnaissance", "weak"))
        self.assertIn("raw_log:ids/other-scan", hypothesis["evidence_refs"])

    def test_sudo_observation_maps_t1548_003_without_a_stage(self):
        alert = self.ids_alert()
        obs = EvidenceObservation("sudo_abuse_suspected", alert["message_id"],
                                  f"raw_log:ids/{alert['message_id']}")
        result = map_alerts([alert], observations=[obs])
        technique, = result["candidate_techniques"]
        self.assertEqual(technique["technique_id"], "T1548.003")
        self.assertEqual(technique["name"], "Abuse Elevation Control Mechanism: Sudo and Sudo Caching")
        self.assertEqual(technique["support"], "weak")
        self.assertEqual(result["stage_hypotheses"], [])   # the Kill Chain has no such stage
        # There is no sudo stage kind, so stage evidence for sudo is rejected, not ignored.
        stage = EvidenceObservation("sudo_abuse_stage", alert["message_id"], "raw_log:ids/other")
        with self.assertRaises(ValueError):
            map_alerts([alert], observations=[obs, stage])

    # ---- added 25 Nov: scan observations follow the detector route's source rules ----
    def scan_observations(self, alert, strong=False):
        kind = "active_scanning_verified" if strong else "active_scanning_suspected"
        return [EvidenceObservation(kind, alert["message_id"], "raw_log:ids/scan"),
                EvidenceObservation("target_discovery", alert["message_id"], "raw_log:ids/other-scan")]

    def test_authorized_source_overrides_scan_observations(self):
        alert, = self.select(9)
        result = map_alerts([alert], external_sources={alert["src_ip"]},
                            authorized_scan_sources={alert["src_ip"]},
                            observations=self.scan_observations(alert, strong=True))
        self.assertEqual(result, {"candidate_techniques": [], "stage_hypotheses": []})

    def test_scan_observations_need_an_external_source_for_reconnaissance(self):
        alert, = self.select(9)   # internal monitoring host, not declared external
        undeclared = map_alerts([alert], observations=self.scan_observations(alert, strong=True))
        technique, = undeclared["candidate_techniques"]
        self.assertEqual((technique["technique_id"], technique["support"]), ("T1595", "weak"))
        self.assertEqual(undeclared["stage_hypotheses"], [])

        external = map_alerts([alert], external_sources={alert["src_ip"]},
                              observations=self.scan_observations(alert, strong=True))
        technique, = external["candidate_techniques"]
        stage, = external["stage_hypotheses"]
        self.assertEqual(technique["support"], "strong")
        self.assertEqual((stage["stage"], stage["support"]), ("reconnaissance", "strong"))
        self.assertIn("raw_log:ids/other-scan", stage["evidence_refs"])

    def test_o1_stage_without_a_mapper_route_is_rejected(self):
        rules = json.loads(MAPPING.read_text(encoding="utf-8"))["rules"]
        _check_stage_coverage(rules)   # the shipped O-1 mapping is consistent
        sudo = next(rule for rule in rules if rule["technique_id"] == "T1548.003")
        sudo["stage_hypotheses"] = [{"stage": "exploitation", "requires": "Example only."}]
        with self.assertRaises(ValueError):
            _check_stage_coverage(rules)


if __name__ == "__main__":
    unittest.main()
