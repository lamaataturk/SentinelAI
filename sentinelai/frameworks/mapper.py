"""Map one incident's alerts to defensive ATT&CK and Kill Chain hypotheses."""
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from functools import lru_cache
from ipaddress import ip_address
from itertools import combinations
from pathlib import Path
import json

from sentinelai.contracts.messages import SCHEMA_VERSION, validate_message


@dataclass(frozen=True)
class EvidenceObservation:
    """A reviewed telemetry finding linked to an alert in the incident."""

    kind: str
    alert_id: str
    evidence_ref: str


# The caller derives these observations from telemetry or analyst review.
# Technique and stage findings have separate evidence requirements.
# Each entry: (weak kind, strong kind, stage kind, Kill Chain stage). A technique
# without a Kill Chain stage has None in both stage fields.
_OBSERVATION_RULES = {
    # IDS scan signatures (e.g. Suricata "ET SCAN ...") carry no detector rule hit,
    # so scans also have an observation route (Reem, 24 Nov). _scan_source applies
    # the same source rules to this route as to the detector route in _map_scans.
    "T1595": ("active_scanning_suspected", "active_scanning_verified",
              "target_discovery", "reconnaissance"),
    "T1190": ("public_app_exploit_suspected", "public_app_exploit_verified",
              "exploitation_stage", "exploitation"),
    "T1505.003": ("web_shell_suspected", "web_shell_verified",
                  "web_shell_installation", "installation"),
    "T1059": ("interpreter_suspected", "interpreter_verified",
              "remote_tasking", "command_and_control"),
    "T1048": ("alternative_exfiltration_suspected", "alternative_exfiltration_verified",
              "data_theft_objective", "actions_on_objectives"),
    # Privilege escalation via sudo (Reem, 24 Nov). The Cyber Kill Chain has no
    # privilege-escalation stage, so O-1 lists none and there is no stage kind.
    "T1548.003": ("sudo_abuse_suspected", "sudo_abuse_verified", None, None),
}
_OBSERVATION_KINDS = {
    kind for weak, strong, stage_kind, _ in _OBSERVATION_RULES.values()
    for kind in (weak, strong, stage_kind) if kind is not None
}


def _check_stage_coverage(rules):
    """Reject an O-1 stage hypothesis that the mapper has no observation route for."""
    for rule in rules:
        route = _OBSERVATION_RULES.get(rule["technique_id"])
        if route is None:
            continue
        missing = {hypothesis["stage"] for hypothesis in rule["stage_hypotheses"]} - {route[3]}
        if missing:
            raise ValueError(
                f"O-1 lists stage {sorted(missing)} for {rule['technique_id']}, "
                "but the mapper has no stage observation for it"
            )


@lru_cache(maxsize=1)
def _load_catalogs():
    directory = Path(__file__).resolve().parent
    techniques = json.loads((directory / "attack_techniques.json").read_text(encoding="utf-8"))
    mapping = json.loads((directory / "technique_stage_mapping.json").read_text(encoding="utf-8"))
    stages = json.loads((directory / "kill_chain_stages.json").read_text(encoding="utf-8"))
    if any(data["schema_version"] != "1.0" for data in (techniques, mapping, stages)):
        raise ValueError("Unsupported O-1 knowledge base version")
    if mapping["message_schema_version"] != SCHEMA_VERSION:
        raise ValueError("O-1 knowledge base targets a different message contract")
    _check_stage_coverage(mapping["rules"])
    return (
        {row["technique_id"]: row["name"] for row in techniques["techniques"]},
        {row["technique_id"]: row for row in mapping["rules"]},
        [row["stage"] for row in stages["stages"]],
    )


def _incident_alerts(alerts):
    unique = {}
    for alert in alerts:
        if alert.get("message_type") != "Alert":
            raise ValueError("map_alerts accepts Alert messages")
        problems = validate_message(alert)
        if problems:
            raise ValueError("; ".join(problems))
        alert_id = alert["message_id"]
        if alert_id in unique and unique[alert_id] != alert:
            raise ValueError(f"Conflicting entries for {alert_id}")
        unique[alert_id] = alert
    if len({alert["network"] for alert in unique.values()}) > 1:
        raise ValueError("An incident's alerts must share a network")
    return unique


def _index_observations(observations, alerts):
    index = defaultdict(lambda: defaultdict(set))
    for item in observations:
        if item.kind not in _OBSERVATION_KINDS:
            raise ValueError(f"Unknown observation kind: {item.kind}")
        if item.alert_id not in alerts:
            raise ValueError(f"Observation references an alert outside the incident: {item.alert_id}")
        prefix, _, log_id = item.evidence_ref.partition(":")
        if prefix != "raw_log" or not log_id.strip():
            raise ValueError("Observations require a nonempty raw_log reference")
        index[item.alert_id][item.kind].add(item.evidence_ref)
    return index


def _refs(alert, rule, detector_hits=()):
    return {
        f"alert:{alert['message_id']}",
        f"rule:{rule['mapping_rule_id']}",
        *(f"rule:{hit}" for hit in detector_hits),
        *(ref for ref in alert["evidence_refs"] if ref.startswith(("flow:", "raw_log:"))),
    }


def _record(labels, label, support, refs):
    previous = labels.get(label)
    if previous is None or (support == "strong" and previous[0] == "weak"):
        labels[label] = (support, set(refs))
    elif support == previous[0]:
        previous[1].update(refs)


def _record_stage(labels, rule, stage, support, refs):
    if any(hypothesis["stage"] == stage for hypothesis in rule["stage_hypotheses"]):
        _record(labels, stage, support, refs)


def _scan_source(alert, external, authorized):
    """Classify an alert's source for scan findings.

    Returns "unknown" when the alert has no src_ip (AIT-ADS IDS alerts from the CSV
    export only know host_ip), otherwise "authorized", "external" or "undeclared".
    Authorization takes precedence over an external role.
    """
    if alert.get("src_ip") is None:
        return "unknown"
    source = ip_address(alert["src_ip"])
    if source in authorized:
        return "authorized"
    return "external" if source in external else "undeclared"


def _map_scans(alerts, rule, external, authorized, techniques, stages):
    by_source = defaultdict(list)
    for alert in alerts:
        hits = set(rule["detection_rule_ids"]).intersection(alert["rule_hits"])
        # Alerts without src_ip cannot use this route (Reem's 24 Nov crash fix), and
        # authorized sources are omitted.
        source = _scan_source(alert, external, authorized)
        if not hits or source in ("unknown", "authorized"):
            continue
        refs = _refs(alert, rule, hits)
        _record(techniques, "T1595", "weak", refs)
        if source == "external" and alert.get("dst_ip") is not None:
            _record_stage(stages, rule, "reconnaissance", "weak", refs)
            flows = {ref for ref in refs if ref.startswith("flow:") and ref[5:]}
            by_source[ip_address(alert["src_ip"])].append((ip_address(alert["dst_ip"]), flows, refs))

    for scans in by_source.values():
        for (dst_a, flows_a, refs_a), (dst_b, flows_b, refs_b) in combinations(scans, 2):
            if dst_a != dst_b and flows_a and flows_b and flows_a.isdisjoint(flows_b):
                refs = refs_a | refs_b
                _record(techniques, "T1595", "strong", refs)
                _record_stage(stages, rule, "reconnaissance", "strong", refs)


def _map_observations(alert, observed, rules, techniques, stages, scan_source):
    for technique, (weak_kind, strong_kind, stage_kind, stage) in _OBSERVATION_RULES.items():
        # Scan observations follow the source rules of _map_scans: an authorized
        # source is omitted, and a known source that is not declared external
        # stays weak with no Reconnaissance hypothesis. Unknown sources are unchanged.
        if technique == "T1595" and scan_source == "authorized":
            continue
        undeclared_scan = technique == "T1595" and scan_source == "undeclared"
        rule = rules[technique]
        weak_logs = observed.get(weak_kind, set())
        strong_logs = observed.get(strong_kind, set())
        dns_hits = set()
        if technique == "T1048" and alert["dst_port"] == 53 and alert["protocol"] in (6, 17):
            required = set(rule["detection_rule_ids"])
            if required and required.issubset(alert["rule_hits"]):
                dns_hits = required
        if not (weak_logs or strong_logs or dns_hits):
            continue

        support = "strong" if strong_logs and not undeclared_scan else "weak"
        refs = _refs(alert, rule, dns_hits) | (strong_logs or weak_logs)
        _record(techniques, technique, support, refs)

        if stage_kind is None or undeclared_scan:
            continue
        independent_logs = observed.get(stage_kind, set()) - refs - weak_logs
        if independent_logs:
            _record_stage(stages, rule, stage, support, refs | independent_logs)


def map_alerts(
    alerts: Iterable[dict],
    *,
    external_sources: Iterable[str] = (),
    authorized_scan_sources: Iterable[str] = (),
    observations: Iterable[EvidenceObservation] = (),
) -> dict[str, list[dict]]:
    """Return the two mapping fields for one IncidentUpdate.

    Source roles and reviewed observations are supplied by the investigation
    caller for this incident's network. See docs/frameworks/o3-mapper.md.
    """
    alerts_by_id = _incident_alerts(alerts)
    observed_by_id = _index_observations(observations, alerts_by_id)
    names, rules, stage_order = _load_catalogs()
    external = {ip_address(source) for source in external_sources}
    authorized = {ip_address(source) for source in authorized_scan_sources}
    techniques, stages = {}, {}
    _map_scans(alerts_by_id.values(), rules["T1595"], external, authorized, techniques, stages)
    for alert_id, alert in alerts_by_id.items():
        _map_observations(alert, observed_by_id[alert_id], rules, techniques, stages,
                          _scan_source(alert, external, authorized))
    return {
        "candidate_techniques": [
            {"technique_id": technique, "name": names[technique], "support": support,
             "evidence_refs": sorted(refs)}
            for technique, (support, refs) in sorted(techniques.items())
        ],
        "stage_hypotheses": [
            {"stage": stage, "support": stages[stage][0], "evidence_refs": sorted(stages[stage][1])}
            for stage in stage_order if stage in stages
        ],
    }
