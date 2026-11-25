"""Explain incident severity and write versioned Assessments to shared memory."""
from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from sqlite3 import IntegrityError
from uuid import NAMESPACE_URL, uuid5

from sentinelai.contracts.messages import KILL_CHAIN_STAGES, SCHEMA_VERSION, validate_message

DEMO_ASSET_INVENTORY = {"fixture-net": {"host:wordpress": "high"}}
_SUPPORT = {"unmapped": 0, "weak": 1, "strong": 2}


@dataclass(frozen=True)
class ExploitationConfirmation:
    """Reviewed log evidence tying successful exploitation to an affected asset."""

    alert_id: str
    asset: str
    raw_log_ref: str


@dataclass(frozen=True)
class SeverityDecision:
    severity: str
    rule_id: str
    reasons: tuple[str, ...]
    evidence_refs: tuple[str, ...]


def _evidence(references, alert_ids):
    """Keep observations and in-incident alert references."""
    evidence = set()
    for reference in references:
        kind, _, item_id = reference.partition(":")
        if item_id and (kind in {"raw_log", "flow"} or (kind == "alert" and item_id in alert_ids)):
            evidence.add(reference)
    return evidence


def _linked_stage_groups(alert_ids, stages, link_reasons):
    """Yield stage findings supported by alerts in the same linked component."""
    neighbors = defaultdict(set)
    weak_edges = set()
    for link in link_reasons:
        left, right = link["alert_id"], link["linked_to"]
        if left in alert_ids and right in alert_ids and left != right:
            neighbors[left].add(right)
            neighbors[right].add(left)
            if link["strength"] == "weak":
                weak_edges.add(frozenset((left, right)))

    stage_anchors = [
        (stage["stage"], stage["support"], {ref[6:] for ref in refs if ref.startswith("alert:")})
        for stage, refs in stages
    ]
    visited = set()
    for start in sorted(neighbors):
        if start in visited:
            continue
        component = {start}
        pending = [start]
        has_weak_link = False
        while pending:
            current = pending.pop()
            for neighbor in neighbors[current]:
                if frozenset((current, neighbor)) in weak_edges:
                    has_weak_link = True
                if neighbor not in component:
                    component.add(neighbor)
                    pending.append(neighbor)
        visited.update(component)

        support_by_stage = {}
        supporting_alerts = set()
        for stage, support, anchors in stage_anchors:
            incident_anchors = anchors & component
            if incident_anchors:
                supporting_alerts.update(incident_anchors)
                support_by_stage[stage] = max(_SUPPORT[support], support_by_stage.get(stage, 0))
        if len(supporting_alerts) >= 2 and len(support_by_stage) >= 2:
            yield support_by_stage, has_weak_link


def assess_severity(
    incident: dict,
    *,
    asset_inventory: Mapping[str, Mapping[str, str]] = DEMO_ASSET_INVENTORY,
    exploitation_confirmations: Iterable[ExploitationConfirmation] = (),
) -> SeverityDecision:
    """Apply the O-4 priority table to one incident and its reviewed context."""
    if incident.get("message_type") != "IncidentUpdate":
        raise ValueError("O-4 requires an IncidentUpdate")
    errors = validate_message(incident)
    if errors:
        raise ValueError("; ".join(errors))
    version = incident["version"]
    if type(version) is not int or version < 1:
        raise ValueError("O-4 requires a positive incident version")

    alert_ids = set(incident["alert_ids"])
    techniques = [
        (item, refs) for item in incident["candidate_techniques"]
        if item["support"] != "unmapped" and (refs := _evidence(item["evidence_refs"], alert_ids))
    ]
    stages = [
        (item, refs) for item in incident["stage_hypotheses"]
        if item["support"] != "unmapped" and (refs := _evidence(item["evidence_refs"], alert_ids))
    ]
    findings = techniques + stages
    strongest = max((_SUPPORT[item["support"]] for item, _ in findings), default=0)
    reached = [stage for stage in KILL_CHAIN_STAGES if any(item["stage"] == stage for item, _ in stages)]
    groups = list(_linked_stage_groups(alert_ids, stages, incident["link_reasons"]))

    inventory = asset_inventory.get(incident["network"], {})
    entity_keys = {f"host:{host.casefold()}" for host in incident["entities"].get("hosts", [])}
    entity_keys.update(f"ip:{ip}" for ip in incident["entities"].get("ips", []))
    known_assets = sorted(entity_keys & inventory.keys())
    exploit_alerts = {
        ref[6:] for item, refs in stages
        if item["stage"] == "exploitation" and item["support"] == "strong"
        for ref in refs if ref.startswith("alert:")
    }
    critical = sorted(
        (proof.asset, proof.alert_id, proof.raw_log_ref) for proof in exploitation_confirmations
        if proof.asset in entity_keys and inventory.get(proof.asset) == "critical"
        and proof.alert_id in exploit_alerts and proof.raw_log_ref.startswith("raw_log:")
        and proof.raw_log_ref[8:].strip()
    )

    high_groups = [
        (support, weak_link) for support, weak_link in groups
        if len(support) >= 3 and support.get("actions_on_objectives") == _SUPPORT["strong"]
    ]
    linked_group = max(high_groups or groups, key=lambda group: (len(group[0]), not group[1]), default=None)
    evidence_refs = {f"incident:{incident['incident_id']}"}
    evidence_refs.update(ref for _, refs in findings for ref in refs)
    reasons = []
    if critical:
        asset, alert_id, raw_log = critical[0]
        severity, rule = "Critical", "SEV-CRITICAL-ASSET-EXPLOIT"
        reasons.append(f"Reviewed log evidence supports successful exploitation of critical asset {asset}.")
        evidence_refs.update({f"alert:{alert_id}", raw_log})
    elif high_groups:
        severity, rule = "High", "SEV-MULTISTAGE-OBJECTIVE"
        reasons.append(f"{len(linked_group[0])} linked stages include strongly supported Actions on Objectives.")
    elif strongest == _SUPPORT["strong"]:
        severity, rule = "Medium", "SEV-STRONG-EVIDENCE"
        reasons.append("At least one finding has strong evidence. The High and Critical conditions require additional evidence.")
    elif linked_group:
        severity, rule = "Medium", "SEV-MULTISTAGE-WEAK"
        reasons.append(f"{len(linked_group[0])} linked stages have weak support.")
    elif len(alert_ids) == 1 and strongest == _SUPPORT["weak"]:
        severity, rule = "Low", "SEV-SINGLE-WEAK"
        reasons.append("One alert supports a weak technique or stage hypothesis.")
    elif len(alert_ids) == 1:
        severity, rule = "Low", "SEV-SINGLE-UNMAPPED"
        reasons.append("One alert has no evidence-backed technique or stage hypothesis.")
    else:
        severity, rule = "Low", "SEV-LIMITED-EVIDENCE"
        reasons.append("Available evidence is limited to unmapped or unlinked weak findings.")

    if reached:
        reasons.append(f"Furthest supported stage hypothesis: {reached[-1].replace('_', ' ').title()}.")
    if linked_group and linked_group[1]:
        reasons.append("The linked stage group includes a weak alert link.")
    if known_assets:
        assets = ", ".join(f"{asset} ({inventory[asset]})" for asset in known_assets)
        reasons.append(f"Incident assets with configured importance: {assets}.")
    return SeverityDecision(severity, rule, tuple(reasons), tuple(sorted(evidence_refs)))


class ResponseAgent:
    """Orchestrator adapter. Reuse the stored assessment on retries."""

    def __init__(
        self,
        *,
        asset_inventory: Mapping[str, Mapping[str, str]] = DEMO_ASSET_INVENTORY,
        exploitation_confirmations: Mapping[
            tuple[str, int], Iterable[ExploitationConfirmation]
        ] | None = None,
    ):
        self.asset_inventory = {network: dict(assets) for network, assets in asset_inventory.items()}
        self.exploitation_confirmations = {
            key: tuple(confirmations) for key, confirmations in (exploitation_confirmations or {}).items()
        }

    def run(self, message: dict, memory) -> dict | None:
        """Assess the latest stored update and return its Assessment."""
        if message.get("message_type") != "IncidentUpdate":
            raise ValueError("ResponseAgent.run requires an IncidentUpdate")
        incident_id, version = message["incident_id"], message["version"]
        latest = memory.latest_incident(incident_id)
        if latest is None or latest["message_id"] != message["message_id"]:
            return None

        key = uuid5(NAMESPACE_URL, f"sentinelai:assessment:{incident_id}:{version}")
        message_id = f"assess-{key.hex}"
        existing = memory.get(message_id)
        if existing is not None:
            return existing
        for existing in memory.read("Assessment"):
            if existing["incident_id"] == incident_id and existing["incident_version"] == version:
                return existing

        decision = assess_severity(
            latest,
            asset_inventory=self.asset_inventory,
            exploitation_confirmations=self.exploitation_confirmations.get((incident_id, version), ()),
        )
        assessment = {
            "message_id": message_id,
            "message_type": "Assessment",
            "schema_version": SCHEMA_VERSION,
            "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "producer": "response_agent",
            "evidence_refs": list(decision.evidence_refs),
            "incident_id": incident_id,
            "incident_version": version,
            "severity": decision.severity,
            "policy_rule_id": decision.rule_id,
            "severity_reasons": list(decision.reasons),
            "recommendations": [],
            "review_status": "pending",
        }
        try:
            memory.write(assessment)
        except IntegrityError:
            existing = memory.get(message_id)
            if existing is None or (existing.get("message_type"), existing.get("incident_id"),
                                    existing.get("incident_version")) != ("Assessment", incident_id, version):
                raise
            return existing
        return assessment
