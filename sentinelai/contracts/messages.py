"""ALL-1 (b): the message contract for the shared incident state.

Agents never call each other. They write these four message types to shared
memory (Lama's SQLite store) and read the ones they need:

    Detection Agent      --Alert-->           shared memory
    Investigation Agent  --IncidentUpdate-->  shared memory
    Response Agent       --Assessment-->      shared memory
    Orchestrator/analyst --ReportRequest-->   shared memory -> Reporting Agent

Every message is a plain JSON object with a common envelope plus a payload.
validate_message() checks one message; validate_bundle() checks that all
evidence references between messages resolve.
"""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime

SCHEMA_VERSION = "1.0"

MESSAGE_TYPES = ("Alert", "IncidentUpdate", "Assessment", "ReportRequest")

PRODUCERS = {
    "Alert": {"detection_agent", "ait_ids_loader"},
    "IncidentUpdate": {"investigation_agent"},
    "Assessment": {"response_agent"},
    "ReportRequest": {"orchestrator", "analyst"},
}

ID_PREFIX = {
    "Alert": "alert-",
    "IncidentUpdate": "incupd-",
    "Assessment": "assess-",
    "ReportRequest": "repreq-",
}

# Evidence references are "<kind>:<id>", e.g. "flow:f-000123", "alert:alert-0001".
EVIDENCE_KINDS = {"flow", "alert", "incident", "assessment", "rule", "raw_log", "technique"}

DETECTORS = {"rf", "rules", "hybrid", "ids"}           # ids = Wazuh/Suricata/AMiner (AIT-ADS)
IDS_SOURCES = {"wazuh", "suricata", "aminer"}
SUPPORT_LEVELS = {"strong", "weak", "unmapped"}
CONFIDENCE = {"high", "medium", "low"}
LINK_STRENGTH = {"strong", "weak"}
INCIDENT_STATUS = {"open", "closed"}
SEVERITIES = ("Low", "Medium", "High", "Critical")
REVIEW_STATUS = {"pending", "approved", "rejected"}
KILL_CHAIN_STAGES = (
    "reconnaissance",
    "weaponization",
    "delivery",
    "exploitation",
    "installation",
    "command_and_control",
    "actions_on_objectives",
)

_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
ENVELOPE_FIELDS = ("message_id", "message_type", "schema_version", "created_at", "producer", "evidence_refs")


# ---------------------------------------------------------------- helpers
def _is_utc(ts) -> bool:
    if not isinstance(ts, str) or not ts.endswith("Z"):
        return False
    try:
        datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return True
    except ValueError:
        return False


def _is_ip(v) -> bool:
    try:
        ipaddress.ip_address(str(v))
        return True
    except ValueError:
        return False


def _check_refs(refs, errors, where):
    if not isinstance(refs, list):
        errors.append(f"{where}: evidence_refs must be a list")
        return
    for r in refs:
        if not isinstance(r, str) or ":" not in r or r.split(":", 1)[0] not in EVIDENCE_KINDS:
            errors.append(f"{where}: bad evidence ref {r!r} (use kind:id, kind in {sorted(EVIDENCE_KINDS)})")


def _require(msg, keys, errors, where):
    for k in keys:
        if k not in msg:
            errors.append(f"{where}: missing field {k!r}")


# ---------------------------------------------------------------- per type
def _validate_alert(m, e, w):
    _require(m, ("network", "detector", "first_seen", "last_seen", "host_ip", "src_ip", "dst_ip",
                 "src_port", "dst_port", "protocol", "rf_score", "rule_hits", "ids_source",
                 "signature", "user", "hostname", "summary"), e, w)
    if e:
        return
    if m["detector"] not in DETECTORS:
        e.append(f"{w}: detector must be one of {sorted(DETECTORS)}")
    # IPs are never dropped. Detection Agent alerts always come from a flow, so
    # src_ip and dst_ip are required. IDS alerts (AIT-ADS) keep every IP the
    # source record has; when it has no src/dst (e.g. the CSV export), the IP
    # of the host that raised the alert (host_ip) is required instead.
    for k in ("src_ip", "dst_ip", "host_ip"):
        if m[k] is not None and not _is_ip(m[k]):
            e.append(f"{w}: {k} is not a valid IP")
    if m["detector"] == "ids":
        if m["host_ip"] is None and (m["src_ip"] is None or m["dst_ip"] is None):
            e.append(f"{w}: ids alerts need host_ip, or both src_ip and dst_ip")
    else:
        for k in ("src_ip", "dst_ip"):
            if m[k] is None:
                e.append(f"{w}: {k} is required (IPs are never dropped)")
    for k in ("first_seen", "last_seen"):
        if not _is_utc(m[k]):
            e.append(f"{w}: {k} must be ISO 8601 UTC ending in Z")
    if m["rf_score"] is not None and not (0.0 <= float(m["rf_score"]) <= 1.0):
        e.append(f"{w}: rf_score must be between 0 and 1 or null")
    if m["detector"] in ("rf", "hybrid") and m["rf_score"] is None:
        e.append(f"{w}: rf/hybrid alerts need an rf_score")
    if m["detector"] in ("rules", "hybrid") and not m["rule_hits"]:
        e.append(f"{w}: rules/hybrid alerts need at least one rule hit")
    if m["detector"] == "ids" and m["ids_source"] not in IDS_SOURCES:
        e.append(f"{w}: ids alerts need ids_source in {sorted(IDS_SOURCES)}")
    if not m["evidence_refs"]:
        e.append(f"{w}: an alert must cite at least one flow, raw_log or rule")


def _validate_incident(m, e, w):
    _require(m, ("incident_id", "version", "status", "network", "alert_ids", "entities",
                 "start_time", "end_time", "link_reasons", "candidate_techniques",
                 "stage_hypotheses", "confidence", "uncertainty_notes"), e, w)
    if e:
        return
    if not str(m["incident_id"]).startswith("inc-"):
        e.append(f"{w}: incident_id must start with 'inc-'")
    if m["status"] not in INCIDENT_STATUS:
        e.append(f"{w}: status must be open/closed")
    if m["confidence"] not in CONFIDENCE:
        e.append(f"{w}: confidence must be high/medium/low")
    if not m["alert_ids"]:
        e.append(f"{w}: an incident needs at least one alert")
    for ip in m["entities"].get("ips", []):
        if not _is_ip(ip):
            e.append(f"{w}: entities.ips has invalid IP {ip!r}")
    for lr in m["link_reasons"]:
        _require(lr, ("alert_id", "linked_to", "shared_entity", "gap_seconds", "strength"), e, w + ".link_reasons")
        if lr.get("strength") not in LINK_STRENGTH:
            e.append(f"{w}: link strength must be strong/weak")
    for t in m["candidate_techniques"]:
        _require(t, ("technique_id", "name", "support", "evidence_refs"), e, w + ".technique")
        if not _TECHNIQUE_RE.match(str(t.get("technique_id", ""))):
            e.append(f"{w}: bad ATT&CK id {t.get('technique_id')!r}")
        if t.get("support") not in SUPPORT_LEVELS:
            e.append(f"{w}: technique support must be strong/weak/unmapped")
        if t.get("support") != "unmapped" and not t.get("evidence_refs"):
            e.append(f"{w}: technique {t.get('technique_id')} has no evidence")
        _check_refs(t.get("evidence_refs", []), e, w + ".technique")
    for s in m["stage_hypotheses"]:
        _require(s, ("stage", "support", "evidence_refs"), e, w + ".stage")
        if s.get("stage") not in KILL_CHAIN_STAGES:
            e.append(f"{w}: unknown Kill Chain stage {s.get('stage')!r}")
        if s.get("support") not in SUPPORT_LEVELS:
            e.append(f"{w}: stage support must be strong/weak/unmapped")
        _check_refs(s.get("evidence_refs", []), e, w + ".stage")


def _validate_assessment(m, e, w):
    _require(m, ("incident_id", "incident_version", "severity", "policy_rule_id",
                 "severity_reasons", "recommendations", "review_status"), e, w)
    if e:
        return
    if m["severity"] not in SEVERITIES:
        e.append(f"{w}: severity must be one of {SEVERITIES}")
    if not m["severity_reasons"]:
        e.append(f"{w}: severity needs at least one reason")
    if m["review_status"] not in REVIEW_STATUS:
        e.append(f"{w}: review_status must be pending/approved/rejected")
    for r in m["recommendations"]:
        _require(r, ("action", "reason", "requires_human_approval"), e, w + ".recommendation")
        if r.get("requires_human_approval") is not True:
            e.append(f"{w}: every recommendation must require human approval (advice only)")


def _validate_report_request(m, e, w):
    _require(m, ("incident_id", "assessment_id", "requested_by_reason", "format"), e, w)
    if e:
        return
    if m["format"] not in ("markdown", "html"):
        e.append(f"{w}: format must be markdown or html")


_VALIDATORS = {
    "Alert": _validate_alert,
    "IncidentUpdate": _validate_incident,
    "Assessment": _validate_assessment,
    "ReportRequest": _validate_report_request,
}


def validate_message(msg: dict) -> list[str]:
    """Returns a list of problems with one message; empty list = valid."""
    errors: list[str] = []
    where = str(msg.get("message_id", "<no id>"))
    _require(msg, ENVELOPE_FIELDS, errors, where)
    if errors:
        return errors
    mtype = msg["message_type"]
    if mtype not in MESSAGE_TYPES:
        return [f"{where}: unknown message_type {mtype!r}"]
    if not msg["message_id"].startswith(ID_PREFIX[mtype]):
        errors.append(f"{where}: {mtype} ids must start with {ID_PREFIX[mtype]!r}")
    if msg["schema_version"] != SCHEMA_VERSION:
        errors.append(f"{where}: schema_version must be {SCHEMA_VERSION}")
    if not _is_utc(msg["created_at"]):
        errors.append(f"{where}: created_at must be ISO 8601 UTC ending in Z")
    if msg["producer"] not in PRODUCERS[mtype]:
        errors.append(f"{where}: producer {msg['producer']!r} may not write {mtype}")
    _check_refs(msg["evidence_refs"], errors, where)
    _VALIDATORS[mtype](msg, errors, where)
    return errors


def validate_bundle(messages: list[dict], flow_ids: set[str] | None = None) -> list[str]:
    """Checks every message, then checks that references between them resolve."""
    errors: list[str] = []
    for m in messages:
        errors += validate_message(m)
    ids = [m.get("message_id") for m in messages]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        errors.append(f"duplicate message ids: {sorted(dupes)}")

    alerts = {m["message_id"] for m in messages if m.get("message_type") == "Alert"}
    incidents = {}
    for m in messages:
        if m.get("message_type") == "IncidentUpdate":
            incidents.setdefault(m["incident_id"], set()).add(m["version"])
    assessments = {m["message_id"]: m for m in messages if m.get("message_type") == "Assessment"}

    known = {"alert": alerts, "incident": set(incidents), "assessment": set(assessments)}
    if flow_ids is not None:
        known["flow"] = flow_ids

    def resolve(ref, where):
        kind, _, rid = ref.partition(":")
        if kind in known and rid not in known[kind]:
            errors.append(f"{where}: reference {ref} points to nothing")

    for m in messages:
        w = m.get("message_id")
        for ref in m.get("evidence_refs", []):
            resolve(ref, w)
        if m.get("message_type") == "IncidentUpdate":
            for a in m["alert_ids"]:
                if a not in alerts:
                    errors.append(f"{w}: alert {a} not found")
            for part in m["candidate_techniques"] + m["stage_hypotheses"]:
                for ref in part["evidence_refs"]:
                    resolve(ref, w)
        if m.get("message_type") == "Assessment":
            if m["incident_id"] not in incidents:
                errors.append(f"{w}: incident {m['incident_id']} not found")
            elif m["incident_version"] not in incidents[m["incident_id"]]:
                errors.append(f"{w}: incident version {m['incident_version']} not found")
        if m.get("message_type") == "ReportRequest":
            if m["incident_id"] not in incidents:
                errors.append(f"{w}: incident {m['incident_id']} not found")
            a = assessments.get(m["assessment_id"])
            if a is None:
                errors.append(f"{w}: assessment {m['assessment_id']} not found")
            elif a["incident_id"] != m["incident_id"]:
                errors.append(f"{w}: assessment is for a different incident")
    return errors
