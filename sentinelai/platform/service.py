"""L-6.2: read model for the API.

This module is the only place the platform reads shared memory. It reuses the
existing building blocks and adds no new security reasoning:

* SharedMemory       (L-2) - every message comes from memory.read()/get()/latest_incident()
* ReportingAgent     (L-4) - the only thing that writes report files
* EvidenceValidator  (L-5) - every validation result shown in the dashboard
* ReviewStore        (L-6) - human decisions, kept apart from agent messages
* O-1 knowledge base (Omar) - technique/stage names and documented limitations

Severity, techniques, stages, confidence and recommendations are shown exactly
as the agents wrote them.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from datetime import datetime, timezone
from functools import cached_property
from pathlib import Path
from uuid import uuid4

from sentinelai.contracts.messages import KILL_CHAIN_STAGES, SCHEMA_VERSION, SEVERITIES
from sentinelai.platform.config import ROOT, Settings, load_flow_ids
from sentinelai.platform.metadata import all_meta, message_count
from sentinelai.platform.reviews import ReviewStore, recommendation_fingerprint, recommendation_ref
from sentinelai.platform.shared_memory import SharedMemory
from sentinelai.reporting.reporting_agent import ReportingAgent
from sentinelai.reporting.traceability import EvidenceValidator

FRAMEWORKS_DIR = ROOT / "sentinelai" / "frameworks"
REPORT_ID_RE = re.compile(r"^repreq-[A-Za-z0-9_-]{1,120}$")

VALIDATION_LIMITATIONS = [
    "Validation covers every message in the database, not only one incident.",
    "Reference validation checks that cited messages and flows exist. It does not show that an attack happened.",
    "Detection rule definitions (rule: references) are not independently verified.",
    "raw_log: references are recorded but cannot be checked against the original logs here.",
    "Generated Markdown is not re-checked against every original source field.",
]


class NotFound(LookupError):
    pass


class Conflict(ValueError):
    pass


def _parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _notes(value) -> list[str]:
    """uncertainty_notes is a string in the fixtures and may be a list elsewhere."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value.strip() else []
    return [str(v) for v in value if str(v).strip()]


class PlatformService:
    def __init__(self, settings: Settings):
        self.settings = settings
        Path(settings.db_path).parent.mkdir(parents=True, exist_ok=True)
        self.memory = SharedMemory(str(settings.db_path))
        self.reviews = ReviewStore(str(settings.db_path))
        self.validator = EvidenceValidator()

    # ------------------------------------------------------------ helpers
    @cached_property
    def flow_ids(self) -> set[str] | None:
        return load_flow_ids(self.settings.flows_csv)

    @cached_property
    def knowledge(self) -> dict:
        """O-1 knowledge base: technique names/tactics, stage names, documented limitations."""
        def load(name):
            return json.loads((FRAMEWORKS_DIR / name).read_text(encoding="utf-8"))

        techniques = {t["technique_id"]: t for t in load("attack_techniques.json")["techniques"]}
        stages = {s["stage"]: s for s in load("kill_chain_stages.json")["stages"]}
        rules = {r["technique_id"]: r for r in load("technique_stage_mapping.json")["rules"]}
        return {"techniques": techniques, "stages": stages, "rules": rules}

    @property
    def data_source(self) -> str:
        source = all_meta(self.settings.db_path).get("data_source")
        if source:
            return source
        return "agents" if self.settings.mode == "live" else "uninitialised"

    def _incident_groups(self) -> dict[str, list[dict]]:
        groups: dict[str, list[dict]] = {}
        for update in self.memory.read("IncidentUpdate"):
            groups.setdefault(update["incident_id"], []).append(update)
        for versions in groups.values():
            versions.sort(key=lambda m: m["version"])
        return groups

    def _assessments_for(self, incident_id: str, assessments=None) -> list[dict]:
        items = assessments if assessments is not None else self.memory.read("Assessment")
        return sorted(
            (a for a in items if a["incident_id"] == incident_id),
            key=lambda a: (a["incident_version"], a["created_at"]),
        )

    @staticmethod
    def _current_assessment(latest_version: int, assessments: list[dict]) -> dict | None:
        """The newest assessment of the incident's latest version (None if there is none)."""
        matching = [a for a in assessments if a["incident_version"] == latest_version]
        return matching[-1] if matching else None

    def _assessment_view(self, assessment: dict, latest_version: int | None) -> dict:
        current = self.reviews.current(assessment["message_id"])
        recommendations = []
        for index, rec in enumerate(assessment["recommendations"]):
            decision = current.get(index)
            recommendations.append({
                **rec,
                "index": index,
                "recommendation_ref": recommendation_ref(assessment["message_id"], index),
                "fingerprint": recommendation_fingerprint(rec),
                "review": decision,
                "review_decision": decision["decision"] if decision else "pending",
            })
        return {
            **assessment,
            "recommendations": recommendations,
            "stored_review_status": assessment["review_status"],
            "review_summary": self.reviews.summary(assessment),
            "is_current": latest_version is not None and assessment["incident_version"] == latest_version,
            "latest_incident_version": latest_version,
        }

    # ------------------------------------------------------------ system
    def system_status(self) -> dict:
        db = Path(self.settings.db_path)
        meta = all_meta(db)
        flows = self.flow_ids
        warnings = []
        source = self.data_source
        if self.settings.mode == "demo" and source != "fixtures":
            warnings.append("Demo database is not initialised. Run: python scripts/init_demo.py")
        if self.settings.mode == "live" and source == "fixtures":
            warnings.append("Live mode is pointed at a database that contains demo fixtures.")
        if flows is None:
            warnings.append("No flow file configured: flow: references are not checked.")
        return {
            "mode": self.settings.mode,
            "data_source": source,
            "is_demo_data": source == "fixtures",
            "database": db.name,
            "database_exists": db.exists(),
            "messages_stored": message_count(db),
            "reports_dir": Path(self.settings.reports_dir).name,
            "flow_evidence_loaded": flows is not None,
            "flow_ids_available": len(flows) if flows is not None else 0,
            "initialised_at": meta.get("initialised_at"),
            "schema_version": SCHEMA_VERSION,
            "authentication": "none (local prototype; analyst names are self-reported)",
            "actions_executed_automatically": False,
            "warnings": warnings,
        }

    # ------------------------------------------------------------ stats
    def stats(self) -> dict:
        alerts = self.memory.read("Alert")
        groups = self._incident_groups()
        assessments = self.memory.read("Assessment")
        requests = self.memory.read("ReportRequest")

        severity = Counter({s: 0 for s in SEVERITIES})
        severity["Unassessed"] = 0
        confidence = Counter()
        stage_support = {stage: Counter() for stage in KILL_CHAIN_STAGES}
        pending = approved = rejected = 0
        for incident_id, versions in groups.items():
            latest = versions[-1]
            confidence[latest["confidence"]] += 1
            for hyp in latest["stage_hypotheses"]:
                stage_support[hyp["stage"]][hyp["support"]] += 1
            current = self._current_assessment(latest["version"], self._assessments_for(incident_id, assessments))
            if current is None:
                severity["Unassessed"] += 1
                continue
            severity[current["severity"]] += 1
            summary = self.reviews.summary(current)
            pending += summary["pending"]
            approved += summary["approved"]
            rejected += summary["rejected"]

        activity = self._alert_activity(alerts)

        reports_generated = sum(1 for r in requests if self._report_path(r["message_id"]).is_file())
        return {
            "data_source": self.data_source,
            "is_demo_data": self.data_source == "fixtures",
            "total_alerts": len(alerts),
            "total_incidents": len(groups),
            "incident_versions": sum(len(v) for v in groups.values()),
            "total_assessments": len(assessments),
            "severity_distribution": dict(severity),
            "high_or_critical_incidents": severity["High"] + severity["Critical"],
            "confidence_distribution": dict(confidence),
            "detector_distribution": dict(Counter(a["detector"] for a in alerts)),
            "alert_activity": activity,
            "stage_support": {s: dict(c) for s, c in stage_support.items()},
            "recommendations_pending": pending,
            "recommendations_approved": approved,
            "recommendations_rejected": rejected,
            "report_requests": len(requests),
            "reports_generated": reports_generated,
        }

    @staticmethod
    def _alert_activity(alerts: list[dict], max_buckets: int = 48) -> dict:
        """Alert counts per time bucket (by first_seen). The bucket size follows the data's time span;
        empty buckets are kept so the time axis is not distorted."""
        if not alerts:
            return {"bucket_minutes": None, "items": []}
        times = [_parse_ts(a["first_seen"]) for a in alerts]
        start, end = min(times), max(times)
        span_min = (end - start).total_seconds() / 60
        size = next((m for m in (1, 5, 10, 15, 30, 60, 180, 360, 720, 1440, 10080)
                     if span_min / m < max_buckets), 43200)
        epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)

        def bucket(ts):
            minutes = int((ts - epoch).total_seconds() // 60)
            return minutes - minutes % size

        counts = Counter(bucket(t) for t in times)
        first, last = bucket(start), bucket(end)
        items = []
        for minute in range(first, last + 1, size):
            ts = datetime.fromtimestamp(minute * 60, timezone.utc)
            items.append({"start": ts.isoformat().replace("+00:00", "Z"), "alerts": counts.get(minute, 0)})
        return {"bucket_minutes": size, "items": items}

    # ------------------------------------------------------------ alerts
    def _alert_incidents(self) -> dict[str, list[str]]:
        index: dict[str, list[str]] = {}
        for incident_id, versions in self._incident_groups().items():
            for alert_id in versions[-1]["alert_ids"]:
                index.setdefault(alert_id, []).append(incident_id)
        return index

    def list_alerts(self, *, detector=None, network=None, ids_source=None, ip=None, rule=None,
                    incident_id=None, min_score=None, max_score=None, has_score=None, q=None,
                    limit=500, offset=0) -> dict:
        alerts = self.memory.read("Alert")
        membership = self._alert_incidents()
        if incident_id is not None:
            latest = self.memory.latest_incident(incident_id)
            if latest is None:
                raise NotFound(f"incident {incident_id} not found")
            allowed = set(latest["alert_ids"])
            alerts = [a for a in alerts if a["message_id"] in allowed]

        def keep(a):
            if detector and a["detector"] != detector:
                return False
            if network and a["network"] != network:
                return False
            if ids_source and a["ids_source"] != ids_source:
                return False
            if ip and ip not in (a["src_ip"], a["dst_ip"], a["host_ip"]):
                return False
            if rule and rule not in a["rule_hits"]:
                return False
            score = a["rf_score"]
            if has_score is not None and (score is not None) != has_score:
                return False
            if min_score is not None and (score is None or score < min_score):
                return False
            if max_score is not None and (score is None or score > max_score):
                return False
            if q:
                text = " ".join(str(a.get(k) or "") for k in
                                ("message_id", "summary", "signature", "hostname", "user")).lower()
                if q.lower() not in text:
                    return False
            return True

        matched = sorted((a for a in alerts if keep(a)), key=lambda a: (a["first_seen"], a["message_id"]))
        page = matched[offset:offset + limit]
        items = [{**a, "incident_ids": membership.get(a["message_id"], [])} for a in page]
        return {"items": items, "total": len(matched), "limit": limit, "offset": offset}

    def get_alert(self, alert_id: str) -> dict:
        alert = self.memory.get(alert_id)
        if alert is None or alert["message_type"] != "Alert":
            raise NotFound(f"alert {alert_id} not found")
        return {
            **alert,
            "incident_ids": self._alert_incidents().get(alert_id, []),
            "evidence": [self._classify_ref(r, set()) for r in alert["evidence_refs"]],
        }

    # ------------------------------------------------------------ incidents
    def list_incidents(self) -> dict:
        groups = self._incident_groups()
        assessments = self.memory.read("Assessment")
        items = []
        for incident_id, versions in groups.items():
            latest = versions[-1]
            related = self._assessments_for(incident_id, assessments)
            current = self._current_assessment(latest["version"], related)
            items.append({
                "incident_id": incident_id,
                "message_id": latest["message_id"],
                "version": latest["version"],
                "versions_available": [v["version"] for v in versions],
                "status": latest["status"],
                "network": latest["network"],
                "start_time": latest["start_time"],
                "end_time": latest["end_time"],
                "confidence": latest["confidence"],
                "alert_count": len(latest["alert_ids"]),
                "entities": latest["entities"],
                "technique_ids": [t["technique_id"] for t in latest["candidate_techniques"]],
                "stages": [s["stage"] for s in latest["stage_hypotheses"]],
                "severity": current["severity"] if current else None,
                "assessment_id": current["message_id"] if current else None,
                "outdated_assessments": [a["message_id"] for a in related if a["incident_version"] != latest["version"]],
                "review_summary": self.reviews.summary(current) if current else None,
            })
        order = {s: i for i, s in enumerate(reversed(SEVERITIES))}
        items.sort(key=lambda i: (order.get(i["severity"], len(order)), i["start_time"]), reverse=False)
        return {"items": items, "total": len(items)}

    def _incident(self, incident_id: str, version: int | None = None) -> tuple[dict, list[dict]]:
        versions = self._incident_groups().get(incident_id)
        if not versions:
            raise NotFound(f"incident {incident_id} not found")
        if version is None:
            return versions[-1], versions
        for v in versions:
            if v["version"] == version:
                return v, versions
        raise NotFound(f"incident {incident_id} has no version {version}")

    def get_incident(self, incident_id: str, version: int | None = None) -> dict:
        incident, versions = self._incident(incident_id, version)
        latest_version = versions[-1]["version"]
        related = self._assessments_for(incident_id)
        current = self._current_assessment(latest_version, related)
        missing_alerts = [a for a in incident["alert_ids"]
                          if (m := self.memory.get(a)) is None or m["message_type"] != "Alert"]
        return {
            **incident,
            "is_latest_version": incident["version"] == latest_version,
            "latest_version": latest_version,
            "versions_available": [v["version"] for v in versions],
            "uncertainty": _notes(incident["uncertainty_notes"]),
            "missing_alerts": missing_alerts,
            "current_assessment": self._assessment_view(current, latest_version) if current else None,
            "assessments": [self._assessment_view(a, latest_version) for a in related],
            "benign_explanations": self._benign_explanations(incident),
        }

    def incident_versions(self, incident_id: str) -> dict:
        _, versions = self._incident(incident_id)
        return {"incident_id": incident_id, "items": [
            {"message_id": v["message_id"], "version": v["version"], "created_at": v["created_at"],
             "alert_count": len(v["alert_ids"]), "confidence": v["confidence"], "status": v["status"]}
            for v in versions]}

    def incident_alerts(self, incident_id: str, version: int | None = None) -> dict:
        incident, _ = self._incident(incident_id, version)
        alerts = [m for a in incident["alert_ids"] if (m := self.memory.get(a)) and m["message_type"] == "Alert"]
        alerts.sort(key=lambda a: (a["first_seen"], a["message_id"]))
        return {"incident_id": incident_id, "version": incident["version"], "items": alerts, "total": len(alerts)}

    def incident_timeline(self, incident_id: str, version: int | None = None) -> dict:
        incident, _ = self._incident(incident_id, version)
        links: dict[str, list[dict]] = {}
        for link in incident["link_reasons"]:
            links.setdefault(link["alert_id"], []).append(link)
        alerts = self.incident_alerts(incident_id, incident["version"])["items"]
        events = []
        for alert in alerts:
            events.append({
                "time": alert["first_seen"],
                "last_seen": alert["last_seen"],
                "alert_id": alert["message_id"],
                "summary": alert["summary"],
                "detector": alert["detector"],
                "src_ip": alert["src_ip"],
                "dst_ip": alert["dst_ip"],
                "host_ip": alert["host_ip"],
                "hostname": alert["hostname"],
                "rf_score": alert["rf_score"],
                "rule_hits": alert["rule_hits"],
                "links": links.get(alert["message_id"], []),
            })
        return {"incident_id": incident_id, "version": incident["version"],
                "start_time": incident["start_time"], "end_time": incident["end_time"], "events": events}

    def _classify_ref(self, ref: str, incident_alerts: set[str]) -> dict:
        kind, _, item = ref.partition(":")
        if kind == "alert":
            found = (m := self.memory.get(item)) is not None and m["message_type"] == "Alert"
            if not found:
                status = "missing"
            elif incident_alerts and item not in incident_alerts:
                status = "outside_incident"
            else:
                status = "resolved"
        elif kind == "flow":
            status = "not_checked" if self.flow_ids is None else ("resolved" if item in self.flow_ids else "missing")
        elif kind in ("incident", "assessment"):
            status = "resolved" if self.memory.get(item) or (kind == "incident" and self.memory.latest_incident(item)) else "missing"
        elif kind == "rule":
            status = "not_verified"
        else:
            status = "not_checked"
        return {"ref": ref, "kind": kind, "id": item, "status": status}

    def _benign_explanations(self, incident: dict) -> list[dict]:
        """Documented limitations from the O-1 knowledge base for each candidate technique."""
        rules = self.knowledge["rules"]
        out = []
        for t in incident["candidate_techniques"]:
            rule = rules.get(t["technique_id"])
            text = rule and rule.get("technique_evidence", {}).get("limitations")
            if text:
                out.append({"technique_id": t["technique_id"], "text": text,
                            "source": f"O-1 knowledge base ({rule['mapping_rule_id']})"})
        return out

    def incident_frameworks(self, incident_id: str, version: int | None = None) -> dict:
        incident, _ = self._incident(incident_id, version)
        alert_ids = set(incident["alert_ids"])
        kb = self.knowledge
        techniques = []
        for t in incident["candidate_techniques"]:
            info = kb["techniques"].get(t["technique_id"], {})
            rule = kb["rules"].get(t["technique_id"], {})
            techniques.append({
                **t,
                "tactics": info.get("tactics", []),
                "reference_url": info.get("source_url"),
                "in_knowledge_base": bool(info),
                "possible_stages": [h["stage"] for h in rule.get("stage_hypotheses", [])],
                "evidence": [self._classify_ref(r, alert_ids) for r in t["evidence_refs"]],
            })
        hypotheses = {}
        for h in incident["stage_hypotheses"]:
            hypotheses.setdefault(h["stage"], []).append(h)
        stages = []
        for stage in KILL_CHAIN_STAGES:
            found = hypotheses.get(stage, [])
            rank = {"strong": 2, "weak": 1, "unmapped": 0}
            best = max((h["support"] for h in found), key=rank.get, default=None)
            refs = sorted({r for h in found for r in h["evidence_refs"]})
            stages.append({
                "stage": stage,
                "name": kb["stages"].get(stage, {}).get("name", stage.replace("_", " ").title()),
                "order": kb["stages"].get(stage, {}).get("order"),
                "description": kb["stages"].get(stage, {}).get("description"),
                "support": best or "no_hypothesis",
                "evidence": [self._classify_ref(r, alert_ids) for r in refs],
            })
        return {
            "incident_id": incident_id,
            "version": incident["version"],
            "techniques": techniques,
            "kill_chain": stages,
            "note": "Techniques and stages are hypotheses written by the Investigation Agent, not confirmed findings. "
                    "A technique can point to zero, one or several stages.",
        }

    # ------------------------------------------------------------ assessments
    def list_assessments(self, incident_id: str | None = None, current_only: bool = False) -> dict:
        groups = self._incident_groups()
        items = []
        for a in self.memory.read("Assessment"):
            if incident_id is not None and a["incident_id"] != incident_id:
                continue
            versions = groups.get(a["incident_id"])
            latest_version = versions[-1]["version"] if versions else None
            view = self._assessment_view(a, latest_version)
            if current_only and not view["is_current"]:
                continue
            items.append(view)
        return {"items": items, "total": len(items)}

    def get_assessment(self, assessment_id: str) -> dict:
        a = self.memory.get(assessment_id)
        if a is None or a["message_type"] != "Assessment":
            raise NotFound(f"assessment {assessment_id} not found")
        latest = self.memory.latest_incident(a["incident_id"])
        return self._assessment_view(a, latest["version"] if latest else None)

    # ------------------------------------------------------------ reviews
    def pending_reviews(self) -> dict:
        items = []
        for a in self.list_assessments(current_only=True)["items"]:
            for rec in a["recommendations"]:
                if rec["review_decision"] == "pending":
                    items.append({"assessment_id": a["message_id"], "incident_id": a["incident_id"],
                                  "incident_version": a["incident_version"], "severity": a["severity"],
                                  **{k: rec[k] for k in ("index", "action", "reason", "recommendation_ref")}})
        return {"items": items, "total": len(items)}

    def record_review(self, **kwargs) -> tuple[dict, bool]:
        return self.reviews.record(self.memory, **kwargs)

    def review_history(self, assessment_id=None, incident_id=None) -> dict:
        groups = self._incident_groups()
        items = []
        for r in self.reviews.history(assessment_id=assessment_id, incident_id=incident_id):
            versions = groups.get(r["incident_id"])
            latest = versions[-1]["version"] if versions else None
            items.append({**r, "applies_to_latest_version": r["incident_version"] == latest})
        return {"items": items, "total": len(items)}

    # ------------------------------------------------------------ reports
    def _report_path(self, request_id: str) -> Path:
        """Path of a report file, only inside the configured reports folder."""
        if not REPORT_ID_RE.fullmatch(request_id or ""):
            raise NotFound("invalid report id")
        base = Path(self.settings.reports_dir).resolve()
        path = (base / f"{request_id}.md").resolve()
        if path.parent != base:
            raise NotFound("invalid report id")
        return path

    def _report_entry(self, request: dict, groups, assessments) -> dict:
        path = self._report_path(request["message_id"])
        assessment = assessments.get(request["assessment_id"])
        versions = groups.get(request["incident_id"])
        latest = versions[-1]["version"] if versions else None
        exists = path.is_file()
        stat = path.stat() if exists else None
        return {
            "request_id": request["message_id"],
            "incident_id": request["incident_id"],
            "assessment_id": request["assessment_id"],
            "requested_at": request["created_at"],
            "requested_by": request["producer"],
            "reason": request["requested_by_reason"],
            "format": request["format"],
            "severity": assessment["severity"] if assessment else None,
            "assessment_incident_version": assessment["incident_version"] if assessment else None,
            "latest_incident_version": latest,
            "is_current": bool(assessment) and assessment["incident_version"] == latest,
            "generated": exists,
            "size_bytes": stat.st_size if stat else None,
            "generated_at": datetime.fromtimestamp(int(stat.st_mtime), timezone.utc).isoformat().replace("+00:00", "Z")
            if stat else None,
            "data_source": self.data_source,
            "is_demo_data": self.data_source == "fixtures",
        }

    def list_reports(self) -> dict:
        groups = self._incident_groups()
        assessments = {a["message_id"]: a for a in self.memory.read("Assessment")}
        items = [self._report_entry(r, groups, assessments) for r in self.memory.read("ReportRequest")]
        items.sort(key=lambda r: r["requested_at"], reverse=True)
        return {"items": items, "total": len(items)}

    def _request(self, request_id: str) -> dict:
        self._report_path(request_id)  # validates the id format first
        request = self.memory.get(request_id)
        if request is None or request["message_type"] != "ReportRequest":
            raise NotFound(f"report {request_id} not found")
        return request

    def get_report(self, request_id: str) -> dict:
        request = self._request(request_id)
        groups = self._incident_groups()
        assessments = {a["message_id"]: a for a in self.memory.read("Assessment")}
        entry = self._report_entry(request, groups, assessments)
        path = self._report_path(request_id)
        entry["content"] = path.read_text(encoding="utf-8") if path.is_file() else None
        return entry

    def report_file(self, request_id: str) -> Path:
        self._request(request_id)
        path = self._report_path(request_id)
        if not path.is_file():
            raise NotFound(f"report {request_id} has not been generated yet")
        return path

    def generate_report(self, assessment_id: str) -> dict:
        """Run the existing Reporting Agent for an assessment.

        Reuses the ReportRequest already stored for that assessment (as the
        orchestrator does); otherwise writes a new one from the analyst.
        """
        assessment = self.memory.get(assessment_id)
        if assessment is None or assessment["message_type"] != "Assessment":
            raise NotFound(f"assessment {assessment_id} not found")
        latest = self.memory.latest_incident(assessment["incident_id"])
        if latest is None or latest["version"] != assessment["incident_version"]:
            raise Conflict("assessment does not match the latest incident version; no report generated")
        validation = self.validator.validate(self.memory, self.flow_ids)
        if not validation["valid"]:
            raise Conflict("evidence validation failed; no report generated: " + "; ".join(validation["errors"][:5]))

        request = next((r for r in self.memory.read("ReportRequest") if r["assessment_id"] == assessment_id), None)
        if request is None:
            request = {
                "message_id": f"repreq-{uuid4().hex}",
                "message_type": "ReportRequest",
                "schema_version": SCHEMA_VERSION,
                "created_at": _utc_now(),
                "producer": "analyst",
                "evidence_refs": [f"incident:{assessment['incident_id']}", f"assessment:{assessment_id}"],
                "incident_id": assessment["incident_id"],
                "assessment_id": assessment_id,
                "requested_by_reason": "Requested from the dashboard",
                "format": "markdown",
            }
            self.memory.write(request)
        agent = ReportingAgent(self.settings.reports_dir, flow_ids=self.flow_ids)
        try:
            agent.run(request, self.memory)
        except ValueError as exc:
            raise Conflict(f"Reporting Agent did not generate the report: {exc}") from exc
        return self.get_report(request["message_id"])

    # ------------------------------------------------------------ validation
    def validation(self) -> dict:
        result = self.validator.validate(self.memory, self.flow_ids)
        return {
            **result,
            "scope": "entire database",
            "flow_ids_available": len(self.flow_ids) if self.flow_ids is not None else 0,
            "rule_definitions_verified": False,
            "limitations": VALIDATION_LIMITATIONS,
            "data_source": self.data_source,
        }
