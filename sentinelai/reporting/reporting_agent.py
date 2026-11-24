
from pathlib import Path
import re

from sentinelai.contracts.messages import validate_message
from sentinelai.reporting.traceability import EvidenceValidator

class ReportingAgent:

    def __init__(self, output_dir="reports", flow_ids=None):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.reports = {}
        self.validator = EvidenceValidator()
        self.flow_ids = flow_ids

    def run(self, message, memory):

        if validate_message(message):
            raise ValueError("Invalid message")

        if message["message_type"] != "ReportRequest":
            raise ValueError("Expected a ReportRequest")

        if message["format"] != "markdown":
            raise ValueError("Only Markdown is currently supported")
        
        validation = self.validator.validate(
            memory, self.flow_ids
        )

        if not validation["valid"]:
            raise ValueError(
                "Evidence validation failed: "
                + "; ".join(validation["errors"])
            )
        
        incident_id = message["incident_id"]
        assessment_id = message["assessment_id"]

        assessment = memory.get(assessment_id)

        if assessment is None:
            raise ValueError("Assessment not found")

        if (
            assessment["message_type"] != "Assessment"
            or assessment["incident_id"] != incident_id
        ):
            raise ValueError("Assessment does not match incident")

        incident = memory.latest_incident(incident_id)

        if incident is None:
            raise ValueError("Incident not found")

        if assessment["incident_version"] != incident["version"]:
            raise ValueError(
                "Assessment does not match latest incident version"
            )

        alerts = []
        missing_alerts = []

        for alert_id in incident["alert_ids"]:
            alert = memory.get(alert_id)

            if alert and alert["message_type"] == "Alert":
                alerts.append(alert)
            else:
                missing_alerts.append(alert_id)

        alerts.sort(key=lambda alert: alert["first_seen"])

        report = self.generate_report(
            incident,
            assessment,
            alerts,
            missing_alerts,
            message["message_id"],
        )
        report += "\n## 11. Evidence Validation\n\n"
        report += "- Stored-message validation: Passed\n"

        if validation["flow_references_checked"]:
            report += "- Flow reference validation: Passed\n"
        else:
            report += "- Flow reference validation: Not performed\n"

        report += "- Detection rule definitions: Not verified\n"
        report += (
            "- Reference validation does not confirm "
            "the correctness of cybersecurity interpretations.\n"
        )
    
        request_id = message["message_id"]

        if not re.fullmatch(r"[A-Za-z0-9_-]+", request_id):
            raise ValueError("Invalid report filename")

        path = self.output_dir / f"{request_id}.md"
        path.write_text(report, encoding="utf-8")

        self.reports[request_id] = path

        return path

    def generate_report(
        self,
        incident,
        assessment,
        alerts,
        missing_alerts,
        request_id,
    ):

        incident_id = incident["incident_id"]
        assessment_id = assessment["message_id"]

        incident_ref = f"[Incident: {incident_id}]"
        assessment_ref = f"[Assessment: {assessment_id}]"

        lines = [
            "# SentinelAI Incident Report",
            "",
            f"**Incident:** {incident_id}",
            f"**Incident version:** {incident['version']}",
            f"**Assessment:** {assessment_id}",
            f"**Report request:** {request_id}",
            "**Classification:** Possible security incident",
            "",
            "## 1. Incident Overview",
            "",
            f"- Network: {incident['network']} {incident_ref}",
            f"- Start: {incident['start_time']} {incident_ref}",
            f"- End: {incident['end_time']} {incident_ref}",
            f"- Confidence: {incident['confidence']} {incident_ref}",
            "",
            "## 2. Event Timeline",
            "",
        ]

        if not alerts:
            lines.append("No referenced alerts are available.")

        for alert in alerts:
            ref = f"[Alert: {alert['message_id']}]"

            lines.append(
                f"- {alert['first_seen']}: "
                f"{alert['summary']} {ref}"
            )

        lines.extend([
            "",
            "## 3. Evidence and Detection Results",
            "",
        ])

        for alert in alerts:
            ref = f"[Alert: {alert['message_id']}]"

            score = alert["rf_score"]

            if score is None:
                score = "Not available"

            rules = ", ".join(alert["rule_hits"]) or "None recorded"

            evidence = ", ".join(alert["evidence_refs"])

            lines.extend([
                f"### {alert['message_id']}",
                f"- Source IP: {alert['src_ip']} {ref}",
                f"- Destination IP: {alert['dst_ip']} {ref}",
                f"- Detector: {alert['detector']} {ref}",
                f"- Random Forest score: {score} {ref}",
                f"- Rule hits: {rules} {ref}",
                f"- Evidence references: {evidence} {ref}",
                "",
            ])

        lines.extend([
            "## 4. Possible MITRE ATT&CK Techniques",
            "",
        ])

        if not incident["candidate_techniques"]:
            lines.append("No candidate techniques recorded.")

        for technique in incident["candidate_techniques"]:
            refs = ", ".join(technique["evidence_refs"])
            refs = refs or "No supporting references recorded"

            lines.append(
                f"- Possible {technique['technique_id']} "
                f"({technique['name']}) — "
                f"support: {technique['support']}. "
                f"Evidence: {refs}. {incident_ref}"
            )

        lines.extend([
            "",
            "## 5. Cyber Kill Chain Assessment",
            "",
        ])

        if not incident["stage_hypotheses"]:
            lines.append("Attack progression is undetermined.")

        for stage in incident["stage_hypotheses"]:
            refs = ", ".join(stage["evidence_refs"])
            refs = refs or "No supporting references recorded"

            lines.append(
                f"- Possible stage: {stage['stage']} — "
                f"support: {stage['support']}. "
                f"Evidence: {refs}. {incident_ref}"
            )

        lines.extend([
            "",
            "## 6. Severity Assessment",
            "",
            f"**Assigned severity:** "
            f"{assessment['severity']} {assessment_ref}",
            f"**Policy:** "
            f"{assessment['policy_rule_id']} {assessment_ref}",
            "",
        ])

        for reason in assessment["severity_reasons"]:
            lines.append(f"- {reason} {assessment_ref}")

        lines.extend([
            "",
            "## 7. Defensive Recommendations",
            "",
        ])

        if not assessment["recommendations"]:
            lines.append("No recommendations recorded.")

        for recommendation in assessment["recommendations"]:
            lines.extend([
                f"- Suggested action: "
                f"{recommendation['action']} {assessment_ref}",
                f"  - Reason: "
                f"{recommendation['reason']} {assessment_ref}",
                "  - Human approval required: Yes",
            ])

        lines.extend([
            "",
            f"**Review status:** "
            f"{assessment['review_status']} {assessment_ref}",
            "",
            "## 8. Uncertainty and Missing Evidence",
            "",
            f"- {incident['uncertainty_notes']} {incident_ref}",
        ])

        for alert_id in missing_alerts:
            lines.append(
                f"- Missing referenced alert: "
                f"{alert_id} {incident_ref}"
            )

        lines.extend([
            "",
            "## 9. Possible Benign Explanations",
            "",
            "The following are general alternative explanations "
            "for analyst consideration, not observed findings:",
            "",
            "- Authorized security monitoring.",
            "- Scheduled maintenance or software updates.",
            "- Legitimate employee or application activity.",
            "",
            "## 10. Human Review",
            "",
            "This report describes a possible security incident. "
            "A human analyst must review the evidence before "
            "making a final determination or approving actions.",
        ])

        return "\n".join(lines) + "\n"
