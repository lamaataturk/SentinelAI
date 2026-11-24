
from sentinelai.contracts.messages import validate_bundle


class EvidenceValidator:

    def validate(self, memory, flow_ids=None):

        messages = memory.read()

        errors = validate_bundle(messages, flow_ids)

        for message in messages:

            message_type = message["message_type"]

            if message_type == "IncidentUpdate":
                errors.extend(
                    self._validate_incident(message, memory)
                )

            elif message_type == "Assessment":
                errors.extend(
                    self._validate_assessment(message)
                )

            elif message_type == "ReportRequest":
                errors.extend(
                    self._validate_request(message, memory)
                )

        return {
            "valid": len(errors) == 0,
            "messages_checked": len(messages),
            "errors": errors,
            "flow_references_checked": flow_ids is not None,
        }

    def _validate_incident(self, incident, memory):

        errors = []
        incident_id = incident["incident_id"]
        alert_ids = set(incident["alert_ids"])

        for alert_id in alert_ids:
            alert = memory.get(alert_id)

            if alert is None:
                errors.append(
                    f"{incident_id}: missing alert {alert_id}"
                )

            elif alert["message_type"] != "Alert":
                errors.append(
                    f"{incident_id}: invalid alert reference"
                )

        findings = (
            incident["candidate_techniques"]
            + incident["stage_hypotheses"]
        )

        for finding in findings:

            refs = finding["evidence_refs"]

            if finding["support"] != "unmapped" and not refs:
                errors.append(
                    f"{incident_id}: finding has no evidence"
                )

            for ref in refs:

                kind, _, ref_id = ref.partition(":")

                if kind == "alert" and ref_id not in alert_ids:
                    errors.append(
                        f"{incident_id}: evidence {ref_id} "
                        "does not belong to this incident"
                    )

        return errors

    def _validate_assessment(self, assessment):

        errors = []
        assessment_id = assessment["message_id"]

        for recommendation in assessment["recommendations"]:

            if recommendation["requires_human_approval"] is not True:
                errors.append(
                    f"{assessment_id}: human approval is required"
                )

            if not str(recommendation["reason"]).strip():
                errors.append(
                    f"{assessment_id}: recommendation has no reason"
                )

        return errors

    def _validate_request(self, request, memory):

        errors = []
        request_id = request["message_id"]

        assessment = memory.get(request["assessment_id"])

        if assessment is None:
            errors.append(
                f"{request_id}: assessment not found"
            )
            return errors

        if assessment["message_type"] != "Assessment":
            errors.append(
                f"{request_id}: invalid assessment reference"
            )
            return errors

        if assessment["incident_id"] != request["incident_id"]:
            errors.append(
                f"{request_id}: incident mismatch"
            )

        return errors
