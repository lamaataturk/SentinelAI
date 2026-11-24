
from datetime import datetime, timezone
from uuid import uuid4

from sentinelai.contracts.messages import SCHEMA_VERSION


class Orchestrator:
    def __init__(
        self,
        memory,
        investigation_agent,
        response_agent,
        reporting_agent,
    ):
        self.memory = memory
        self.investigation_agent = investigation_agent
        self.response_agent = response_agent
        self.reporting_agent = reporting_agent
        self.processed = set()

    def _create_report_request(self, assessment):
        existing = self.memory.read("ReportRequest")

        for request in existing:
            if request["assessment_id"] == assessment["message_id"]:
                return

        request = {
            "message_id": f"repreq-{uuid4().hex}",
            "message_type": "ReportRequest",
            "schema_version": SCHEMA_VERSION,
            "created_at": datetime.now(
                timezone.utc
            ).isoformat().replace("+00:00", "Z"),
            "producer": "orchestrator",
            "evidence_refs": [
                f"incident:{assessment['incident_id']}",
                f"assessment:{assessment['message_id']}",
            ],
            "incident_id": assessment["incident_id"],
            "assessment_id": assessment["message_id"],
            "requested_by_reason": "New assessment",
            "format": "markdown",
        }

        self.memory.write(request)

    def _process(self, message_type, handler):
        count = 0

        for message in self.memory.read(message_type):
            message_id = message["message_id"]

            if message_id in self.processed:
                continue

            handler(message)
            self.processed.add(message_id)
            count += 1

        return count

    def run_once(self):
        results = {
            "alerts_processed": self._process(
                "Alert",
                lambda message: self.investigation_agent.run(
                    message, self.memory
                ),
            ),
            "incidents_processed": self._process(
                "IncidentUpdate",
                lambda message: self.response_agent.run(
                    message, self.memory
                ),
            ),
            "assessments_processed": self._process(
                "Assessment",
                self._create_report_request,
            ),
            "reports_processed": self._process(
                "ReportRequest",
                lambda message: self.reporting_agent.run(
                    message, self.memory
                ),
            ),
        }

        return results
