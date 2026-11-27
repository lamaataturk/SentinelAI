import logging
from datetime import datetime, timezone
from uuid import uuid4

from sentinelai.contracts.messages import SCHEMA_VERSION

log = logging.getLogger("sentinelai.orchestrator")


class Orchestrator:
    """Route new shared-memory messages to the agent that handles them.

    An agent passed as None is not run, and its messages wait for a later run.
    A message whose handler raises is logged, listed under "errors" and retried
    on the next run, so one bad message never stops the others.
    """

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

    def _process(self, message_type, handler, errors):
        count = 0
        failed = 0

        for message in self.memory.read(message_type):
            message_id = message["message_id"]

            if message_id in self.processed:
                continue

            try:
                handler(message)
            except Exception as error:
                failed += 1
                if failed == 1:
                    log.exception("%s %s failed; failed messages are retried on the next run",
                                  message_type, message_id)
                errors.append({
                    "message_id": message_id,
                    "message_type": message_type,
                    "error": f"{type(error).__name__}: {error}",
                })
                continue

            self.processed.add(message_id)
            count += 1

        if failed > 1:
            log.error("%d %s messages failed in this run (first traceback above)",
                      failed, message_type)

        return count

    def _run_agent(self, agent, message_type, errors):
        if agent is None:
            return 0

        return self._process(
            message_type,
            lambda message: agent.run(message, self.memory),
            errors,
        )

    def run_once(self):
        errors = []
        results = {
            "alerts_processed": self._run_agent(
                self.investigation_agent, "Alert", errors
            ),
            "incidents_processed": self._run_agent(
                self.response_agent, "IncidentUpdate", errors
            ),
            "assessments_processed": self._process(
                "Assessment", self._create_report_request, errors
            ),
            "reports_processed": self._run_agent(
                self.reporting_agent, "ReportRequest", errors
            ),
            "errors": errors,
        }

        return results
