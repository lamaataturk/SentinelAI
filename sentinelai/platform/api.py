"""L-6.2: FastAPI backend for the SentinelAI analyst dashboard.

Run locally (binds to 127.0.0.1 only):

    python -m sentinelai.platform.api

or  python -m uvicorn sentinelai.platform.api:app --host 127.0.0.1 --port 8000

Interactive API docs: http://127.0.0.1:8000/docs

The API reads agent messages through SharedMemory and only ever writes:
  * human review decisions (separate `human_reviews` table), and
  * ReportRequest messages + report files through the existing Reporting Agent.
It never executes a recommendation.
"""
from __future__ import annotations

import logging
from typing import Literal

from fastapi import FastAPI, HTTPException, Path, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

from sentinelai.contracts.messages import DETECTORS, IDS_SOURCES
from sentinelai.platform.config import Settings
from sentinelai.platform.reviews import DECISIONS, MAX_ANALYST_LENGTH, MAX_COMMENT_LENGTH, ReviewError
from sentinelai.platform.service import Conflict, NotFound, PlatformService

log = logging.getLogger("sentinelai.api")

API_VERSION = "1.0"
# Identifier formats from the message contract (prefixes) plus a safe character set.
ALERT_ID = r"^alert-[A-Za-z0-9_.-]{1,120}$"
INCIDENT_ID = r"^inc-[A-Za-z0-9_.-]{1,120}$"
ASSESSMENT_ID = r"^assess-[A-Za-z0-9_.-]{1,120}$"
REPORT_ID = r"^repreq-[A-Za-z0-9_-]{1,120}$"


class ReviewIn(BaseModel):
    assessment_id: str = Field(pattern=ASSESSMENT_ID)
    recommendation_index: int = Field(ge=0, le=10_000)
    incident_version: int = Field(ge=1, description="Version the analyst saw; must match the assessment")
    decision: Literal["approved", "rejected"]
    comment: str = Field(default="", max_length=MAX_COMMENT_LENGTH)
    analyst: str = Field(default="", max_length=MAX_ANALYST_LENGTH,
                         description="Free-text label. Not authenticated.")


class ReviewOut(BaseModel):
    review_id: str
    assessment_id: str
    incident_id: str
    incident_version: int
    recommendation_index: int
    recommendation_ref: str
    recommendation_fingerprint: str
    recommendation_action: str
    decision: str
    comment: str
    analyst: str
    reviewed_at: str
    supersedes: str | None
    created: bool
    note: str = "Decision recorded only. No action was executed."


class ReportIn(BaseModel):
    assessment_id: str = Field(pattern=ASSESSMENT_ID)


class Health(BaseModel):
    status: str
    api_version: str
    mode: str
    data_source: str


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    service = PlatformService(settings)

    app = FastAPI(
        title="SentinelAI Platform API",
        version=API_VERSION,
        description="Read-only access to SentinelAI shared memory, report generation through the "
                    "Reporting Agent, and human review records. Decisions are advisory only.",
    )
    app.state.service = service
    if settings.allowed_hosts:
        # A web page can point its own domain at 127.0.0.1 (DNS rebinding) and send
        # requests here. Those requests carry the page's host name, so they are refused.
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(settings.allowed_hosts))

    # --------------------------------------------------------- error handling
    @app.exception_handler(NotFound)
    async def _not_found(_: Request, exc: NotFound):
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(Conflict)
    async def _conflict(_: Request, exc: Conflict):
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(ReviewError)
    async def _review_error(_: Request, exc: ReviewError):
        return JSONResponse(status_code=exc.status, content={"detail": str(exc)})

    @app.exception_handler(RequestValidationError)
    async def _invalid(_: Request, exc: RequestValidationError):
        problems = [{"field": ".".join(str(p) for p in e["loc"][1:]), "problem": e["msg"]} for e in exc.errors()]
        return JSONResponse(status_code=422, content={"detail": "invalid request", "errors": problems})

    @app.exception_handler(Exception)
    async def _unexpected(_: Request, exc: Exception):
        log.exception("unhandled error")  # full trace in the server log only
        return JSONResponse(status_code=500, content={"detail": "internal server error"})

    # --------------------------------------------------------- system
    @app.get("/api/health", response_model=Health, tags=["system"])
    def health():
        return {"status": "ok", "api_version": API_VERSION, "mode": settings.mode,
                "data_source": service.data_source}

    @app.get("/api/system", tags=["system"])
    def system():
        return service.system_status()

    @app.get("/api/stats", tags=["dashboard"])
    def stats():
        return service.stats()

    # --------------------------------------------------------- alerts
    @app.get("/api/alerts", tags=["alerts"])
    def alerts(
        detector: Literal[tuple(sorted(DETECTORS))] | None = None,
        network: str | None = Query(None, max_length=100),
        ids_source: Literal[tuple(sorted(IDS_SOURCES))] | None = None,
        ip: str | None = Query(None, max_length=45),
        rule: str | None = Query(None, max_length=100),
        incident_id: str | None = Query(None, pattern=INCIDENT_ID),
        min_score: float | None = Query(None, ge=0, le=1),
        max_score: float | None = Query(None, ge=0, le=1),
        has_score: bool | None = None,
        q: str | None = Query(None, max_length=200),
        limit: int = Query(500, ge=1, le=5000),
        offset: int = Query(0, ge=0),
    ):
        if min_score is not None and max_score is not None and min_score > max_score:
            raise HTTPException(422, "min_score is greater than max_score")
        return service.list_alerts(detector=detector, network=network, ids_source=ids_source, ip=ip,
                                   rule=rule, incident_id=incident_id, min_score=min_score,
                                   max_score=max_score, has_score=has_score, q=q, limit=limit, offset=offset)

    @app.get("/api/alerts/{alert_id}", tags=["alerts"])
    def alert(alert_id: str = Path(pattern=ALERT_ID)):
        return service.get_alert(alert_id)

    # --------------------------------------------------------- incidents
    @app.get("/api/incidents", tags=["incidents"])
    def incidents():
        return service.list_incidents()

    @app.get("/api/incidents/{incident_id}", tags=["incidents"])
    def incident(incident_id: str = Path(pattern=INCIDENT_ID), version: int | None = Query(None, ge=1)):
        return service.get_incident(incident_id, version)

    @app.get("/api/incidents/{incident_id}/versions", tags=["incidents"])
    def incident_versions(incident_id: str = Path(pattern=INCIDENT_ID)):
        return service.incident_versions(incident_id)

    @app.get("/api/incidents/{incident_id}/alerts", tags=["incidents"])
    def incident_alerts(incident_id: str = Path(pattern=INCIDENT_ID), version: int | None = Query(None, ge=1)):
        return service.incident_alerts(incident_id, version)

    @app.get("/api/incidents/{incident_id}/timeline", tags=["incidents"])
    def incident_timeline(incident_id: str = Path(pattern=INCIDENT_ID), version: int | None = Query(None, ge=1)):
        return service.incident_timeline(incident_id, version)

    @app.get("/api/incidents/{incident_id}/frameworks", tags=["incidents"])
    def incident_frameworks(incident_id: str = Path(pattern=INCIDENT_ID), version: int | None = Query(None, ge=1)):
        return service.incident_frameworks(incident_id, version)

    @app.get("/api/incidents/{incident_id}/assessments", tags=["incidents"])
    def incident_assessments(incident_id: str = Path(pattern=INCIDENT_ID)):
        service.incident_versions(incident_id)  # 404 if the incident does not exist
        return service.list_assessments(incident_id=incident_id)

    # --------------------------------------------------------- assessments
    @app.get("/api/assessments", tags=["assessments"])
    def assessments(incident_id: str | None = Query(None, pattern=INCIDENT_ID), current_only: bool = False):
        return service.list_assessments(incident_id=incident_id, current_only=current_only)

    @app.get("/api/assessments/{assessment_id}", tags=["assessments"])
    def assessment(assessment_id: str = Path(pattern=ASSESSMENT_ID)):
        return service.get_assessment(assessment_id)

    # --------------------------------------------------------- reviews
    @app.get("/api/reviews", tags=["reviews"])
    def reviews(assessment_id: str | None = Query(None, pattern=ASSESSMENT_ID),
                incident_id: str | None = Query(None, pattern=INCIDENT_ID)):
        return service.review_history(assessment_id=assessment_id, incident_id=incident_id)

    @app.get("/api/reviews/pending", tags=["reviews"])
    def pending_reviews():
        return service.pending_reviews()

    @app.post("/api/reviews", response_model=ReviewOut, tags=["reviews"],
              responses={200: {"description": "Same decision already recorded (no new entry)"},
                         201: {"description": "Decision recorded"},
                         404: {"description": "Assessment or recommendation not found"},
                         409: {"description": "Assessment is outdated or the version does not match"}})
    def create_review(body: ReviewIn, response: Response):
        review, created = service.record_review(**body.model_dump())
        response.status_code = 201 if created else 200
        return {**review, "created": created}

    # --------------------------------------------------------- reports
    @app.get("/api/reports", tags=["reports"])
    def reports():
        return service.list_reports()

    @app.post("/api/reports", status_code=201, tags=["reports"])
    def generate_report(body: ReportIn):
        return service.generate_report(body.assessment_id)

    @app.get("/api/reports/{request_id}", tags=["reports"])
    def report(request_id: str = Path(pattern=REPORT_ID)):
        return service.get_report(request_id)

    @app.get("/api/reports/{request_id}/download", tags=["reports"])
    def download_report(request_id: str = Path(pattern=REPORT_ID)):
        path = service.report_file(request_id)
        return Response(
            content=path.read_bytes(),
            media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{path.name}"',
                     "X-Content-Type-Options": "nosniff"},
        )

    # --------------------------------------------------------- validation
    @app.get("/api/validation", tags=["validation"])
    def validation():
        return service.validation()

    @app.get("/api/meta/decisions", tags=["system"])
    def decisions():
        return {"decisions": list(DECISIONS)}

    return app


def main():
    import uvicorn

    settings = Settings.from_env()
    if settings.api_host not in ("127.0.0.1", "localhost", "::1"):
        log.warning("API is bound to %s; this prototype has no authentication", settings.api_host)
    uvicorn.run(create_app(settings), host=settings.api_host, port=settings.api_port)


def __getattr__(name):  # `uvicorn sentinelai.platform.api:app` builds the app on first use
    if name == "app":
        return create_app()
    raise AttributeError(name)


if __name__ == "__main__":
    main()
