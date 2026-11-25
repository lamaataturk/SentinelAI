"""L-6.3: persistent human review decisions for Response Agent recommendations.

Design decisions
* Reviews are stored in their own table (`human_reviews`) in the same SQLite
  file as the shared memory. Assessment messages are never changed, so the
  `review_status` field inside a stored Assessment keeps the value the Response
  Agent wrote ("pending"). The current status is always worked out from this table.
* Recommendations have no ID in the message contract, so a recommendation is
  identified by (assessment_id, position in the list). Assessments are immutable,
  so that position never changes. A fingerprint (SHA-256 of the recommendation)
  and the action text are stored with every decision so the audit trail stays
  readable on its own.
* The table is append-only. Changing a decision adds a new row that points to the
  row it replaces (`supersedes`); nothing is updated or deleted.
* A decision is only accepted for an assessment of the incident's latest version.
  Decisions about an older version stay in the history but are never shown as
  the status of a newer version.
* Recording a decision only records it. Nothing here (or anywhere in the
  platform) carries out a recommendation.
* `analyst` is a free-text label typed by the user. There is no authentication.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import closing
from uuid import uuid4

from sentinelai.platform.metadata import utc_now

DECISIONS = ("approved", "rejected")
MAX_COMMENT_LENGTH = 2000
MAX_ANALYST_LENGTH = 100


class ReviewError(ValueError):
    """A review that cannot be accepted. `status` is the matching HTTP status code."""

    def __init__(self, message: str, status: int = 422):
        super().__init__(message)
        self.status = status


def recommendation_ref(assessment_id: str, index: int) -> str:
    return f"{assessment_id}#rec-{index}"


def recommendation_fingerprint(recommendation: dict) -> str:
    canonical = json.dumps(recommendation, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


_COLUMNS = (
    "review_id", "assessment_id", "incident_id", "incident_version", "recommendation_index",
    "recommendation_ref", "recommendation_fingerprint", "recommendation_action",
    "decision", "comment", "analyst", "reviewed_at", "supersedes",
)


class ReviewStore:
    def __init__(self, db_path):
        self.db_path = db_path
        with closing(self._connect()) as conn, conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS human_reviews (
                    review_id TEXT PRIMARY KEY NOT NULL,
                    assessment_id TEXT NOT NULL,
                    incident_id TEXT NOT NULL,
                    incident_version INTEGER NOT NULL,
                    recommendation_index INTEGER NOT NULL,
                    recommendation_ref TEXT NOT NULL,
                    recommendation_fingerprint TEXT NOT NULL,
                    recommendation_action TEXT NOT NULL,
                    decision TEXT NOT NULL CHECK (decision IN ('approved', 'rejected')),
                    comment TEXT NOT NULL DEFAULT '',
                    analyst TEXT NOT NULL DEFAULT '',
                    reviewed_at TEXT NOT NULL,
                    supersedes TEXT REFERENCES human_reviews(review_id)
                );
                CREATE INDEX IF NOT EXISTS idx_reviews_assessment
                    ON human_reviews(assessment_id, recommendation_index);
                CREATE INDEX IF NOT EXISTS idx_reviews_incident
                    ON human_reviews(incident_id, incident_version);
            """)

    def _connect(self):
        return sqlite3.connect(self.db_path)

    @staticmethod
    def _row(row) -> dict:
        return dict(zip(_COLUMNS, row))

    # ------------------------------------------------------------ reading
    def history(self, assessment_id: str | None = None, incident_id: str | None = None) -> list[dict]:
        """Every decision, oldest first (the full audit trail)."""
        query = f"SELECT {', '.join(_COLUMNS)} FROM human_reviews"
        clauses, params = [], []
        if assessment_id is not None:
            clauses.append("assessment_id = ?")
            params.append(assessment_id)
        if incident_id is not None:
            clauses.append("incident_id = ?")
            params.append(incident_id)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY reviewed_at, rowid"
        with closing(self._connect()) as conn:
            return [self._row(r) for r in conn.execute(query, params)]

    def get(self, review_id: str) -> dict | None:
        with closing(self._connect()) as conn:
            row = conn.execute(
                f"SELECT {', '.join(_COLUMNS)} FROM human_reviews WHERE review_id = ?", (review_id,)
            ).fetchone()
        return self._row(row) if row else None

    def current(self, assessment_id: str) -> dict[int, dict]:
        """The latest decision per recommendation index of one assessment."""
        latest: dict[int, dict] = {}
        for review in self.history(assessment_id=assessment_id):
            latest[review["recommendation_index"]] = review
        return latest

    def summary(self, assessment: dict) -> dict:
        """Review status of one assessment, worked out from the decisions table."""
        total = len(assessment["recommendations"])
        current = self.current(assessment["message_id"])
        approved = sum(1 for r in current.values() if r["decision"] == "approved")
        rejected = sum(1 for r in current.values() if r["decision"] == "rejected")
        pending = total - approved - rejected
        if total == 0:
            status = "no_recommendations"
        elif pending:
            status = "pending" if pending == total else "partially_reviewed"
        else:
            status = "reviewed"
        return {
            "status": status,
            "recommendations": total,
            "approved": approved,
            "rejected": rejected,
            "pending": pending,
        }

    # ------------------------------------------------------------ writing
    def record(
        self,
        memory,
        *,
        assessment_id: str,
        recommendation_index: int,
        decision: str,
        incident_version: int,
        comment: str = "",
        analyst: str = "",
    ) -> tuple[dict, bool]:
        """Validate and store one decision. Returns (review, created).

        created is False when the same decision and comment are already the
        current decision for that recommendation (a repeated click or retry).
        """
        if decision not in DECISIONS:
            raise ReviewError(f"decision must be one of {DECISIONS}")
        if not isinstance(recommendation_index, int) or isinstance(recommendation_index, bool):
            raise ReviewError("recommendation_index must be an integer")
        comment = (comment or "").strip()
        analyst = (analyst or "").strip()
        if len(comment) > MAX_COMMENT_LENGTH:
            raise ReviewError(f"comment is longer than {MAX_COMMENT_LENGTH} characters")
        if len(analyst) > MAX_ANALYST_LENGTH:
            raise ReviewError(f"analyst is longer than {MAX_ANALYST_LENGTH} characters")

        assessment = memory.get(assessment_id)
        if assessment is None or assessment.get("message_type") != "Assessment":
            raise ReviewError(f"assessment {assessment_id} not found", status=404)

        recommendations = assessment["recommendations"]
        if not 0 <= recommendation_index < len(recommendations):
            raise ReviewError(
                f"assessment {assessment_id} has no recommendation {recommendation_index}", status=404
            )

        if incident_version != assessment["incident_version"]:
            raise ReviewError(
                f"assessment {assessment_id} is for incident version {assessment['incident_version']}, "
                f"not version {incident_version}",
                status=409,
            )
        latest = memory.latest_incident(assessment["incident_id"])
        if latest is None:
            raise ReviewError(f"incident {assessment['incident_id']} not found", status=409)
        if latest["version"] != assessment["incident_version"]:
            raise ReviewError(
                f"assessment {assessment_id} is outdated: it judged version "
                f"{assessment['incident_version']} but incident {assessment['incident_id']} "
                f"is now at version {latest['version']}",
                status=409,
            )

        recommendation = recommendations[recommendation_index]
        previous = self.current(assessment_id).get(recommendation_index)
        if previous and previous["decision"] == decision and previous["comment"] == comment:
            return previous, False

        review = {
            "review_id": f"review-{uuid4().hex}",
            "assessment_id": assessment_id,
            "incident_id": assessment["incident_id"],
            "incident_version": assessment["incident_version"],
            "recommendation_index": recommendation_index,
            "recommendation_ref": recommendation_ref(assessment_id, recommendation_index),
            "recommendation_fingerprint": recommendation_fingerprint(recommendation),
            "recommendation_action": str(recommendation["action"]),
            "decision": decision,
            "comment": comment,
            "analyst": analyst,
            "reviewed_at": utc_now(),
            "supersedes": previous["review_id"] if previous else None,
        }
        with closing(self._connect()) as conn, conn:
            conn.execute(
                f"INSERT INTO human_reviews ({', '.join(_COLUMNS)}) VALUES ({', '.join('?' * len(_COLUMNS))})",
                tuple(review[c] for c in _COLUMNS),
            )
        return review, True
