# Spec · Reporting Agent + platform

**Owner:** Lama · **Tasks:** L-1 to L-6 · **Slides:** 7, 12, 16

> ALL-4 spec. Updated after L-6 with what was built.

## Reporting Agent
| | |
|---|---|
| **Goal** | Write a clear incident report an analyst can check |
| **Observes** | Everything in shared memory for one incident |
| **State** | Report template, reports already written |
| **Decision policy** | Use only facts in shared memory. Point out gaps. Every statement cites an alert, flow or incident ID. |
| **Actions** | Writes a markdown report for each `ReportRequest` |
| **Reads** | `ReportRequest`, `IncidentUpdate` (latest version), `Assessment`, `Alert` |
| **Autonomy limit** | Says "possible", never "confirmed"; lists innocent explanations |

Report sections: timeline · evidence (with IPs) · ML scores and rule hits · possible techniques · attack stage · severity and why · advice · uncertainty · innocent explanations.

## Shared memory (SQLite)
- Table `messages(message_id PK, message_type, created_at, producer, body JSON)`. `scripts/check_contracts.py --sqlite` reads this table.
- Index `idx_messages_type` on `message_type`. Incident versions: `latest_incident(id)` reads all `IncidentUpdate`s of that incident and returns the highest `version`.
- L-6 adds two tables to the same file, never touching `messages`: `human_reviews` (append-only review log) and `platform_meta` (data source: `fixtures` or `agents`).

## Orchestrator
Scheduler only, not an agent: new Alert → Investigation; new IncidentUpdate → Response; new Assessment → ReportRequest; new ReportRequest → Reporting. Triggered by calling `run_once()` (no background polling); processed IDs are kept in memory.

## API and dashboard
- FastAPI (`sentinelai/platform/api.py`, bound to 127.0.0.1): `/api/health`, `/api/system`, `/api/stats`, `/api/alerts[/{id}]`, `/api/incidents[/{id}[/versions|/alerts|/timeline|/frameworks|/assessments]]`, `/api/assessments[/{id}]`, `/api/reviews` (GET, POST), `/api/reviews/pending`, `/api/reports` (GET, POST), `/api/reports/{id}[/download]`, `/api/validation`. Full table in the README.
- Streamlit (`sentinelai/dashboard/`, talks to the API only): Overview, Alerts, Incident Investigation, ATT&CK & Kill Chain, Incident Reports, Human Review.
- Approve/reject is saved in shared memory's SQLite file, in a separate `human_reviews` table, so Assessment messages stay immutable. Decisions are only accepted for the assessment of an incident's latest version (409 otherwise) and execute nothing.
- Demo mode: `scripts/init_demo.py` loads the fixtures into `data/platform/demo/` (idempotent) and generates reports with the Reporting Agent. Live mode reads `data/platform/live/`.
