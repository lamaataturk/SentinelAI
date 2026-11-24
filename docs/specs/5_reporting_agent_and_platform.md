# Spec · Reporting Agent + platform

**Owner:** Lama · **Tasks:** L-1 to L-6 · **Slides:** 7, 12, 16

> ALL-4 draft. Pre-filled from the proposal deck; replace every _TODO_ with what you actually built.

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
- _TODO: indexes, how incident versions are queried_

## Orchestrator
Scheduler only, not an agent: new Alert → Investigation; new IncidentUpdate → Response; new Assessment → ReportRequest. _TODO: polling interval or trigger_

## API and dashboard
- FastAPI endpoints: _TODO_
- Streamlit views: alerts, incidents, report, review screen (approve/reject is saved back to shared memory)
