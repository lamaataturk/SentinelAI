# SentinelAI

A hybrid Random Forest + four-agent prototype for cyber threat detection and explainable incident analysis (Intelligent Agents course project).

Team: Reem Abubakr · Habiba Hashem · Omar Akram · Lama Hassan · Malak Elaidi

SentinelAI is an **academic, defensive decision-support prototype**. It suggests; a human decides. It never blocks traffic, changes a firewall or carries out any recommendation by itself.

---

## Quick start (demo with fixtures)

```
pip install -r requirements.txt
python scripts/check_platform_env.py     # confirms packages + modules (prints READY)
python scripts/init_demo.py              # builds the demo database from fixtures/ (safe to repeat)
python scripts/run_platform.py           # starts API + dashboard; Ctrl+C stops both
```

| | Address |
|---|---|
| Dashboard | http://127.0.0.1:8501 |
| API | http://127.0.0.1:8000 |
| API docs (interactive) | http://127.0.0.1:8000/docs |

Both servers bind to `127.0.0.1` only. To start them separately (two terminals):

```
python -m sentinelai.platform.api
python -m streamlit run sentinelai/dashboard/app.py
```

Run the tests:

```
python -m pytest
```

> **Demo data is synthetic.** The demo database is built from `fixtures/*.json`. Every page of the dashboard shows a "DEMONSTRATION DATA" banner while this data is loaded. Fixture Random Forest scores are hand-written values, not measured model output.

---

## Shared project commands (ALL-1 to ALL-5, data pipeline)

```
python scripts/make_fixtures.py      # rebuild the example data
python scripts/check_contracts.py    # check data and messages against the contracts
python scripts/build_features.py --data-dir data/raw/ait --networks fox   # H-5: AIT zips -> data/processed/
```

| Task | Where |
|---|---|
| ALL-1 Contracts | `sentinelai/contracts/features.py`, `sentinelai/contracts/messages.py`, `docs/contracts/` |
| ALL-2 Fixtures | `fixtures/` (see `fixtures/README.md`), built by `scripts/make_fixtures.py` |
| ALL-3 Integration | `scripts/check_contracts.py`, `docs/integration_checklist.md` |
| ALL-4 Specs | `docs/specs/` (one per person) |
| ALL-5 Demo | `docs/demo_runbook.md` |
| Data pipeline (Habiba) | `sentinelai/data/`, `scripts/build_features.py`, `docs/data/` |

---

## Architecture

```
 Detection Agent ──Alert──────────┐
 Investigation Agent ──IncidentUpdate──┐      SQLite shared memory (one file)
 Response Agent ──Assessment──────────┼──►  ┌─────────────────────────────┐
 Orchestrator/analyst ──ReportRequest─┘      │ messages        (agents, L-2)│
                                             │ human_reviews   (L-6)        │
 Reporting Agent ◄── ReportRequest           │ platform_meta   (L-6)        │
   └─► reports/<request_id>.md               └──────────────┬──────────────┘
                                                            │ SharedMemory / ReviewStore
                                       FastAPI backend (sentinelai/platform/api.py)
                                                            │ HTTP (JSON)
                                       Streamlit dashboard (sentinelai/dashboard/)
```

* Agents never call each other. They exchange the four message types of `sentinelai/contracts/messages.py` through shared memory.
* The dashboard talks **only** to the API; it never opens the SQLite file.
* The API reads agent messages through `SharedMemory`, generates reports only through the existing `ReportingAgent`, validates only through the existing `EvidenceValidator`, and writes nothing to the `messages` table except analyst `ReportRequest`s.

### The four agents

| Agent | Owner | Writes | Where | Status in this repo |
|---|---|---|---|---|
| Detection | Malak | `Alert` | `sentinelai/detection/` | Not merged into `main` yet; fixtures stand in |
| Investigation | Reem | `IncidentUpdate` | `sentinelai/investigation/` | Merged (batch pipeline on AIT-ADS alerts; no `run(message, memory)` adapter yet) |
| Response | Omar | `Assessment` | `sentinelai/response/` | Merged, has `run(message, memory)` |
| Reporting | Lama | report files | `sentinelai/reporting/` | Merged (L-4, L-5) |

ATT&CK / Kill Chain knowledge base and mapper (Omar): `sentinelai/frameworks/`.

## Ground rules
- **IP addresses are never dropped** from features, alerts or incidents.
- Agents talk only through shared memory, using the four message types.
- No agent reads `label`/`label_raw` at runtime.
- All recommendations are advice only (`requires_human_approval = true`).
- A contract changes only in a pull request that updates code, docs and fixtures together and is seen by all five.

---

## Lama's tasks (L-1 to L-6)

### L-1 Repository and project setup
Repository layout, `requirements.txt`, `pytest.ini` (`pythonpath = .`, `testpaths = tests`), `.gitignore`, contract checker (`scripts/check_contracts.py`).

### L-2 SQLite shared memory: `sentinelai/platform/shared_memory.py`

| Method | Description |
|---|---|
| `SharedMemory(db_path)` | Opens/creates the database (table `messages(message_id PK, message_type, created_at, producer, body JSON)`, index on `message_type`). |
| `write(message)` | Validates against the contract and stores. Invalid messages and duplicate IDs are rejected. |
| `read(message_type=None)` | All messages, or one type, in insertion order. |
| `get(message_id)` | One message or `None`. |
| `latest_incident(incident_id)` | The `IncidentUpdate` with the highest `version`. |

Messages are never updated or deleted.

### L-3 Orchestrator: `sentinelai/platform/orchestrator.py`
A scheduler, not an agent. `run_once()` routes new messages: `Alert` → Investigation, `IncidentUpdate` → Response, `Assessment` → creates one `ReportRequest` per assessment, `ReportRequest` → Reporting. Each agent implements `run(self, message, memory)`. Processed IDs are kept in memory (a restart reprocesses; agents are written to be idempotent). An agent passed as `None` is skipped and its messages wait for a later run. If an agent fails on a message, the error is logged and listed under `errors` in the result, the other messages carry on, and the failed message is retried on the next run.

### L-4 Reporting Agent: `sentinelai/reporting/reporting_agent.py`
`ReportingAgent(output_dir, flow_ids=None).run(report_request, memory)` writes `<output_dir>/<request_id>.md`. It refuses to write a report if evidence validation fails or if the assessment does not belong to the latest incident version. Sections: overview, timeline, detection evidence (IPs, RF score, rule hits), possible ATT&CK techniques, possible Kill Chain stages, severity, recommendations (advice only), uncertainty, benign explanations, human review, evidence validation. Every statement cites the message it comes from.

### L-5 Evidence traceability: `sentinelai/reporting/traceability.py`
`EvidenceValidator().validate(memory, flow_ids=None)` runs `validate_bundle` on every stored message, then checks incident alert references, finding evidence, human-approval flags and report request consistency. Returns `{"valid", "messages_checked", "errors", "flow_references_checked"}`.

### L-6 FastAPI backend + Streamlit dashboard

| File | Purpose |
|---|---|
| `sentinelai/platform/config.py` | Settings from environment variables; separate demo and live files |
| `sentinelai/platform/metadata.py` | `platform_meta` table: where the data came from (`fixtures` / `agents`) |
| `sentinelai/platform/reviews.py` | `ReviewStore`: append-only human review log |
| `sentinelai/platform/service.py` | Read model used by the API (reuses SharedMemory, ReportingAgent, EvidenceValidator, O-1 knowledge base) |
| `sentinelai/platform/api.py` | FastAPI app (`create_app(settings)`) |
| `sentinelai/dashboard/` | Streamlit app (`app.py`), HTTP client, theme, six pages in `views/` |
| `scripts/init_demo.py` | Builds the demo database from fixtures and generates demo reports |
| `scripts/run_platform.py` | Starts API + dashboard together |
| `scripts/check_platform_env.py` | Environment check |
| `.streamlit/config.toml` | Dark theme, `127.0.0.1` binding, usage statistics off |

---

## API reference

All responses are JSON. Lists are `{"items": [...], "total": n}`. Errors are `{"detail": "..."}` (422 adds `"errors"`). Unexpected errors return `500 {"detail": "internal server error"}` without stack traces.

| Method | Path | Description |
|---|---|---|
| GET | `/api/health` | Liveness, mode, data source |
| GET | `/api/system` | Mode, data source, demo flag, message count, flow evidence, warnings |
| GET | `/api/stats` | Dashboard figures: alerts, distinct incidents, versions, severity (current assessments of latest versions), detectors, alert activity buckets, stage support, review counts, reports |
| GET | `/api/alerts` | Filters: `detector`, `network`, `ids_source`, `ip`, `rule`, `incident_id`, `min_score`, `max_score`, `has_score`, `q`, `limit`, `offset` |
| GET | `/api/alerts/{alert_id}` | One alert, its incidents and evidence status |
| GET | `/api/incidents` | Latest version of each incident with current severity and review summary |
| GET | `/api/incidents/{id}?version=` | Incident detail: uncertainty, missing alerts, assessments, benign explanations |
| GET | `/api/incidents/{id}/versions` | All versions |
| GET | `/api/incidents/{id}/alerts` | Alerts of the incident |
| GET | `/api/incidents/{id}/timeline` | Chronological events with link reasons |
| GET | `/api/incidents/{id}/frameworks` | Candidate techniques and all 7 Kill Chain stages with support and evidence status |
| GET | `/api/incidents/{id}/assessments` | Assessments of the incident (current and outdated) |
| GET | `/api/assessments?incident_id=&current_only=` | Assessments with per-recommendation review status |
| GET | `/api/assessments/{id}` | One assessment |
| GET | `/api/reviews?assessment_id=&incident_id=` | Review history (audit log) |
| GET | `/api/reviews/pending` | Recommendations of current assessments without a decision |
| POST | `/api/reviews` | Record a decision (201 new, 200 same decision already recorded, 404, 409 outdated, 422 invalid) |
| GET | `/api/reports` | Report requests and whether each report file exists |
| POST | `/api/reports` | `{"assessment_id"}`: generate with the Reporting Agent (201, 404, 409) |
| GET | `/api/reports/{request_id}` | Report metadata and Markdown content |
| GET | `/api/reports/{request_id}/download` | Markdown file download |
| GET | `/api/validation` | EvidenceValidator result + limitations |

Example review:

```
POST /api/reviews
{"assessment_id": "assess-0001", "recommendation_index": 0, "incident_version": 2,
 "decision": "approved", "comment": "Evidence in alert-0005 supports this.", "analyst": "Lama"}
```

## Dashboard pages

| Page | Shows |
|---|---|
| Overview | Status, demo indicator, metric cards, severity chart, alert activity, detection methods, Kill Chain stage hypotheses, incidents with "Investigate" links, validation status |
| Alerts | Search and filters (text, method, IP, RF score), table, alert details with evidence status and linked incidents |
| Incident Investigation | Incident and version picker, timeline, related alerts, severity justification, recommendations with review status, uncertainty, weak links, benign explanations from the O-1 knowledge base |
| ATT&CK & Kill Chain | Observation / hypothesis / confirmed legend, 7-stage Kill Chain strip, techniques grouped by strong and weak support, evidence status per reference |
| Incident Reports | Report list, Markdown viewer, download, "generate report" (Reporting Agent), current evidence validation and its limitations |
| Human Review | Recommendations of current assessments with justification, approve/reject with comment, decision history |

Unavailable values are shown as "not available" / "not recorded", never as 0. Severity colours always come with a text label.

## Human review workflow

* Stored in table `human_reviews` (same SQLite file, separate from `messages`). Agent messages are never changed.
* A recommendation is referenced as `<assessment_id>#rec-<index>`; a SHA-256 fingerprint and the action text are stored with each decision.
* Only `approved` and `rejected` are accepted.
* The analyst must send the incident version they looked at. It must equal the assessment's version, and that must be the incident's **latest** version, otherwise the API answers `409`. Decisions about older versions stay in the history and are marked "outdated".
* The log is append-only. Changing a decision adds a new row that points to the one it replaces. Sending the same decision and comment again adds nothing.
* The `analyst` field is a self-reported label. **There is no authentication.**
* Recording a decision executes nothing.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `SENTINELAI_MODE` | `demo` | `demo` or `live` |
| `SENTINELAI_DB` | demo: `data/platform/demo/sentinelai_demo.db`, live: `data/platform/live/sentinelai.db` | Shared-memory file |
| `SENTINELAI_REPORTS_DIR` | `data/platform/<mode>/reports` | Report folder |
| `SENTINELAI_FLOWS_CSV` | demo: `fixtures/features_sample.csv`, live: none | Feature CSV for `flow:` reference checks (`none` = do not check) |
| `SENTINELAI_API_URL` | `http://127.0.0.1:8000` | Where the dashboard finds the API |
| `SENTINELAI_API_HOST` / `SENTINELAI_API_PORT` | `127.0.0.1` / `8000` | API binding |
| `SENTINELAI_ALLOWED_HOSTS` | `127.0.0.1,localhost` plus the API host | Host names the API answers to. Other `Host` headers get `400`, which stops a web page from reaching the API through DNS rebinding. `*` turns the check off |

PowerShell example:

```
$env:SENTINELAI_MODE = "live"
python scripts/run_platform.py --mode live
```

`data/platform/` is git-ignored. `init_demo.py` refuses to write into a database that holds non-fixture data and refuses the live database path.

## Moving from fixtures to real agents

1. Write real agent output to the live database (`SENTINELAI_DB`, default `data/platform/live/sentinelai.db`) with `SharedMemory.write()` or through the `Orchestrator`.
2. Optionally mark the source: `from sentinelai.platform.metadata import set_meta; set_meta(db, "data_source", "agents")` (live mode assumes `agents` when unset).
3. Point `SENTINELAI_FLOWS_CSV` at the real feature file so `flow:` references are checked.
4. Start with `python scripts/run_platform.py --mode live`. No API or dashboard code changes are needed.

`tests/test_platform_integration.py` already runs the real Response Agent and Reporting Agent through the orchestrator on fixture incidents and serves the result through the API in live mode.

Still needed for full integration (outside L-6):
* Detection Agent (Malak) merged into `main`, writing `Alert`s.
* A `run(message, memory)` adapter for the Investigation Agent (it is a batch pipeline today), or a batch step that writes its `IncidentUpdate`s to the live database.
* Real feature file (Habiba) for flow reference checks.
* An end-to-end run on one AIT network (integration checklist, `docs/integration_checklist.md`).

## Known limitations

* Fixture-only demo: the full five-agent pipeline has not been run end to end on real data.
* Evidence validation covers the whole database, not one incident. Reference checks show that cited items exist; they do not show that an attack happened. Rule definitions and `raw_log:` references are not verified.
* The generated Markdown is not re-checked against every source field.
* The Reporting Agent prints the `review_status` stored in the Assessment (always `pending`, because agent messages are immutable); the current decision is in the dashboard / `/api/reviews`.
* The report uses single line breaks between header fields; the dashboard adds display-only line breaks so they render on separate lines. The file itself is unchanged.
* The orchestrator keeps processed IDs in memory only.
* No authentication or user accounts; local use only.

## Testing

`python -m pytest` runs every test:

| File | Tests | Covers |
|---|---|---|
| `test_contracts.py` | 14 | Message and feature contracts |
| `test_shared_memory.py` | 7 | L-2 |
| `test_orchestrator.py` | 10 | L-3, including skipped agents and failed messages |
| `test_reporting_agent.py` | 13 | L-4 |
| `test_traceability.py` | 7 | L-5 |
| `test_platform_api.py` | 60 | L-6 API: health, stats, filters, incidents, versions, errors, reports, path safety, validation, Host check, ATT&CK links |
| `test_platform_reviews.py` | 20 | L-6 reviews: approve, reject, persistence, history, duplicates, invalid input, outdated versions |
| `test_platform_demo.py` | 13 | L-6 demo initialisation, no duplicates, demo/live separation, configuration |
| `test_platform_integration.py` | 11 | Orchestrator + real Response/Reporting agents → API; every dashboard page via Streamlit AppTest against a running API |
| others | rest | Data pipeline, detection, investigation, frameworks and Response Agent (teammates) |

## Folders

```
sentinelai/contracts/     message + feature contracts (ALL-1)
sentinelai/data/          Habiba  (features, split)
sentinelai/detection/     Malak   (training, rules, Detection Agent)
sentinelai/investigation/ Reem    (alert loading, correlation)
sentinelai/frameworks/    Omar    (ATT&CK subset, Kill Chain table, mapper)
sentinelai/response/      Omar    (severity policy, recommendations)
sentinelai/reporting/     Lama    (Reporting Agent, evidence traceability)
sentinelai/platform/      Lama    (shared memory, orchestrator, API, reviews, config)
sentinelai/dashboard/     Lama    (Streamlit dashboard)
fixtures/                 invented example data (see fixtures/README.md)
docs/                     contracts, specs, runbooks
```
