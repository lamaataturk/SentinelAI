# SentinelAI

A hybrid Random Forest + four-agent prototype for cyber threat detection and explainable incident analysis (Intelligent Agents course project).

Team: Reem Abubakr · Habiba Hashem · Omar Akram · Lama Hassan · Malak Elaidi

## Start here

```
pip install -r requirements.txt
python scripts/make_fixtures.py      # rebuild the example data
python scripts/check_contracts.py    # check data and messages against the contracts
pytest                               # 14 contract tests
```

## What's in the repo so far (shared tasks ALL-1 to ALL-5)

| Task | Where |
|---|---|
| ALL-1 Contracts | `sentinelai/contracts/features.py`, `sentinelai/contracts/messages.py`, `docs/contracts/` |
| ALL-2 Fixtures | `fixtures/` (see `fixtures/README.md`), built by `scripts/make_fixtures.py` |
| ALL-3 Integration | `scripts/check_contracts.py`, `docs/integration_checklist.md` |
| ALL-4 Specs | `docs/specs/` (one draft per person, `_TODO_` marks what's left) |
| ALL-5 Demo | `docs/demo_runbook.md` |

## Ground rules
- **IP addresses are never dropped** from features, alerts or incidents.
- Agents talk only through shared memory, using the four message types.
- No agent reads `label`/`label_raw` at runtime.
- All recommendations are advice only (`requires_human_approval = true`).
- A contract changes only in a pull request that updates code, docs and fixtures together and is seen by all five.

## Suggested folders for each person's work
```
sentinelai/data/          Habiba  (features, split)
sentinelai/detection/     Malak   (training, rules, Detection Agent)
sentinelai/investigation/ Reem    (alert loading, correlation)
sentinelai/frameworks/    Omar    (ATT&CK subset, Kill Chain table, mapper)
sentinelai/response/      Omar    (severity policy, recommendations)
sentinelai/reporting/     Lama    (Reporting Agent)
sentinelai/platform/      Lama    (shared memory, orchestrator, API, dashboard)
```
