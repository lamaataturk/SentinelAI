# ALL-3 · Integration week checklist (week 5)

Swap fixtures for the real parts one link at a time, and run the checker after each swap:

```
python scripts/check_contracts.py --features <file> --messages <files>   # or --sqlite shared.db
pytest
```

| # | Swap | Who | Check | ✓ |
|---|---|---|---|---|
| 1 | Real feature file replaces `features_sample.csv` | Habiba → Malak | `check_contracts.py --features` passes; IPs present | ☐ |
| 2 | Real model + rules write Alerts | Malak → Reem | Alerts pass; every `flow:` ref resolves | ☐ |
| 3 | Real Investigation Agent writes IncidentUpdates | Reem + Omar → Omar | Every `alert:` ref resolves; techniques have evidence | ☐ |
| 4 | Real Response Agent writes Assessments | Omar → Lama | `incident_version` exists; all advice needs human approval | ☐ |
| 5 | Real Reporting Agent + dashboard | Lama | Traceability test (L-5) passes on real data | ☐ |
| 6 | End-to-end tests (H-7) | Habiba | Demo scenarios give the expected incidents and severity | ☐ |
| 7 | Run on one full AIT test network | Everyone | No crash; report for the main incident looks sensible | ☐ |

## When something breaks
1. Find the first message that fails `check_contracts.py`. The writer of that message type fixes it.
2. If the contract itself has to change, update `messages.py`/`features.py`, the docs and the fixtures in one pull request, and tell everyone.
3. Write the bug and the fix in the log below. Problems found here are good material for the report.

## Problems log
| Date | Problem | Fixed by | How |
|---|---|---|---|
| | | | |
