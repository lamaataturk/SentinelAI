# ALL-2 · Fixtures

Hand-made, invented data that tells one small story. Build and test your part against these until the real upstream part exists. Regenerate with `python scripts/make_fixtures.py`, and don't edit the files by hand.

**Attack:** `203.0.113.66` (outside) scans the network, attacks the WordPress server `10.0.1.20`, uploads a web shell and runs commands. The web server then leaks data over DNS through `10.0.1.53`.
**Normal but noisy:** the monitoring server `10.0.1.5` runs its routine scan, an employee (`10.0.2.15`) downloads updates, and the backup host (`10.0.1.30`) copies files to the file share (`10.0.1.40`).

| File | What's in it | Who reads it while waiting |
|---|---|---|
| `features_sample.csv` | 32 flows (20 normal background, 9 attack, 3 noisy-but-normal), all contract columns, IPs included | Malak (M-1 harness, M-3 first training run) |
| `alerts.json` | 11 Alerts: 8 attack, 3 false alarms | Reem (R-2), Omar (O-3 mapper) |
| `incident_updates.json` | 5 updates: `inc-0001` v1 and v2 (attack), plus 3 single-alert incidents | Omar (O-4 severity), Lama (L-4 report) |
| `assessments.json` | 4 Assessments (1 High, 3 Low) with advice-only recommendations | Lama (L-4, L-6 dashboard) |
| `report_requests.json` | 2 ReportRequests | Lama (L-4) |

Things worth testing against:
- **`inc-0001` has two versions.** Agents must use the latest one, and the Assessment says which version it judged.
- **The link from alert 6 to alert 7 is weak** (a 15-minute gap and a new destination). The report should show that uncertainty.
- **`inc-0002` is a scan that is most likely innocent.** It must not end up High.
- **IPs are in every alert and incident.** The validator rejects an alert without them.

Each owner should replace their own file with real output from their agent as soon as it runs, then rerun `python scripts/check_contracts.py`.
