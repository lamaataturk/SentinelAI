# Spec · Investigation Agent (knowledge-based)

**Owner:** Reem (correlation) with Omar (framework mapper) · **Tasks:** R-1 to R-6, O-1, O-3, O-7 · **Slides:** 12–15

> ALL-4 draft. Pre-filled from the proposal deck; replace every _TODO_ with what you actually built.

| | |
|---|---|
| **Goal** | Group related alerts into one possible incident and say what it may mean |
| **Observes** | Alerts: IPs, hosts, users, times, rule hits; ATT&CK subset and Kill Chain table |
| **State** | Open incidents with their alerts, entities, link reasons, versions |
| **Decision policy** | Link a new alert to an open incident only if (1) it shares an IP, host or user, (2) the gap is ≤ _TODO_ minutes, and (3) the order makes sense. Otherwise start a new incident. Being close in time alone is never enough. |
| **Actions** | Writes a new `IncidentUpdate` version with candidate techniques, stage guesses and uncertainty |
| **Reads** | `Alert` |
| **Writes** | `IncidentUpdate` |
| **Autonomy limit** | Says "possible", never "confirmed"; takes no action |

## Link strength
- **strong**: _TODO, e.g. shared IP and gap well inside the limit_
- **weak**: _TODO, e.g. new destination or gap near the limit_

## Framework mapping (Omar's mapper)
- Evidence → candidate technique, support strong / weak / unmapped
- Technique → possible Kill Chain stages (not one-to-one)
- ATT&CK subset: T1595, T1190, T1505.003, T1059, T1048, _TODO_

## Evaluation
- Grouping against AIT-ADS `labels.csv` phases. Tune the gap on networks _TODO_ and report on _TODO_.
- Mapping agreement on the demo scenarios (small set, not a general accuracy claim).

## Tests
_TODO: same host close → linked; different hosts close → separate; gap too long → separate; wrong order → weak; duplicates merged_
