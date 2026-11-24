# Spec · Response Agent (rule-based policy)

**Owner:** Omar · **Tasks:** O-4 to O-6 · **Slides:** 12, 14

> ALL-4 draft. Pre-filled from the proposal deck; replace every _TODO_ with what you actually built.

| | |
|---|---|
| **Goal** | Decide how serious an incident is and advise safely |
| **Observes** | Latest `IncidentUpdate`: evidence strength, stages reached, number of linked stages, which hosts are involved |
| **State** | Policy table, asset importance list, last assessed version per incident |
| **Decision policy** | Severity from the policy table below; recommendations from the catalogue, each with a reason |
| **Actions** | Writes an `Assessment` with severity, reasons and advice-only recommendations |
| **Reads** | `IncidentUpdate` |
| **Writes** | `Assessment` |
| **Autonomy limit** | Never blocks, isolates or deletes anything. `requires_human_approval` is always true. |

## Severity policy (draft)
| Rule ID | Condition | Severity |
|---|---|---|
| `SEV-MULTISTAGE-OBJECTIVE` | ≥ 3 linked stages **and** actions_on_objectives with strong support | High |
| _TODO_ | ≥ 2 linked stages, strongest support weak | Medium |
| `SEV-SINGLE-WEAK` | 1 alert, weak support | Low |
| `SEV-SINGLE-UNMAPPED` | 1 alert, no technique mapped | Low |
| _TODO_ | Critical asset + exploitation strong | _TODO_ |

## Asset importance
| Host / IP | Importance |
|---|---|
| WordPress server (public) | high |
| _TODO_ | |

## Tests
Same evidence → same severity (O-6). Every recommendation needs human approval.
