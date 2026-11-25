# Spec · Investigation Agent (knowledge-based)

**Owner:** Reem (correlation) with Omar (framework mapper) · **Tasks:** R-1 to R-6, O-1, O-3, O-7 · **Slides:** 12–15

> Built and evaluated (24 Nov). Code: `sentinelai/investigation/`. Results and decisions: `docs/investigation/results.md`.

| | |
|---|---|
| **Goal** | Group related alerts into one possible incident and say what it may mean |
| **Observes** | Alerts: IPs, hosts, users, times, rule hits; ATT&CK subset and Kill Chain table |
| **State** | Open incidents with their alerts, entities, link reasons, versions |
| **Decision policy** | Link a new alert to an open incident only if (1) it shares an IP, host or user, (2) the gap is ≤ 45 minutes, and (3) the order makes sense. Otherwise start a new incident. Being close in time alone is never enough. |
| **Actions** | Writes a new `IncidentUpdate` version with candidate techniques, stage guesses and uncertainty |
| **Reads** | `Alert` |
| **Writes** | `IncidentUpdate` |
| **Autonomy limit** | Says "possible", never "confirmed"; takes no action |

## Rules (in order)
1. **Merge bursts:** same alert type on the same host, < 60 s apart → one group (capped at 10 min). Groups keep every IP.
2. **Routine filter:** an alert type seen in ≥ 6 of the 10-minute slots of the first 24 h is routine, unless > 3× its busiest normal slot (a spike). Routine groups never start or extend incidents.
3. **Link on shared evidence:** shared host or IP, gap ≤ 45 min.
4. **Order check:** a step whose Kill Chain stage comes before a stage the incident already reached is still linked, but weak and marked `out_of_order`.
5. **Long-gap joins:** shared host or IP, gap > 45 min and ≤ 24 h, and the later incident's earliest stage comes strictly after the earlier one's latest stage. Always weak, marked `long_gap`.

## Link strength
- **strong**: shared host or IP and a gap of 5 minutes or less, in Kill Chain order (or stage unknown)
- **weak**: a gap over 5 minutes, an out-of-order step (Rule 4), or a long-gap join (Rule 5)

Incident confidence: **low** = one alert group (or routine), **medium** = has a weak link, **high** = only strong links.

## Framework mapping (Omar's mapper)
- Evidence → candidate technique, support strong / weak / unmapped
- Technique → possible Kill Chain stages (not one-to-one)
- ATT&CK subset: T1595, T1190, T1505.003, T1059, T1048, T1548.003 (added for privilege escalation; Omar to review)
- The agent hands the mapper "suspected" (weak) observations from a fixed table of IDS alert names (`sentinelai/investigation/knowledge.py`), chosen by meaning, never by which alerts fire during attacks. A stage observation is given only when a second, different alert type in the same incident supports the same technique.

## Evaluation
- Grouping against the AIT-ADS answers (exact attack labels inside attack-phase windows). Tuned on russellmitchell, santos, shaw; final test once on fox, harrison, wardbeck, wheeler, wilson.
- Final test: 100% of attack alerts kept, 1.4% of normal-time alerts kept, 99.9% of the attack in one incident, purity 0.998, 0 contract problems.
- Mapping agreement on the demo scenarios (small set, not a general accuracy claim): scenario 1 and 2 meet all their written predictions.

## Tests
`tests/test_r1_loader.py`, `test_r3_correlation.py`, `test_r4_scenarios.py`, `test_r5_incident_updates.py`: loader keeps answers out; repeats within 60 s merge, longer gaps split, endless streams capped; routine type filtered, spike kept; same host close → linked strong; different hosts close → separate; gap > 45 min → separate; 10-min gap → weak; shared attacker IP links two hosts; wrong order → kept but weak; long-gap join only to a later stage with a shared host/IP within 24 h; messages follow the contract; both demo scenarios.
