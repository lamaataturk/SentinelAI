# SentinelAI O-7 mapping agreement

The tracker's Tasks row 32 asks for a mapping agreement check on Reem's demo scenarios, reported on the small set and not as general accuracy. O-7 runs both scenarios through the Investigation Agent and the O-3 mapper. It then compares the ATT&CK techniques and Kill Chain stages on each incident with the labels the scenario author wrote for every alert (`gt_technique` and `gt_stage` in `sentinelai/investigation/scenarios.py`). The demo network context is used: the attacker is the only outside source.

## Run it

From the repository root:

```bash
python scripts/mapping_agreement.py
python -m unittest discover -s tests -p test_o7_mapping_agreement.py -v
```

The script prints the full report, including a table of attack steps that shows which alerts each technique label cites. `--out report.md` also writes it to a file.

## Results

| Scenario | Techniques agree | Missed | Extra | Stages agree | Missed | Extra |
|---|---|---|---|---|---|---|
| Scenario 1 (web attack) | 5 | 1 | 0 | 2 | 3 | 0 |
| Scenario 2 (innocent but noisy) | 0 | 0 | 1 | 0 | 0 | 0 |

In scenario 1, the whole attack (GT-1 and GT-2) forms one incident, and the mistyped mail password stays alone with no labels. In scenario 2, the monitoring scans are filtered as routine, and the backup, update and antivirus incidents get no stage.

| Scenario 1 attack incident | Labels |
|---|---|
| Techniques that agree | T1595, T1190, T1059, T1548.003, T1048 (all weak) |
| Technique missed | T1505.003 web shell |
| Stages that agree | Reconnaissance, Actions on Objectives (both weak) |
| Stages missed | Exploitation, Installation, Command and Control |

## Why the labels disagree

- **Web shell (T1505.003) is missed.** No AIT alert type specifically shows a web shell. The scenario's "Suspicious URL access" alert is not in the Investigation Agent's observation table, so the mapper gets no evidence for it. A label would need reviewed host evidence, which is O-1's criterion for this technique.
- **Three stages are missed.** Under the agreed stage-evidence rule, a stage needs a second, independent alert type that supports the same technique, or reviewed stage evidence. Reconnaissance has two scan alert types and Actions on Objectives has two DNS anomaly types. Exploitation (T1190) and Command and Control (T1059) each have only one alert type in the scenario, and the web shell is not mapped, so Installation has no technique to build on.
- **Every agreeing label is weak.** IDS alert names alone support only weak labels. Strong labels need reviewed evidence.
- **Not every attack alert is cited.** T1595 cites 25 of the 275 scan alerts: the Nmap and repeated-400 alerts. Single 400 errors, new request methods and forbidden-file attempts have common benign causes and are not in the observation table. Privilege escalation cites 3 of 4 alerts, because a PAM session opening is not sudo evidence.
- **The admin's sudo gets weak T1548.003 in scenario 2.** The scenario author expected this. The incident has no stage and stays Low.

## Severity

The attack incident is rated Medium, while the scenario expects High. This follows the O-4 policy: High requires strong Actions on Objectives evidence, and the demo has only weak IDS evidence. Severity is not part of the mapping agreement. The team still needs to decide whether to present Medium with this explanation or add reviewed evidence to the demo.

## Limits

These are two small synthetic scenarios. The same author wrote the ground truth and the Investigation Agent's observation table, so the comparison is not independent. The AIT Alert Data Set labels alerts with attack phases, not ATT&CK techniques, so repeating this check on the real data would first need a reviewed mapping from phases to techniques. Read the numbers as a description of these scenarios, not as accuracy.
