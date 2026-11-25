# SentinelAI O-3 framework mapper

O-3 uses the O-1 knowledge base to add ATT&CK candidates and Kill Chain stage hypotheses to an `IncidentUpdate`. The tracker requires each label to cite the evidence and the mapping rule behind it. Reem's Investigation Agent supplies the alerts for one incident and owns correlation, incident state, overall confidence, and uncertainty notes.

## Use it from the Investigation Agent

```python
from sentinelai.frameworks.mapper import map_alerts

mapping = map_alerts(incident_alerts, external_sources=network_external_sources)
incident_update.update(mapping)
```

`map_alerts` accepts complete `Alert` messages in any order. Alerts must belong to one network. Repeated copies are collapsed and conflicting copies raise an error. The optional source lists accept IP addresses scoped to that network. Use `external_sources` for sources whose external role is established by network context. Use `authorized_scan_sources` for sources authorized to scan the affected targets in this incident. When both apply, the authorization takes precedence for scan findings.

The result contains only `candidate_techniques` and `stage_hypotheses`. Each entry contains its own support rating and sorted references to the alerts, relevant detector hits, underlying flow or log evidence, and the O-1 rule, such as `rule:O1-T1595`. When several findings support the same label, the mapper cites the findings at the highest support level. Labels without sufficient evidence are omitted. Both lists are empty when every finding is unmapped.

## What the sample alerts support

| Alerts | Mapping under the documented context |
| --- | --- |
| `alert-0001`, `alert-0002` | Strong T1595 and Reconnaissance when their shared source is explicitly identified as external. Distinct destinations and disjoint flow references provide corroboration. A single scan from that external source is weak. |
| `alert-0009` | Weak T1595 when monitoring authorization is uncertain. No Reconnaissance hypothesis without external source context. An explicitly authorized scan is omitted. |
| `alert-0003` through `alert-0006` | Generic HTTP flow anomalies leave exploitation, web shell use, interpreter use, and C2 unmapped unless there is relevant reviewed evidence. |
| `alert-0007`, `alert-0008` | Both DNS detector rules on DNS traffic give a weak T1048 candidate. Data theft as an objective requires additional evidence. |
| `alert-0010`, `alert-0011` | Empty mapping for the standalone large download and internal transfer. |

For the scan demo, supply `external_sources={"203.0.113.66"}`. This address is reserved for documentation and plays the role of an outside source in the synthetic network. The project’s earlier fixture labels illustrate the message shape. Some are stronger than the underlying flow data supports under the O-1 evidence guidance.

From the repository root, run this in Python to compare both cases:

```python
import json
from pathlib import Path

from sentinelai.frameworks.mapper import map_alerts

alerts = json.loads(Path("fixtures/alerts.json").read_text(encoding="utf-8"))
by_id = {alert["message_id"]: alert for alert in alerts}
scan = [by_id["alert-0001"], by_id["alert-0002"]]
monitoring_scan = [by_id["alert-0009"]]
print(json.dumps(map_alerts(scan, external_sources={"203.0.113.66"}), indent=2))
print(json.dumps(map_alerts(monitoring_scan), indent=2))
```

## Supply reviewed evidence

Pass `EvidenceObservation(kind, alert_id, evidence_ref)` instances in `observations`. The caller derives each observation from reviewed telemetry, ties it to the cited alert, and provides a resolvable `raw_log:...` reference. The mapper checks these fields and uses the supplied findings. Source authentication and log retrieval belong to the caller.

| Technique | Weak observation | Strong observation | Separate stage observation |
| --- | --- | --- | --- |
| T1190 | `public_app_exploit_suspected` | `public_app_exploit_verified` | `exploitation_stage` |
| T1505.003 | `web_shell_suspected` | `web_shell_verified` | `web_shell_installation` |
| T1059 | `interpreter_suspected` | `interpreter_verified` | `remote_tasking` |
| T1048 | `alternative_exfiltration_suspected` | `alternative_exfiltration_verified` | `data_theft_objective` |
| T1595 | `active_scanning_suspected` | `active_scanning_verified` | `target_discovery` |
| T1548.003 | `sudo_abuse_suspected` | `sudo_abuse_verified` | None. The Cyber Kill Chain has no privilege-escalation stage, so a sudo stage observation is rejected. |

The T1595 and T1548.003 rows were added on 24 November for IDS alerts from the AIT Alert Data Set, which carry no detector rule hits. Alerts without `src_ip` are accepted. These are IDS alerts that only know the reporting host, `host_ip`, and the detector-rule scan route skips them.

Scan observations follow the same source rules as detector-rule scans:

- A source in `authorized_scan_sources` gets no T1595 finding.
- A known source that is not in `external_sources` gets at most weak T1595 and no Reconnaissance hypothesis.
- An alert without `src_ip` keeps the supplied findings, because the mapper cannot check its source.

When the mapper loads O-1, it checks that every stage listed for a technique has a stage observation in the table above. To give sudo a stage, add the stage to O-1 and a stage observation kind for T1548.003 to the mapper.

Use a suspected observation when the log supports the corresponding weak criterion in `technique_stage_mapping.json`. Use a verified observation only when reviewed evidence meets its strong criterion, including corroboration and consideration of benign explanations. Supply stage evidence on the same alert with a separate log reference that meets the stage criterion. Its rating is capped by the technique rating on that alert. The mapper treats these as incident hypotheses, including when the underlying activity was observed directly.

A second, different alert type in the same incident that supports the same technique also counts as stage evidence. Supply it as the stage observation on the alert, citing the other alert's log. The Investigation Agent uses this rule. It supports at most a weak stage, so supply it only with a suspected technique observation. A strong stage needs reviewed evidence specific to the stage. The `stage_support_policy` in `technique_stage_mapping.json` states the same rule.

## Run the checks

From the repository root:

```powershell
python -m unittest discover -s tests -p "test_o*.py" -v
python scripts/check_contracts.py
```

The mapper can be used directly from the repo, with no new library dependency. The contract check uses the project's existing dependencies. The IDS alert tests need the `host_ip` field from the amended message contract.
