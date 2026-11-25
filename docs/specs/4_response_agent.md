# Spec · Response Agent (rule-based policy)

**Owner:** Omar · **Tasks:** O-4 to O-6 · **Slides:** 12, 14

O-4 implements severity assessment in `sentinelai/response/response_agent.py`.

| | |
|---|---|
| **Goal** | Decide how serious an incident is and advise safely |
| **Observes** | Latest `IncidentUpdate`: evidence strength, stages reached, number of linked stages, which hosts are involved |
| **State** | Asset inventory and reviewed observations as input. Assessments already written are stored in shared memory. |
| **Decision policy** | Select the first matching severity rule below and include its rationale and evidence references. |
| **Actions** | Writes one `Assessment` for the latest incident version with review status `pending`. O-5 supplies advice. |
| **Reads** | `IncidentUpdate` |
| **Writes** | `Assessment` |
| **Autonomy limit** | Never blocks, isolates or deletes anything. `requires_human_approval` is always true. |

## Severity policy

The first applicable row decides severity.

| Rule ID | Condition | Severity |
|---|---|---|
| `SEV-CRITICAL-ASSET-EXPLOIT` | Strong Exploitation hypothesis and reviewed log evidence of successful exploitation tied to that alert and an affected critical asset | Critical |
| `SEV-MULTISTAGE-OBJECTIVE` | At least 3 linked stages, including Actions on Objectives with strong support in the same linked group | High |
| `SEV-STRONG-EVIDENCE` | At least one evidence-backed technique or stage with strong support | Medium |
| `SEV-MULTISTAGE-WEAK` | At least 2 linked stages and the strongest support is weak | Medium |
| `SEV-SINGLE-WEAK` | 1 alert with a weak technique or stage hypothesis | Low |
| `SEV-SINGLE-UNMAPPED` | 1 alert with no evidence-backed technique or stage hypothesis | Low |
| `SEV-LIMITED-EVIDENCE` | All other valid updates | Low |

A technique or stage contributes support when it cites an incident alert, a flow, or a raw log. A stage counts toward a linked group when it cites an alert in that group. Groups are the connected components of `link_reasons` among the incident's own alert IDs. At least two distinct cited alerts must support the group, and each stage counts once. Weak links can connect stages and are disclosed in the reasons. A strong stage in a separate component cannot raise the support of the linked group. Later stages are recorded as hypotheses.

## Asset importance
The default inventory covers the fixture network and sets `host:wordpress` to `high`. Supply an inventory as a mapping from network to asset keys (`host:<lowercase hostname>` or `ip:<address>`) and importance labels. Only an asset explicitly marked `critical` is eligible for the Critical rule. Its ID must be present among the incident entities.

For Critical, pass a reviewed `ExploitationConfirmation(alert_id, asset, raw_log_ref)` for the applicable incident version. The alert must already support a strong Exploitation hypothesis. The confirmation records the affected asset and a `raw_log:` reference the caller can resolve. This preserves the distinction between strong evidence of an exploit attempt and evidence of successful exploitation.

For the orchestrator adapter, pass confirmations as `exploitation_confirmations={(incident_id, version): [confirmation]}` when constructing `ResponseAgent`. An assessment records one decision per incident version, so new evidence belongs in a new incident version.

## Integration

```python
from sentinelai.response.response_agent import ResponseAgent

response_agent = ResponseAgent()
# Pass response_agent into the existing Orchestrator.
```

`ResponseAgent.run(message, memory)` is the orchestrator entry point. It uses the latest stored incident version, writes a contract-valid `Assessment`, and reuses the existing record on retries. The pure `assess_severity(incident, ...)` function returns the policy decision for use in tests or offline analysis. New assessments contain an empty recommendation list until O-5 supplies the catalogue.

The Response Agent skips old updates when a newer version is already queued. Reporting's handling of historical assessments and report requests across orchestrator restarts still depends on the platform.

## Tests
Run the O-4 integration checks from the repository root:

```bash
python -m unittest discover -s tests -p test_response_integration.py -v
python scripts/check_contracts.py
```

O-6 covers the broader severity-policy test matrix. Every recommendation requires human approval.
