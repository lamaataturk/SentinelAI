# ALL-1 (b) · Message contract

**Code:** `sentinelai/contracts/messages.py` · **Examples:** `fixtures/*.json` · **Store:** Lama's SQLite shared memory (L-2)

Agents never call each other. Each one writes its own message type to shared memory and reads the types it needs.

```
Detection Agent (Malak)       --Alert-------------> shared memory
Investigation Agent (Reem)    --IncidentUpdate----> shared memory
Response Agent (Omar)         --Assessment--------> shared memory
Orchestrator / analyst (Lama) --ReportRequest-----> shared memory --> Reporting Agent (Lama)
```

## Envelope (every message)

| Field | Type | Rule |
|---|---|---|
| `message_id` | str | Prefix by type: `alert-`, `incupd-`, `assess-`, `repreq-` |
| `message_type` | str | `Alert`, `IncidentUpdate`, `Assessment` or `ReportRequest` |
| `schema_version` | str | `"1.0"` |
| `created_at` | str | ISO 8601 UTC ending in `Z` |
| `producer` | str | Only the allowed writer for that type (see `PRODUCERS`) |
| `evidence_refs` | list[str] | `kind:id`, kind ∈ flow, alert, incident, assessment, rule, raw_log, technique |

## Alert (Detection Agent; `ait_ids_loader` for AIT-ADS alerts)

`network`, `detector` (rf / rules / hybrid / ids), `first_seen`, `last_seen`, `host_ip`, **`src_ip`, `dst_ip`**, `src_port`, `dst_port`, `protocol`, `rf_score` (0–1 or null), `rule_hits` (list), `ids_source` (wazuh / suricata / aminer, for ids only), `signature`, `user`, `hostname`, `summary`.

IP rule (v1.0, amended 23 Nov): Detection Agent alerts always need `src_ip` and `dst_ip`. IDS alerts from AIT-ADS keep every IP their source record has; the authors' CSV export has only the IP of the host that raised the alert, so for those `host_ip` is required and `src_ip`/`dst_ip` may be null. No IP present in the input is ever dropped.

Other rules: rf and hybrid alerts need a score; rules and hybrid alerts need a rule hit; every alert cites at least one flow, raw log or rule.

## IncidentUpdate (Investigation Agent)

`incident_id` (`inc-…`), `version` (goes up with each update), `status`, `network`, `alert_ids`, `entities` {ips, hosts, users}, `start_time`, `end_time`, `link_reasons` [{alert_id, linked_to, shared_entity, gap_seconds, strength}], `candidate_techniques` [{technique_id, name, support, evidence_refs}], `stage_hypotheses` [{stage, support, evidence_refs}], `confidence`, `uncertainty_notes`.

Rules: support is strong / weak / unmapped. Any technique that is not unmapped needs evidence. Stages are the seven Kill Chain stages in `KILL_CHAIN_STAGES`.

## Assessment (Response Agent)

`incident_id`, `incident_version` (the version it judged), `severity` (Low / Medium / High / Critical), `policy_rule_id`, `severity_reasons`, `recommendations` [{action, reason, technique_id, requires_human_approval}], `review_status` (pending / approved / rejected).

Rule: `requires_human_approval` is always `true`. The system only advises.

## ReportRequest (orchestrator or analyst)

`incident_id`, `assessment_id`, `requested_by_reason`, `format` (markdown / html).

## Checking your output

```
python scripts/check_contracts.py --messages my_output.json
```

It prints every problem, including references that point to messages that don't exist.
