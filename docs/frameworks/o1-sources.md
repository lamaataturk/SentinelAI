# SentinelAI O-1 knowledge base

The tracker’s Tasks row 26 calls for a sourced ATT&CK subset and a hand-written Kill Chain table in the repository. The Investigation Agent spec identifies T1059 for the tracker’s “command execution” entry and lists the other four IDs. Tasks row 28 requires O-3 to trace every label to supporting evidence and its mapping rule.

## Sources verified 24 November 2026

The Enterprise ATT&CK names, tactics, IDs, and record versions follow MITRE’s technique pages. The descriptions are paraphrases. For T1505.003 the display name includes its parent, matching the repository fixture.

| Entry | MITRE record version | Primary source |
| --- | --- | --- |
| T1595 | 1.0 | [Active Scanning](https://attack.mitre.org/techniques/T1595/) |
| T1190 | 2.8 | [Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) |
| T1505.003 | 1.5 | [Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003/) |
| T1059 | 2.7 | [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/) |
| T1048 | 1.6 | [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/) |
| T1548.003 | 2.0 | [Abuse Elevation Control Mechanism: Sudo and Sudo Caching](https://attack.mitre.org/techniques/T1548/003/) (added 24 Nov; tactic Privilege Escalation) |

Reem's AIT integration added T1548.003 as the sixth entry. Its stage hypotheses are empty because the Cyber Kill Chain has no dedicated Privilege Escalation stage. Ordinary administrative sudo use is a plausible explanation. Strong support requires corroborating evidence of unauthorized elevation.

The seven stage definitions and ordering follow §3.2 of Eric M. Hutchins, Michael J. Cloppert, and Rohan M. Amin’s Lockheed Martin white paper. The descriptions are paraphrases. Stage identifiers follow SentinelAI’s message contract. [Intelligence-Driven Computer Network Defense](https://www.lockheedmartin.com/content/dam/lockheed-martin/rms/documents/cyber/LM-White-Paper-Intel-Driven-Defense.pdf?Offer=ab_ss_reeng_plt_var1)

## O-3 handoff

Read the three UTF-8 JSON files from `sentinelai/frameworks/` with the standard JSON parser. Each file declares its data format version. The mapping file also names the target message schema version.

| File | Lookup key | Contents |
| --- | --- | --- |
| `attack_techniques.json` | `techniques[].technique_id` | ATT&CK catalog and provenance |
| `kill_chain_stages.json` | `stages[].stage` | Ordered stage catalog |
| `technique_stage_mapping.json` | `rules[].mapping_rule_id` | SentinelAI evidence guidance and conditional stage hypotheses |

The mapping file is project-authored guidance. Its evidence conditions are written for O-3 to implement against available telemetry. Look up candidate names by `technique_id` and keep stable mapping rule IDs in the mapper’s trace. When that trace can resolve a mapping rule ID, cite it as `rule:O1-T1595` in the existing `evidence_refs` array alongside the underlying `alert:...`, `flow:...`, or `raw_log:...` references. Cite a detector rule only when it actually fired. An empty `detection_rule_ids` array means the supplied fixtures have no dedicated detector rule for that candidate.

`IncidentUpdate.candidate_techniques` entries use `technique_id`, `name`, `support`, and `evidence_refs`. Entries in `stage_hypotheses` use `stage`, `support`, and `evidence_refs`. Assess stage support separately, using corroboration relevant to that stage. A single incident can have multiple hypotheses. Missing stages stay absent, and the two catalogs can represent stages for which the current fixture evidence provides no hypothesis.

The fixtures illustrate the integration format. For example, the monitoring scan (alert-0009) has an ordinary operational explanation, and the download and backup (alert-0010 and alert-0011) can remain unmapped. The demonstration fixture assigns strong T1048 support to DNS anomalies and includes a weak C2 hypothesis from HTTP requests. For O-3, those labels require the additional evidence described in the mapping file. Correlation strength, repeated alerts, and a high RF score alone do not establish a technique or stage.

## Verification

From the repository root, run `python -m unittest discover -s tests -p test_o1_knowledge_base.py -v` for the O-1 checks. The test suite reads the checked-in synthetic fixtures and exercises the existing message and bundle validators. Use `python scripts/check_contracts.py` for the repository’s full fixture check.
