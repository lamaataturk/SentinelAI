"""Link between the Investigation Agent and Omar's O-1 / O-3 (sentinelai/frameworks).

* OBSERVATION_RULES: which IDS alert types count as evidence for O-3. Chosen by what
  each alert name MEANS, never by which alerts fire during attacks. Only "suspected"
  (= weak) kinds: an IDS alert name alone never makes a technique strong.
* signature_stage(): the Kill Chain position (1-7) an alert type may point to, read
  from O-1's technique_stage_mapping.json. Used by Rules 4 and 5.
* observations_for(): the EvidenceObservations handed to Omar's map_alerts().

Works without Omar's files too (before his O-3 is merged): then no alert type has a
stage, Rules 4 and 5 change nothing, and MAPPER_AVAILABLE is False.
"""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from sentinelai.contracts.messages import KILL_CHAIN_STAGES

_O1_MAPPING = Path(__file__).resolve().parents[1] / "frameworks" / "technique_stage_mapping.json"

try:  # Omar's O-3 mapper
    from sentinelai.frameworks.mapper import EvidenceObservation, map_alerts
    MAPPER_AVAILABLE = True
except ImportError:  # not merged yet
    EvidenceObservation = map_alerts = None
    MAPPER_AVAILABLE = False

O1_RULES = json.loads(_O1_MAPPING.read_text(encoding="utf-8"))["rules"] if _O1_MAPPING.exists() else []

OBSERVATION_RULES = {
    # T1595 Active Scanning
    "Suricata: Alert - ET SCAN Possible Nmap User-Agent Observed": "active_scanning_suspected",
    "Suricata: Alert - ET SCAN Behavioral Unusual Port 445 traffic Potential Scan or Infection": "active_scanning_suspected",
    "Wazuh: sshd: insecure connection attempt (scan).": "active_scanning_suspected",
    "Wazuh: Multiple web server 400 error codes from same source ip.": "active_scanning_suspected",
    # T1190 Exploit Public-Facing Application
    "Wazuh: Common web attack.": "public_app_exploit_suspected",
    # T1059 Command and Scripting Interpreter
    "AMiner: New user_cmd parameter combination in Audit logs.": "interpreter_suspected",
    # T1548.003 Sudo and Sudo Caching
    "Wazuh: Successful sudo to ROOT executed.": "sudo_abuse_suspected",
    "Wazuh: First time user executed sudo.": "sudo_abuse_suspected",
    # T1048 Exfiltration Over Alternative Protocol (data hidden in DNS names)
    "AMiner: High entropy in DNS domain.": "alternative_exfiltration_suspected",
    "AMiner: New characters in DNS domain.": "alternative_exfiltration_suspected",
}
# Not mapped on purpose: no AIT alert type specifically shows a web shell (T1505.003).
KIND_TECHNIQUE = {"active_scanning_suspected": "T1595", "public_app_exploit_suspected": "T1190",
                  "interpreter_suspected": "T1059", "sudo_abuse_suspected": "T1548.003",
                  "alternative_exfiltration_suspected": "T1048"}
STAGE_KIND = {"T1595": "target_discovery", "T1190": "exploitation_stage",
              "T1059": "remote_tasking", "T1048": "data_theft_objective"}  # T1548.003: no Kill Chain stage
STAGE_NO = {stage: i for i, stage in enumerate(KILL_CHAIN_STAGES, start=1)}
POSSIBLE_STAGE = {r["technique_id"]: [h["stage"] for h in r["stage_hypotheses"]] for r in O1_RULES}


def signature_stage(signature) -> int | None:
    """Kill Chain position (1-7) a signature may point to, from O-1; None if unknown."""
    stages = POSSIBLE_STAGE.get(KIND_TECHNIQUE.get(OBSERVATION_RULES.get(signature)), [])
    return min(STAGE_NO[s] for s in stages) if stages else None


def observations_for(sub: pd.DataFrame) -> list:
    """Technique evidence from the table; stage evidence only when ANOTHER alert type in the
    same incident supports the same technique (its log is the independent evidence)."""
    obs = []
    rows = sub[sub["signature"].isin(list(OBSERVATION_RULES))].to_dict("records")
    first_by_sig = {}
    for r in rows:
        first_by_sig.setdefault(r["signature"], r)
    for r in rows:
        kind = OBSERVATION_RULES[r["signature"]]
        obs.append(EvidenceObservation(kind, r["alert_id"], f"raw_log:{r['network']}/{r['alert_id']}"))
        tech = KIND_TECHNIQUE[kind]
        other = next((o for s, o in first_by_sig.items()
                      if s != r["signature"] and KIND_TECHNIQUE[OBSERVATION_RULES[s]] == tech), None)
        if other is not None and tech in STAGE_KIND:
            obs.append(EvidenceObservation(STAGE_KIND[tech], r["alert_id"],
                                           f"raw_log:{other['network']}/{other['alert_id']}"))
    return obs
