"""Investigation Agent (Reem): groups IDS alerts into incidents and explains every link.

    alerts, labels = load_alert_csv(path, "fox")          # R-1 (labels never reach the agent)
    a, groups, links, incidents = investigate(alerts)     # R-2 / R-3: Rules 1-5
    messages = incident_updates(a, groups, links, incidents, "fox")   # R-5 (needs Omar's O-3)

See docs/specs/3_investigation_agent.md and docs/investigation/results.md.
"""
from .ait_ads import ATTACK_PHASES, SCENARIOS, load_alert_csv, read_table, save_table, to_alert_messages
from .correlation import CorrelationConfig, investigate
from .incident_updates import alert_message, incident_updates
from .knowledge import MAPPER_AVAILABLE, OBSERVATION_RULES

__all__ = ["ATTACK_PHASES", "SCENARIOS", "CorrelationConfig", "MAPPER_AVAILABLE", "OBSERVATION_RULES",
           "alert_message", "incident_updates", "investigate", "load_alert_csv", "read_table",
           "save_table", "to_alert_messages"]
