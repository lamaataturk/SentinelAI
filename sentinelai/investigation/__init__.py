"""Investigation Agent (Reem): groups IDS alerts into incidents and explains every link.

    alerts, labels = load_alert_csv(path, "fox")          # R-1 (labels never reach the agent)

See docs/specs/3_investigation_agent.md.
"""
from .ait_ads import ATTACK_PHASES, SCENARIOS, load_alert_csv, read_table, save_table, to_alert_messages

__all__ = ["ATTACK_PHASES", "SCENARIOS", "load_alert_csv", "read_table", "save_table", "to_alert_messages"]
