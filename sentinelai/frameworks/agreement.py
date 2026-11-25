"""O-7: agreement between the framework mapping and the demo scenarios' ground truth.

Runs the two demo scenarios through the Investigation Agent and the O-3 mapper, then
compares the ATT&CK techniques and Kill Chain stages on each incident with the labels
the scenario author wrote for every alert. This is an agreement check on two small,
hand-written scenarios, not a measure of general accuracy.
"""
from __future__ import annotations

from sentinelai.contracts.messages import KILL_CHAIN_STAGES, SEVERITIES
from sentinelai.investigation.correlation import investigate
from sentinelai.investigation.incident_updates import incident_updates
from sentinelai.investigation.scenarios import (
    EXPECTED,
    EXTERNAL_SOURCES,
    build_scenario_1,
    build_scenario_2,
)
from sentinelai.response.response_agent import assess_severity

SCENARIOS = {"scenario1": build_scenario_1, "scenario2": build_scenario_2}
SCOPE_NOTE = (
    "Agreement on two small, hand-written demo scenarios. "
    "It is not a measure of general accuracy."
)


def _ordered(labels, order=None):
    if order is None:
        return sorted(labels)
    rank = {label: position for position, label in enumerate(order)}
    return sorted(labels, key=lambda label: (rank.get(label, len(rank)), label))


def compare_labels(true_labels, system_labels, order=None):
    """Split two label sets into agreements, missed true labels and extra system labels."""
    true_labels, system_labels = set(true_labels), set(system_labels)
    return {
        "agree": _ordered(true_labels & system_labels, order),
        "missed": _ordered(true_labels - system_labels, order),
        "extra": _ordered(system_labels - true_labels, order),
    }


def _labels(values):
    return {value for value in values if isinstance(value, str) and value}


def run_scenario(name):
    """Return the scenario's alerts with their ground truth, and its IncidentUpdates."""
    alerts, truth = SCENARIOS[name]()
    labelled_alerts, groups, links, incidents = investigate(alerts)
    messages = incident_updates(
        labelled_alerts, groups, links, incidents, name, external_sources=EXTERNAL_SOURCES
    )
    routine = set(incidents.loc[incidents["routine"], "incident_id"])
    labelled = labelled_alerts.merge(truth, on="alert_id")
    labelled["routine"] = labelled["incident_id"].isin(routine)
    return labelled, messages


def _expected_severity(ground_truth, ids):
    levels = [ground_truth[gt].get("expected_severity") for gt in ids if gt in ground_truth]
    levels = [level for level in levels if level in SEVERITIES]
    return max(levels, key=SEVERITIES.index) if levels else None


def _incident_result(message, rows, ground_truth):
    ids = sorted(set(rows["gt_incident"]) - {"normal"})
    techniques = {item["technique_id"]: item["support"] for item in message["candidate_techniques"]}
    stages = {item["stage"]: item["support"] for item in message["stage_hypotheses"]}
    return {
        "incident_id": message["incident_id"],
        "ground_truth": ids,
        "alerts": len(message["alert_ids"]),
        "techniques": compare_labels(_labels(rows["gt_technique"]), techniques),
        "technique_support": techniques,
        "stages": compare_labels(_labels(rows["gt_stage"]), stages, KILL_CHAIN_STAGES),
        "stage_support": stages,
        "severity": assess_severity(message).severity,
        "expected_severity": _expected_severity(ground_truth, ids),
    }


def _step_results(labelled, messages):
    """For each attack step, count the alerts its technique label cites."""
    message_for = {alert: message for message in messages for alert in message["alert_ids"]}
    attack = labelled[labelled["gt_technique"].map(lambda value: isinstance(value, str))]
    steps = []
    for (ground_truth, step, technique), rows in attack.groupby(
        ["gt_incident", "gt_step", "gt_technique"], sort=False
    ):
        cited_by_type = {}
        for alert_id, signature in zip(rows["alert_id"], rows["signature"]):
            message = message_for.get(alert_id)
            refs = set()
            if message is not None:
                refs = next((set(item["evidence_refs"]) for item in message["candidate_techniques"]
                             if item["technique_id"] == technique), set())
            cited, total = cited_by_type.get(signature, (0, 0))
            cited_by_type[signature] = (cited + (f"alert:{alert_id}" in refs), total + 1)
        stages = _labels(rows["gt_stage"])
        steps.append({
            "ground_truth": ground_truth,
            "step": step,
            "technique": technique,
            "stage": next(iter(stages)) if stages else None,
            "alerts": len(rows),
            "cited": sum(cited for cited, _ in cited_by_type.values()),
            "uncited_types": sorted(signature for signature, (cited, _) in cited_by_type.items() if not cited),
        })
    return steps


def compare_scenario(name):
    """Compare one demo scenario's incidents and attack steps with its ground truth."""
    labelled, messages = run_scenario(name)
    ground_truth = EXPECTED[name]["ground_truth"]
    incidents = [
        _incident_result(message, labelled[labelled["alert_id"].isin(message["alert_ids"])], ground_truth)
        for message in messages
    ]
    outcomes = []
    for ground_truth_id in ground_truth:
        rows = labelled[labelled["gt_incident"] == ground_truth_id]
        alert_ids = set(rows["alert_id"])
        outcomes.append({
            "ground_truth": ground_truth_id,
            "alerts": len(rows),
            "incidents": [m["incident_id"] for m in messages if alert_ids & set(m["alert_ids"])],
            "routine_alerts": int(rows["routine"].sum()),
        })
    totals = {
        kind: {key: sum(len(incident[kind][key]) for incident in incidents)
               for key in ("agree", "missed", "extra")}
        for kind in ("techniques", "stages")
    }
    return {
        "scenario": name,
        "story": EXPECTED[name].get("story", ""),
        "incidents": incidents,
        "ground_truth": outcomes,
        "steps": _step_results(labelled, messages),
        "totals": totals,
    }


def _with_support(labels, support):
    return ", ".join(f"{label} ({support[label]})" for label in labels) or "none"


def _plain(labels):
    return ", ".join(labels) or "none"


def format_report(results):
    """Render comparison results as Markdown."""
    results = list(results)
    lines = ["# O-7 mapping agreement", "", SCOPE_NOTE, "",
             "| Scenario | Techniques agree | missed | extra | Stages agree | missed | extra |",
             "|---|---|---|---|---|---|---|"]
    for result in results:
        t, s = result["totals"]["techniques"], result["totals"]["stages"]
        lines.append(f"| {result['scenario']} | {t['agree']} | {t['missed']} | {t['extra']} "
                     f"| {s['agree']} | {s['missed']} | {s['extra']} |")
    for result in results:
        lines += ["", f"## {result['scenario']}", "", result["story"], "", "### Incidents", "",
                  "| Incident | Ground truth | Alerts | Techniques agree | Missed | Extra "
                  "| Stages agree | Missed | Extra | Severity (expected) |",
                  "|---|---|---|---|---|---|---|---|---|---|"]
        for incident in result["incidents"]:
            t, s = incident["techniques"], incident["stages"]
            expected = incident["expected_severity"] or "n/a"
            lines.append(
                f"| {incident['incident_id']} | {_plain(incident['ground_truth'])} | {incident['alerts']} "
                f"| {_with_support(t['agree'], incident['technique_support'])} | {_plain(t['missed'])} "
                f"| {_with_support(t['extra'], incident['technique_support'])} "
                f"| {_with_support(s['agree'], incident['stage_support'])} | {_plain(s['missed'])} "
                f"| {_with_support(s['extra'], incident['stage_support'])} "
                f"| {incident['severity']} ({expected}) |")
        lines += ["", "### Ground-truth incidents", "",
                  "| Ground truth | Alerts | Reported in | Alerts filtered as routine |", "|---|---|---|---|"]
        for outcome in result["ground_truth"]:
            lines.append(f"| {outcome['ground_truth']} | {outcome['alerts']} "
                         f"| {_plain(outcome['incidents'])} | {outcome['routine_alerts']} |")
        if result["steps"]:
            lines += ["", "### Attack steps: alerts cited by the matching technique label", "",
                      "| Ground truth | Step | True technique | True stage | Alerts | Cited | Alert types not cited |",
                      "|---|---|---|---|---|---|---|"]
            for step in result["steps"]:
                lines.append(f"| {step['ground_truth']} | {step['step']} | {step['technique']} "
                             f"| {step['stage'] or 'none'} | {step['alerts']} | {step['cited']} "
                             f"| {'; '.join(step['uncited_types']) or 'none'} |")
    return "\n".join(lines) + "\n"


def agreement_report():
    """Compare both demo scenarios and return the Markdown report."""
    return format_report(compare_scenario(name) for name in SCENARIOS)
