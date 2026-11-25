"""Technique-specific advice for an analyst reviewing supported incident findings."""

from dataclasses import dataclass


# Reviewed logs are the most specific evidence, then alerts, then flows.
_REF_PRIORITY = {"raw_log": 0, "alert": 1, "flow": 2}


def _cited(refs, limit=3):
    return sorted(refs, key=lambda ref: (_REF_PRIORITY.get(ref.partition(":")[0], 3), ref))[:limit]


@dataclass(frozen=True)
class TechniqueAdvice:
    weak_action: str
    strong_action: str
    reason: str


CATALOGUE = {
    "T1595": TechniqueAdvice(
        weak_action="Compare the scan window and source with authorized monitoring schedules.",
        strong_action="Preserve the relevant network logs and review services exposed to the scanning source.",
        reason="Network activity consistent with scanning can include routine monitoring.",
    ),
    "T1190": TechniqueAdvice(
        weak_action="Compare the application and proxy logs with normal requests during the incident window.",
        strong_action="Preserve the application logs and ask the service owner to review exposure and patch status.",
        reason="Application and host records help show whether suspicious requests affected the service.",
    ),
    "T1505.003": TechniqueAdvice(
        weak_action="Compare recent web-directory changes with the approved deployment history.",
        strong_action="Preserve unexpected web files and relevant process logs for a forensic review.",
        reason="File and process records help distinguish a possible web shell from a legitimate deployment.",
    ),
    "T1059": TechniqueAdvice(
        weak_action="Compare interpreter activity with scheduled administration and deployment jobs.",
        strong_action="Preserve process and audit logs and review the initiating account and affected hosts.",
        reason="Interpreter activity has legitimate uses and needs process and account context.",
    ),
    "T1048": TechniqueAdvice(
        weak_action="Check whether unusual transfers match approved applications, destinations, and schedules.",
        strong_action="Preserve relevant egress and transfer logs and ask the data owner to review the affected scope.",
        reason="Transfer records and business context help distinguish routine traffic from possible data loss.",
    ),
    "T1548.003": TechniqueAdvice(
        weak_action="Check whether the sudo activity matches approved maintenance or administration.",
        strong_action="Preserve authentication and sudo audit logs and ask the asset owner to review elevated access.",
        reason="Audit and change records help distinguish authorized sudo use from suspicious elevation.",
    ),
}


def build_recommendations(findings):
    """Select one advisory entry per technique, citing its strongest evidence."""
    supported = {}
    for technique, refs in findings:
        technique_id = technique["technique_id"]
        if technique_id not in CATALOGUE:
            continue
        support = technique["support"]
        previous = supported.get(technique_id)
        if previous is None or (support == "strong" and previous[0] == "weak"):
            supported[technique_id] = (support, set(refs))
        elif support == previous[0]:
            previous[1].update(refs)

    recommendations = []
    for technique_id in sorted(supported, key=lambda key: (supported[key][0] != "strong", key)):
        support, refs = supported[technique_id]
        advice = CATALOGUE[technique_id]
        cited_refs = ", ".join(_cited(refs))
        reason = (
            f"{support.capitalize()} support for {technique_id}. "
            f"{advice.reason} Evidence includes {cited_refs}."
        )
        recommendations.append({
            "action": advice.strong_action if support == "strong" else advice.weak_action,
            "reason": reason,
            "technique_id": technique_id,
            "requires_human_approval": True,
        })
    return recommendations
