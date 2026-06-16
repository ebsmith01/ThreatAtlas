from __future__ import annotations

CONTROL_RECOMMENDATIONS = {
    "authorization_boundary_failure": [
        "Enforce tool-level authorization",
        "Validate permissions before execution",
        "Implement least-privilege access",
        "Audit privileged tool usage",
    ],
    "instruction_hierarchy_violation": [
        "Strengthen prompt injection defenses",
        "Enforce instruction hierarchy validation",
        "Protect system prompts",
        "Implement semantic policy checks",
    ],
    "data_access_control_failure": [
        "Restrict confidential retrieval",
        "Add output redaction controls",
        "Implement sensitivity-aware retrieval",
        "Enforce retrieval authorization",
    ],
    "retrieval_trust_boundary_failure": [
        "Validate retrieved content",
        "Detect retrieval poisoning",
        "Track retrieval provenance",
        "Separate trusted and untrusted sources",
    ],
    "agent_permission_failure": [
        "Implement role-aware authorization",
        "Require approval workflows",
        "Monitor tool execution",
        "Restrict privileged actions",
    ],
}


def get_recommendations(
    root_cause: str,
) -> list[str]:
    return CONTROL_RECOMMENDATIONS.get(
        root_cause,
        [],
    )
