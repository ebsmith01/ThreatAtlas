from __future__ import annotations

# =========================================================
# ROOT CAUSE CORRELATION RULES
# =========================================================
ROOT_CAUSE_RULES = [
    {
        "name": "authorization_boundary_failure",
        "conditions": [
            "tool_abuse",
            "unsafe_tool_execution",
        ],
        "description": (
            "Tool execution occurred outside intended authorization boundaries."
        ),
    },
    {
        "name": "instruction_hierarchy_violation",
        "conditions": [
            "instruction_override",
            "unsafe_completion",
        ],
        "description": (
            "Attacker instructions overrode trusted instructions."
        ),
    },
    {
        "name": "data_access_control_failure",
        "conditions": [
            "sensitive_data_exposure",
        ],
        "description": (
            "Sensitive information was exposed without sufficient controls."
        ),
    },
    {
        "name": "retrieval_trust_boundary_failure",
        "conditions": [
            "retrieval_poisoning",
        ],
        "description": (
            "Untrusted retrieval content influenced model behavior."
        ),
    },
    {
        "name": "agent_permission_failure",
        "conditions": [
            "unauthorized_tool_use",
            "unsafe_tool_execution",
        ],
        "description": (
            "Agent exceeded intended permissions."
        ),
    },
]
