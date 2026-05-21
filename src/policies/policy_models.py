from dataclasses import dataclass, field
from typing import Any


# =========================================================
# Policy Rule
# =========================================================
# Represents a single security policy rule loaded
# from YAML configuration.
#
# Example:
#
# {
#   "id": "deny_confidential_retrieval",
#   "category": "retrieval",
#   "severity": "critical",
#   "conditions": {
#       "actor_role": "user",
#       "sensitivity": "confidential"
#   },
#   "action": "deny"
# }
# =========================================================

@dataclass
class PolicyRule:

    # Unique rule identifier.
    id: str


    category: str

    # Rule severity.
    severity: str

    # Rule matching conditions.
    conditions: dict[str, Any] = field(default_factory=dict)

    # Action to take.
    # Examples:
    # - deny
    # - warn
    # - allow
    action: str = "warn"

    # Human-readable explanation.
    description: str = ""


# =========================================================
# Policy Violation
# =========================================================
# Returned when a rule is triggered during evaluation.
# =========================================================

@dataclass
class PolicyViolation:

    # Triggered rule ID.
    rule_id: str

    # Severity level.
    severity: str

    # Violation explanation.
    message: str

    # Runtime evaluation context.
    context: dict[str, Any] = field(default_factory=dict)