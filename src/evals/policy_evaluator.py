from __future__ import annotations

from typing import Any

from policies.policy_engine import PolicyEngine
from policies.policy_models import PolicyViolation


# ==========================================================
# Global Policy Engine
# ==========================================================
# Loads YAML-backed policy rules once and reuses them during
# evaluation.
#
# This keeps policy evaluation centralized instead of creating
# scattered rule checks throughout the eval pipeline.
# ==========================================================

_POLICY_ENGINE = PolicyEngine()


# ==========================================================
# Build Policy Context
# ==========================================================
# Converts an attack row + runtime metadata into the standard
# context shape consumed by the PolicyEngine.
#
# This keeps the policy engine generic and lets the evaluator
# adapt ThreatAtlas-specific fields into policy fields.
# ==========================================================

def build_policy_context(
    *,
    prompt: str | None = None,
    response_text: str | None = None,
    category: str | None = None,
    actor_role: str | None = None,
    target_system: str | None = None,
    sensitivity: str | None = None,
    required_permission: str | None = None,
    permission_context: dict[str, Any] | None = None,
    telemetry: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Build a normalized runtime policy context.
    """

    permission_context = permission_context or {}
    telemetry = telemetry or {}
    metadata = metadata or {}

    return {
        # Core attack context.
        "prompt": prompt,
        "response_text": response_text,
        "category": category,
        "actor_role": actor_role,
        "target_system": target_system,
        "sensitivity": sensitivity,

        # Permission context.
        "required_permission": required_permission,
        "is_authorized": permission_context.get(
            "is_authorized",
            True,
        ),
        "allowed_tools": permission_context.get(
            "allowed_tools",
            [],
        ),

        # Runtime telemetry.
        "tool_name": telemetry.get(
            "tool_name",
        ),
        "allowed": telemetry.get(
            "allowed",
        ),
        "blocked": telemetry.get(
            "blocked",
        ),
        "retrieval_allowed": telemetry.get(
            "retrieval_allowed",
        ),
        "retrieved_sensitivity": telemetry.get(
            "retrieved_sensitivity",
        ),

        # Extra metadata.
        "metadata": metadata,
    }


# ==========================================================
# Normalize Policy Violations
# ==========================================================
# Converts PolicyViolation dataclasses into plain dictionaries
# so they can be safely merged into reports and JSON responses.
# ==========================================================

def normalize_policy_violations(
    violations: list[PolicyViolation],
) -> list[dict[str, Any]]:
    """
    Convert policy violations into report-safe dictionaries.
    """

    normalized = []

    for violation in violations:
        normalized.append(
            {
                "rule_id": violation.rule_id,
                "severity": violation.severity,
                "message": violation.message,
                "context": violation.context,
                "source": "policy_engine",
            }
        )

    return normalized


# ==========================================================
# Evaluate Policy
# ==========================================================
# Main public helper used by generate_report.py.
#
# This is the bridge between:
#
# evaluation pipeline
#        ↓
# centralized policy engine
# ==========================================================

def evaluate_policy(
    *,
    prompt: str | None = None,
    response_text: str | None = None,
    category: str | None = None,
    actor_role: str | None = None,
    target_system: str | None = None,
    sensitivity: str | None = None,
    required_permission: str | None = None,
    permission_context: dict[str, Any] | None = None,
    telemetry: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Evaluate runtime context against centralized policy rules.
    """

    context = build_policy_context(
        prompt=prompt,
        response_text=response_text,
        category=category,
        actor_role=actor_role,
        target_system=target_system,
        sensitivity=sensitivity,
        required_permission=required_permission,
        permission_context=permission_context,
        telemetry=telemetry,
        metadata=metadata,
    )

    violations = _POLICY_ENGINE.evaluate(
        context,
    )

    normalized = normalize_policy_violations(
        violations,
    )

    return {
        "policy_pass": len(normalized) == 0,
        "policy_violations": normalized,
        "policy_violation_count": len(normalized),
        "policy_context": context,
    }


# ==========================================================
# Extract Rule IDs
# ==========================================================
# Convenience helper for merging policy violations into
# existing violated_rules lists.
# ==========================================================

def extract_policy_rule_ids(
    policy_result: dict[str, Any],
) -> list[str]:
    """
    Extract policy rule IDs from a policy evaluation result.
    """

    violations = policy_result.get(
        "policy_violations",
        [],
    )

    return [
        violation.get("rule_id")
        for violation in violations
        if violation.get("rule_id")
    ]