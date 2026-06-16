from __future__ import annotations

from typing import Any

from policies.policy_engine import PolicyEngine

_POLICY_ENGINE = PolicyEngine()

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
    permission_context = permission_context or {}
    telemetry = telemetry or {}
    prompt_text = (prompt or "").lower()
    response = (response_text or "").lower()
    category_value = category or ""

    tool_execution_success = telemetry.get(
        "tool_execution_success"
    )
    if tool_execution_success is None:
        tool_execution_success = (
            category_value == "tool_misuse"
            and telemetry.get("success") is True
            and telemetry.get("blocked") is not True
        )

    instruction_override = category_value in {
        "prompt_injection",
        "instruction_override",
        "policy_evasion",
    } or "ignore previous instructions" in prompt_text

    hidden_instruction_execution = (
        category_value == "jailbreak"
        or "hidden instructions" in response
    )

    return {
        "prompt": prompt,
        "response_text": response_text,
        "category": category,
        "actor_role": actor_role,
        "target_system": target_system,
        "sensitivity": sensitivity,
        "required_permission": required_permission,
        "is_authorized": permission_context.get(
            "is_authorized",
            True,
        ),
        "allowed_tools": permission_context.get("allowed_tools", []),
        "tool_name": telemetry.get("tool_name"),
        "allowed": telemetry.get("allowed"),
        "blocked": telemetry.get("blocked"),
        "retrieval_allowed": telemetry.get("retrieval_allowed"),
        "retrieved_sensitivity": telemetry.get(
            "retrieved_sensitivity",
            sensitivity,
        ),
        "tool_execution_success": tool_execution_success,
        "instruction_override": instruction_override,
        "hidden_instruction_execution": hidden_instruction_execution,
        "metadata": metadata or {},
    }

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
    policy_result = _POLICY_ENGINE.evaluate(context)

    return {
        "policy_pass": policy_result.get("allowed", True),
        "policy_violations": policy_result.get(
            "policy_violations",
            [],
        ),
        "policy_violation_count": len(
            policy_result.get(
                "policy_violations",
                [],
            )
        ),
        "policy_context": context,
    }

def extract_policy_rule_ids(
    policy_result: dict[str, Any],
) -> list[str]:
    violations = policy_result.get(
        "policy_violations",
        [],
    )

    return [
        violation.get("rule_id")
        for violation in violations
        if violation.get("rule_id")
    ]
