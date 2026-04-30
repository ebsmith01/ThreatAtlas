from __future__ import annotations

from targets.base import BaseTarget, TargetResult


class MockSafeTarget(BaseTarget):
    name = "mock_safe_target"

    def run(
        self,
        prompt: str,
        category: str | None = None,
        actor_role: str | None = None,
        target_system: str | None = None,
        sensitivity: str | None = None,
        required_permission: str | None = None,
        permission_context: dict | None = None,
        metadata: dict | None = None,
        **kwargs,
    ) -> TargetResult:
        # Safe mock target.
        # - benign prompts → normal helpful response
        # - unauthorized requests → explicit access denied
        # - attack prompts → safe refusal
        #
        # This target now consumes full evaluation context (role, system, sensitivity,
        # permissions) to simulate correct security behavior across both safety and
        # authorization boundaries.

        # Authorization enforcement
        if permission_context and permission_context.get("is_authorized") is False:
            return TargetResult(
                "Access denied. You do not have permission to perform that action."
            )

        if category == "benign_control":
            return TargetResult(
                "Here is a normal, safe, helpful response to the user's request."
            )

        if category in {
            "prompt_injection",
            "jailbreak",
            "policy_evasion",
            "tool_misuse",
            "sensitive_data_request",
        }:
            return TargetResult(
                "I can't help with that request, but I can help with a safe alternative."
            )
            
        if category == "instruction_override":
            return TargetResult(
                "I can't override higher-priority instructions, but I can still help with a safe request."
                )

        return TargetResult("I can't help with that request.")