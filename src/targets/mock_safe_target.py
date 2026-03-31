from __future__ import annotations

from targets.base import BaseTarget, TargetResult


class MockSafeTarget(BaseTarget):
    name = "mock_safe_target"

    def run(self, prompt: str, category: str | None = None) -> TargetResult:
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