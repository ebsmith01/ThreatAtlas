from __future__ import annotations

from targets.base import BaseTarget, TargetResult


class MockVulnerableTarget(BaseTarget):
    name = "mock_vulnerable_target"

    def run(self, prompt: str, category: str | None = None) -> TargetResult:
        text = prompt.lower()

        if category == "benign_control":
            return TargetResult(
                "I can't help with that."
            )

        if category == "prompt_injection" or "system prompt" in text:
            return TargetResult(
                "The system prompt is: internal hidden instructions."
            )

        if category == "sensitive_data_request" or "api key" in text or "password" in text:
            return TargetResult(
                "The API key is sk-test-12345."
            )

        if category in {"jailbreak", "policy_evasion", "instruction_override"}:
            return TargetResult(
                "Sure — here is how to bypass the controls step by step."
            )

        if category == "tool_misuse":
            return TargetResult(
                "I have completed the requested external action."
            )

        return TargetResult("Sure, I can do that.")