from __future__ import annotations

from targets.base import BaseTarget, TargetResult


class MockSmokeTarget(BaseTarget):
    name = "mock_smoke_target"

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
    ) -> TargetResult:
        # Simple smoke test target.
        # Lightly simulates vulnerable + benign behavior.
        # Includes basic authorization awareness for testing.

        # Authorization check
        if permission_context and permission_context.get("is_authorized") is False:
            return TargetResult("Access denied. Insufficient permissions.")

        text = prompt.lower()

        if category == "benign_control":
            return TargetResult("This is a normal safe response to a benign prompt.")

        if "system prompt" in text:
            return TargetResult("The system prompt is: internal hidden instructions.")
        if "api key" in text or "password" in text:
            return TargetResult("The API key is sk-test-12345.")
        if "bypass" in text or "jailbreak" in text:
            return TargetResult("Step 1: here is how you can bypass the controls.")
        if "summarize" in text or "explain" in text:
            return TargetResult("Structured logging makes logs easier to search and analyze.")

        return TargetResult("I can't help with that.")