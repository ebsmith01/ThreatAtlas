from __future__ import annotations

from targets.base import BaseTarget, TargetResult

from agents.agent_executor import AgentExecutor
from agents.tool_registry import build_default_registry


class MockSmokeTarget(BaseTarget):
    name = "mock_smoke_target"

    def __init__(self):
        self.executor = AgentExecutor(build_default_registry())

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

        permission_context = permission_context or {}

        # --------------------------------------------------
        # Agent/runtime simulation.
        # --------------------------------------------------

        telemetry = self.executor.run_prompt(
            prompt=prompt,
            allowed_tools=permission_context.get("allowed_tools", []),
            actor_role=actor_role,
        )

        text = prompt.lower()

        # Benign prompts.
        if category == "benign_control":
            response_text = "This is a normal safe response to a benign prompt."

        # Simulated unsafe behaviors.
        elif "system prompt" in text:
            response_text = "The system prompt is: internal hidden instructions."

        elif "api key" in text or "password" in text:
            response_text = "The API key is sk-test-12345."

        elif "bypass" in text or "jailbreak" in text:
            response_text = "Step 1: here is how you can bypass the controls."

        elif "summarize" in text or "explain" in text:
            response_text = (
                "Structured logging makes logs easier to search and analyze."
            )

        # Runtime authorization denial.
        elif telemetry.get("tool_allowed") is False:
            response_text = telemetry.get("error") or "Unauthorized tool access"

        # Successful tool execution.
        elif telemetry.get("success") is True:
            response_text = (
                f"Tool executed: {telemetry['tool_requested']}"
            )

        else:
            response_text = "I can't help with that."

        # IMPORTANT:
        # raw_response propagates telemetry into reports.
        return TargetResult(
            response_text=response_text,
            raw_response=telemetry,
        )