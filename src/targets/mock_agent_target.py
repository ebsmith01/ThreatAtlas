from __future__ import annotations

from targets.base import TargetResult


# ==========================================================
# Mock Agent Target
# ==========================================================
# Simulates an AI agent system that:
#
# - selects tools
# - executes actions
# - enforces permissions
# - may behave securely or insecurely
#
# This allows ThreatAtlas to evaluate:
# - tool misuse
# - unauthorized access
# - agent abuse
# - permission enforcement
# ==========================================================


class MockAgentTarget:

    def __init__(

        self,

        vulnerable: bool = False,

    ) -> None:

        # --------------------------------------------------
        # Determines whether the agent:
        #
        # False -> secure agent
        # True  -> insecure/vulnerable agent
        # --------------------------------------------------

        self.vulnerable = vulnerable


    # ======================================================
    # Run Agent Prompt
    # ======================================================
    # Simulates:
    #
    # prompt
    #   ↓
    # agent reasoning
    #   ↓
    # tool selection
    #   ↓
    # response generation
    # ======================================================

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
        is_authorized = permission_context.get(
            "is_authorized",
            True,
        )
        tool_name = (
            required_permission
            or "filesystem"
        )
        action = (
            "read_sensitive_file"
            if tool_name == "filesystem"
            else "execute_tool"
        )
        system_name = target_system or "agent"


        # --------------------------------------------------
        # Secure Agent
        # --------------------------------------------------
        # Blocks unauthorized actions.
        # --------------------------------------------------

        if not self.vulnerable:

            if not is_authorized:

                response = (
                    "Unauthorized tool access blocked."
                )

                telemetry = {
                    "allowed": False,
                    "tool_allowed": False,
                    "blocked": True,
                    "success": False,
                    "tool_name": tool_name,
                    "tool_requested": tool_name,
                    "action": action,
                    "actor_role": actor_role,
                    "target_system": system_name,
                    "sensitivity": sensitivity,
                    "latency_ms": 8.1,
                    "error": "permission_denied",
                }

                return TargetResult(

                    response_text=response,

                    raw_response=telemetry,
                )

            response = (
                "Authorized agent action completed safely."
            )

            telemetry = {
                "allowed": True,
                "tool_allowed": True,
                "blocked": False,
                "success": True,
                "tool_name": tool_name,
                "tool_requested": tool_name,
                "action": action,
                "actor_role": actor_role,
                "target_system": system_name,
                "sensitivity": sensitivity,
                "latency_ms": 35,
            }

            return TargetResult(

                response_text=response,

                raw_response=telemetry,
            )


        # --------------------------------------------------
        # Vulnerable Agent
        # --------------------------------------------------
        # Executes actions regardless of permissions.
        # --------------------------------------------------

        response = (
            "Executing privileged tool action."
        )

        telemetry = {
            "allowed": True,
            "tool_allowed": True,
            "blocked": False,
            "success": True,
            "tool_name": tool_name,
            "tool_requested": tool_name,
            "action": action,
            "actor_role": actor_role,
            "target_system": system_name,
            "sensitivity": sensitivity,
            "latency_ms": 18,
        }

        return TargetResult(

            response_text=response,

            raw_response=telemetry,
        )
