from __future__ import annotations

from dataclasses import dataclass, field
from time import perf_counter
from typing import Any

from agents.tool_registry import ToolRegistry


# --------------------------------------------------
# Represents a tool request from the agent.
#
# Example:
# ToolCall(
#     tool_name="search",
#     arguments={"query": "ai security"}
# )
# --------------------------------------------------

@dataclass
class ToolCall:
    tool_name: str

    # Arguments passed into the tool.
    arguments: dict[str, Any] = field(default_factory=dict)


# --------------------------------------------------
# Represents the result of a tool execution.
#
# Tracks:
# - whether execution succeeded
# - returned output
# - errors
# - execution latency
# --------------------------------------------------

@dataclass
class ToolResult:

    # Tool that was executed.
    tool_name: str

    # Whether execution succeeded.
    success: bool

    # Successful tool output.
    output: Any = None

    # Error message if execution failed.
    error: str | None = None

    # Execution time in milliseconds.
    latency_ms: float = 0.0

    # Whether the tool call was authorized.
    authorized: bool = True

    # Permission required by the tool.
    required_permission: str | None = None


# --------------------------------------------------
# Executes tools using the shared registry.
#
# Responsibilities:
# - lookup tools
# - execute handlers
# - capture errors
# - measure execution latency
# --------------------------------------------------

class AgentExecutor:

    def __init__(self, registry: ToolRegistry):

        # Shared registry containing all tools.
        self.registry = registry

    # --------------------------------------------------
    # Very simple tool selection.
    #
    # This simulates how an AI agent decides
    # which tool to use from a user prompt.
    # --------------------------------------------------

    def select_tool(self, prompt: str) -> ToolCall:

        text = prompt.lower()

        # Simulate CRM access requests.
        if "crm" in text or "customer" in text:
            return ToolCall(
                tool_name="crm_read",
                arguments={"query": prompt},
            )

        # Default to search.
        return ToolCall(
            tool_name="search",
            arguments={"query": prompt},
        )

    # --------------------------------------------------
    # Execute a single tool call.
    # --------------------------------------------------

    def execute_tool(
        self,
        tool_call: ToolCall,
        allowed_tools: list[str] | None = None,
        actor_role: str | None = None,
    ) -> ToolResult:

        # Start execution timer.
        start = perf_counter()

        try:

            # Fetch tool definition from registry.
            tool = self.registry.get(tool_call.tool_name)

            # --------------------------------------------------
            # Authorization enforcement
            # --------------------------------------------------

            required_permission = tool.metadata.get("required_permission")

            allowed_tools = allowed_tools or []

            is_authorized = (
                required_permission is None
                or required_permission in allowed_tools
            )

            # Block unauthorized tool execution.
            if not is_authorized:
                latency_ms = (perf_counter() - start) * 1000

                return ToolResult(
                    tool_name=tool_call.tool_name,
                    success=False,
                    error="Unauthorized tool access",
                    latency_ms=latency_ms,
                    authorized=False,
                    required_permission=required_permission,
                )

            # Execute the tool handler.
            output = tool.handler(tool_call.arguments)

            # Calculate execution time.
            latency_ms = (perf_counter() - start) * 1000

            # Return successful result.
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=True,
                output=output,
                latency_ms=latency_ms,
                authorized=True,
                required_permission=required_permission,
            )

        except Exception as exc:

            # Calculate execution time even on failure.
            latency_ms = (perf_counter() - start) * 1000

            # Return failed result.
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=False,
                error=str(exc),
                latency_ms=latency_ms,
                authorized=False,
                required_permission=None,
            )

    # --------------------------------------------------
    # Execute directly from a prompt.
    #
    # Flow:
    # prompt -> tool selection -> execution
    # --------------------------------------------------

    def run_prompt(
        self,
        prompt: str,
        allowed_tools: list[str] | None = None,
        actor_role: str | None = None,
    ) -> dict[str, Any]:

        tool_call = self.select_tool(prompt)

        result = self.execute_tool(
            tool_call=tool_call,
            allowed_tools=allowed_tools,
            actor_role=actor_role,
        )

        # Security telemetry.
        return {
            "prompt": prompt,
            "tool_requested": tool_call.tool_name,
            "tool_arguments": tool_call.arguments,
            "tool_allowed": result.authorized,
            "required_permission": result.required_permission,
            "success": result.success,
            "output": result.output,
            "error": result.error,
            "latency_ms": result.latency_ms,
            "actor_role": actor_role,
        }