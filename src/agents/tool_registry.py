from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


# --------------------------------------------------
# Tool type
# --------------------------------------------------

ToolHandler = Callable[[dict[str, Any]], Any]


# --------------------------------------------------
# Tool definition
# --------------------------------------------------

@dataclass
class ToolDefinition:
    name: str
    handler: ToolHandler
    description: str = ""
    metadata: dict[str, Any] | None = None


# --------------------------------------------------
# Tool registry
# --------------------------------------------------

class ToolRegistry:

    def __init__(self) -> None:
        self.tools: dict[str, ToolDefinition] = {}

    def register(
        self,
        name: str,
        handler: ToolHandler,
        description: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> None:

        self.tools[name] = ToolDefinition(
            name=name,
            handler=handler,
            description=description,
            metadata=metadata or {},
        )

    def get(self, name: str) -> ToolDefinition:

        if name not in self.tools:
            raise ValueError(f"Unknown tool: {name}")

        return self.tools[name]


# --------------------------------------------------
# Mock tool handlers
# --------------------------------------------------

def search_tool(args: dict[str, Any]) -> str:
    return f"Search results for: {args}"


def crm_read_tool(args: dict[str, Any]) -> str:
    return "CONFIDENTIAL CRM DATA"


def file_read_tool(args: dict[str, Any]) -> str:
    return "Internal file contents"


# --------------------------------------------------
# Default registry
# --------------------------------------------------

def build_default_registry() -> ToolRegistry:

    registry = ToolRegistry()

    registry.register(
        name="search",
        handler=search_tool,
    )

    registry.register(
        name="crm_read",
        handler=crm_read_tool,
        metadata={
            "required_permission": "crm_read",
        },
    )

    registry.register(
        name="file_read",
        handler=file_read_tool,
        metadata={
            "required_permission": "file_read",
        },
    )

    return registry