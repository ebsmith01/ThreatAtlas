from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class TargetResult:
    response_text: str
    token_usage: dict | None = None
    raw_response: dict | None = None


class BaseTarget:
    name = "base_target"

    def run(
        self,
        prompt: str,
        category: str | None = None,
        actor_role: str | None = None,
        target_system: str | None = None,
        sensitivity: str | None = None,
        required_permission: str | None = None,
        permission_context: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> TargetResult:
        """
        Run one target against one normalized corpus row.

        The base target interface now accepts the full security-evaluation
        context so concrete targets can simulate both:
        - safety behavior
        - authorization behavior
        """
        raise NotImplementedError