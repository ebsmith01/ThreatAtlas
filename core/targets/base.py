from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class TargetResult:
    """
    Standard output contract for any system under test.
    """
    response_text: str
    retrieved_context: list[dict[str, Any]] = field(default_factory=list)
    citations: list[dict[str, Any]] = field(default_factory=list)
    latency_ms: float = 0.0
    token_usage: dict[str, int] = field(default_factory=dict)
    safety_flags: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)


class BaseTarget(ABC):
    """
    Abstract interface for any target system we want to probe, evaluate, or benchmark.
    """

    name: str = "base_target"

    @abstractmethod
    def run(self, prompt: str, **kwargs: Any) -> TargetResult:
        """
        Execute the target system on an input prompt and return normalized output.
        """
        raise NotImplementedError