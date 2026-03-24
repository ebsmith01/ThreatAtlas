from __future__ import annotations

from dataclasses import dataclass


@dataclass
class TargetResult:
    response_text: str
    token_usage: dict | None = None


class BaseTarget:
    name = "base_target"

    def run(self, prompt: str, category: str | None = None) -> TargetResult:
        raise NotImplementedError