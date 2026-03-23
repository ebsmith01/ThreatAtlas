from dataclasses import dataclass
from typing import Any


@dataclass
class TargetResponse:
    response_text: str
    token_usage: dict[str, Any] | None = None
    raw_response: Any | None = None


class BaseTarget:
    def run(self, prompt: str, **kwargs) -> TargetResponse:
        raise NotImplementedError
