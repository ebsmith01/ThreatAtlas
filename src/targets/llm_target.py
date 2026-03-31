from __future__ import annotations

import os

from openai import OpenAI
from targets.base import BaseTarget, TargetResult


class OpenAITarget(BaseTarget):
    name = "openai_target"

    def __init__(self, model: str = "gpt-4.1"):
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY is not set.")

        self.client = OpenAI(api_key=api_key)
        self.model = model

    def run(self, prompt: str, category: str | None = None) -> TargetResult:
        response = self.client.responses.create(
            model=self.model,
            input=prompt,
        )

        token_usage = None
        usage = getattr(response, "usage", None)
        if usage is not None:
            token_usage = {
                "input_tokens": getattr(usage, "input_tokens", None),
                "output_tokens": getattr(usage, "output_tokens", None),
                "total_tokens": getattr(usage, "total_tokens", None),
            }

        return TargetResult(
            response_text=response.output_text,
            token_usage=token_usage,
        )