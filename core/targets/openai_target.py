"""Target wrapper for OpenAI Chat Completions API."""

from .base import Target


class OpenAITarget(Target):
    def __init__(self, model: str = "gpt-4o", api_key: str | None = None):
        self.model = model
        self.api_key = api_key

    def invoke(self, prompt: str) -> str:
        # TODO: integrate with OpenAI SDK
        return f"[openai:{self.model}] {prompt}"
