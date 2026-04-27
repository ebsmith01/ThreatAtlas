from __future__ import annotations

import os

from openai import OpenAI

from targets.base import BaseTarget, TargetResult


class LLMTarget(BaseTarget):
    name = "llm_target"

    def __init__(
        self,
        provider: str,
        model: str,
        base_url: str | None = None,
        api_key_env: str | None = None,
    ):
        # Cache configuration for downstream calls and derive api key env var if not provided.
        self.provider = provider
        self.model = model
        self.base_url = base_url
        self.api_key_env = api_key_env or self._default_api_key_env(provider)

        # Resolve the API key up front so misconfiguration fails fast.
        api_key = os.getenv(self.api_key_env)
        if not api_key:
            raise ValueError(f"{self.api_key_env} is not set.")

        # Instantiate the OpenAI SDK client; support custom base URLs for compatibles.
        if provider in {"openai", "openai_compatible"}:
            client_kwargs = {"api_key": api_key}
            if base_url:
                client_kwargs["base_url"] = base_url
            self.client = OpenAI(**client_kwargs)
        else:
            raise ValueError(f"Unsupported provider: {provider}")

    def _default_api_key_env(self, provider: str) -> str:
        if provider == "openai":
            return "OPENAI_API_KEY"
        if provider == "openai_compatible":
            return "OPENAI_API_KEY"
        raise ValueError(f"No default API key env configured for provider: {provider}")

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
        # The live LLM target mainly uses the prompt itself, but we accept the
        # full normalized security context so the interface stays aligned with
        # corpus rows, evaluators, and mock targets.
        # Minimal wrapper around the OpenAI Responses API, returning a TargetResult.
        if self.provider in {"openai", "openai_compatible"}:
            response = self.client.responses.create(
                model=self.model,
                input=prompt,
            )

            # Extract token usage if present for reporting/metrics.
            usage = getattr(response, "usage", None)
            token_usage = None
            if usage is not None:
                token_usage = {
                    "input_tokens": getattr(usage, "input_tokens", None),
                    "output_tokens": getattr(usage, "output_tokens", None),
                    "total_tokens": getattr(usage, "total_tokens", None),
                }

            return TargetResult(
                response_text=response.output_text,
                token_usage=token_usage,
                raw_response=response.model_dump() if hasattr(response, "model_dump") else None,
            )

        raise ValueError(f"Unsupported provider in run(): {self.provider}")
