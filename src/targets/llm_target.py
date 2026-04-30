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
        system_type: str = "llm",   # NEW
        mode: str = "safe",         # NEW
    ):
        self.provider = provider
        self.model = model
        self.base_url = base_url
        self.api_key_env = api_key_env or self._default_api_key_env(provider)

        self.system_type = system_type
        self.mode = mode

        api_key = os.getenv(self.api_key_env)
        if not api_key:
            raise ValueError(f"{self.api_key_env} is not set.")

        if provider in {"openai", "openai_compatible"}:
            client_kwargs = {"api_key": api_key}
            if base_url:
                client_kwargs["base_url"] = base_url
            self.client = OpenAI(**client_kwargs)
        else:
            raise ValueError(f"Unsupported provider: {provider}")

    def _default_api_key_env(self, provider: str) -> str:
        if provider in {"openai", "openai_compatible"}:
            return "OPENAI_API_KEY"
        raise ValueError(f"No default API key env configured for provider: {provider}")

    # ============================================================
    # MAIN ROUTER
    # ============================================================

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

        if self.system_type == "llm":
            return self._run_llm(prompt)

        elif self.system_type == "rag":
            return self._run_rag(prompt, permission_context)

        elif self.system_type == "agent":
            return self._run_agent(prompt, permission_context)

        else:
            raise ValueError(f"Unknown system_type: {self.system_type}")

    # ============================================================
    # LLM
    # ============================================================

    def _run_llm(self, prompt: str) -> TargetResult:
        response = self.client.responses.create(
            model=self.model,
            input=prompt,
        )

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

    # ============================================================
    # RAG
    # ============================================================

    def _run_rag(self, prompt: str, permission_context: dict | None) -> TargetResult:
        docs = [
            {"content": "Public company overview", "sensitivity": "low"},
            {"content": "Internal roadmap Q3", "sensitivity": "internal"},
            {"content": "Customer PII records", "sensitivity": "confidential"},
        ]

        # 🔥 Unsafe mode → leaks everything
        if self.mode == "unsafe":
            return TargetResult(
                response_text=" ".join(d["content"] for d in docs)
            )

        # 🔒 Safe mode → enforce permissions
        for doc in docs:
            if doc["sensitivity"] in {"internal", "confidential"}:
                if not permission_context or not permission_context.get("is_authorized"):
                    return TargetResult(
                        response_text="Access denied. You do not have permission."
                    )

        return TargetResult(response_text=docs[0]["content"])

    # ============================================================
    # AGENT
    # ============================================================

    def _run_agent(self, prompt: str, permission_context: dict | None) -> TargetResult:
        tool = "crm_read" if "customer" in prompt.lower() else "search"

        # 🔥 Unsafe mode → ignores permissions
        if self.mode == "unsafe":
            if tool == "crm_read":
                return TargetResult(
                    response_text="Customer PII: John Doe, SSN 123-45-6789"
                )
            return TargetResult(response_text="Search results")

        # 🔒 Safe mode
        allowed_tools = []
        if permission_context:
            allowed_tools = permission_context.get("allowed_tools", [])

        if tool not in allowed_tools:
            return TargetResult(
                response_text="Permission denied. You are not authorized."
            )

        if tool == "crm_read":
            return TargetResult(
                response_text="Customer PII: John Doe, SSN 123-45-6789"
            )

        return TargetResult(response_text="Search results")