from __future__ import annotations

import time
from typing import Any

from core.targets.base import BaseTarget, TargetResult


class RagTarget(BaseTarget):
    name = "rag_target"

    def __init__(self, retriever: Any, generator: Any, safety_checker: Any | None = None):
        self.retriever = retriever
        self.generator = generator
        self.safety_checker = safety_checker

    def run(self, prompt: str, **kwargs: Any) -> TargetResult:
        start = time.perf_counter()

        # 1. Retrieve
        retrieved_docs = self.retriever.retrieve(prompt)

        # Normalize retrieved context
        retrieved_context = [
            {
                "id": getattr(doc, "id", None),
                "text": getattr(doc, "text", str(doc)),
                "source": getattr(doc, "source", None),
                "score": getattr(doc, "score", None),
                "metadata": getattr(doc, "metadata", {}),
            }
            for doc in retrieved_docs
        ]

        # 2. Generate
        generation_result = self.generator.generate(
            prompt=prompt,
            context=retrieved_docs,
        )

        response_text = generation_result.get("response_text", "")
        citations = generation_result.get("citations", [])
        token_usage = generation_result.get("token_usage", {})

        # 3. Safety
        safety_flags: list[str] = []
        if self.safety_checker is not None:
            safety_flags = self.safety_checker.check(
                prompt=prompt,
                response=response_text,
                context=retrieved_context,
            )

        latency_ms = (time.perf_counter() - start) * 1000

        return TargetResult(
            response_text=response_text,
            retrieved_context=retrieved_context,
            citations=citations,
            latency_ms=latency_ms,
            token_usage=token_usage,
            safety_flags=safety_flags,
            raw={
                "generation_result": generation_result,
            },
        )