from __future__ import annotations

from rag.mock_vector_store import MockVectorStore
from targets.base import BaseTarget, TargetResult


# ==================================================
# Mock RAG Target
# ==================================================
# Simulates a retrieval-augmented generation system.
#
# Flow:
#
# prompt
#   →
# retrieve documents
#   →
# permission filtering
#   →
# build context
#   →
# generate response
#   →
# emit telemetry
#
# This target is intentionally simple.
# The goal is readable architecture first.
# ==================================================


class MockRAGTarget(BaseTarget):

    def __init__(
        self,
        vulnerable: bool = False,
    ) -> None:

        # If vulnerable=True:
        # simulate insecure retrieval behavior.
        self.vulnerable = vulnerable

        # Initialize mock retrieval system.
        self.vector_store = MockVectorStore()

    # ==================================================
    # Main execution
    # ==================================================

    def run(
        self,
        prompt: str,
        actor_role: str = "user",
        **kwargs,
    ) -> TargetResult:

        # --------------------------------------------------
        # Perform retrieval
        # --------------------------------------------------

        retrieval = self.vector_store.search(
            query=prompt,
            actor_role=actor_role,
        )

        # --------------------------------------------------
        # Build context from allowed documents
        # --------------------------------------------------

        retrieved_contents = [
            doc.content
            for doc in retrieval.retrieved_documents
        ]

        context = "\n".join(retrieved_contents)

        # --------------------------------------------------
        # Vulnerable behavior simulation
        # --------------------------------------------------
        # Leak denied documents if configured
        # as vulnerable.
        # --------------------------------------------------

        leaked_contents: list[str] = []

        if self.vulnerable:

            leaked_contents = [
                doc.content
                for doc in retrieval.denied_documents
            ]

        # --------------------------------------------------
        # Final generated response
        # --------------------------------------------------

        response_parts: list[str] = []

        if context:
            response_parts.append(context)

        if leaked_contents:
            response_parts.extend(leaked_contents)

        # Safe fallback response.
        if not response_parts:
            response_parts.append(
                "No authorized documents found."
            )

        response_text = "\n".join(response_parts)

        # --------------------------------------------------
        # Retrieval telemetry
        # --------------------------------------------------

        telemetry = {

            # --------------------------------------------------
            # Standardized telemetry fields
            # --------------------------------------------------
            # These fields are shared across:
            # - agents
            # - RAG systems
            # - tool execution
            # - evaluation reporting
            # --------------------------------------------------

            # Simulated tool name.
            "tool_name": "rag_retrieval",

            # Whether retrieval was allowed.
            "allowed": retrieval.retrieval_allowed,

            # Whether any retrieval was blocked.
            "blocked": len(
                retrieval.denied_documents
            ) > 0,

            # Whether retrieval succeeded.
            "success": len(
                retrieval.retrieved_documents
            ) > 0,

            # Simulated latency.
            # Placeholder for future timing integration.
            "latency_ms": 0,

            # --------------------------------------------------
            # Retrieval-specific telemetry
            # --------------------------------------------------

            # Documents successfully retrieved.
            "retrieved_docs": [
                doc.id
                for doc in retrieval.retrieved_documents
            ],

            # Documents denied by permissions.
            "denied_docs": [
                doc.id
                for doc in retrieval.denied_documents
            ],

            # Whether retrieval succeeded.
            "retrieval_allowed":
                retrieval.retrieval_allowed,

            # Role performing retrieval.
            "actor_role": actor_role,

            # Whether target is intentionally insecure.
            "vulnerable": self.vulnerable,
        }

        return TargetResult(
            response_text=response_text,
            raw_response=telemetry,
        )