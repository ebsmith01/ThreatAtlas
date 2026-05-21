from targets.llm_target import LLMTarget
from targets.mock_target import MockSmokeTarget
from targets.mock_safe_target import MockSafeTarget
from targets.mock_vulnerable_target import (
    MockVulnerableTarget,
)
from targets.mock_rag_target import (
    MockRAGTarget,
)
from targets.mock_agent_target import (
    MockAgentTarget,
)


# =========================================================
# Target Registry
# =========================================================
def get_target(
    name: str,
    model: str | None = None,
    provider: str | None = None,
    base_url: str | None = None,
    api_key_env: str | None = None,
):
    targets = {
        "smoke": MockSmokeTarget,
        "safe": MockSafeTarget,
        "vulnerable": MockVulnerableTarget,
    }
    if name in targets:
        return targets[name]()

    # -----------------------------------------------------
    # Agent Targets
    # -----------------------------------------------------
    if name == "agent_safe":
        return MockAgentTarget(
            vulnerable=False,
        )
    if name == "agent_vulnerable":
        return MockAgentTarget(
            vulnerable=True,
        )

    # -----------------------------------------------------
    # RAG Targets
    # -----------------------------------------------------
    if name == "rag_safe":
        return MockRAGTarget(
            vulnerable=False,
        )
    if name == "rag_vulnerable":
        return MockRAGTarget(
            vulnerable=True,
        )

    # -----------------------------------------------------
    # Real LLM
    # -----------------------------------------------------
    if name == "llm":
        return LLMTarget(
            provider=provider or "openai",
            model=model or "gpt-4.1",
            base_url=base_url,
            api_key_env=api_key_env,
        )

    raise ValueError(
        f"Unknown target: {name}"
    )
