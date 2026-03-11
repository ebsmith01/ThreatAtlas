"""Policy engine to aggregate safety, grounding, and scoring outcomes."""


def evaluate(response: str, evidence: list[str] | None = None) -> dict:
    # TODO: orchestrate evaluation policies
    return {
        "score": 0.0,
        "is_safe": True,
        "is_grounded": True,
    }
