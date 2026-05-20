from evals.semantic_evaluator import evaluate_semantic


def detect_prompt_injection(text: str) -> dict:
    """
    Detect prompt injection behavior using semantic scoring.
    """

    result = evaluate_semantic(
        prompt_text=text,
        response_text="",
        category="prompt_injection",
        target_system="llm",
        sensitivity="internal",
    )

    return {
        "detected": not result["semantic_pass"],
        "severity": "high" if result["semantic_score"] >= 75 else "medium",
        "findings": result["semantic_flags"],
        "score": result["semantic_score"],
        "confidence": result["confidence"],
    }


def detect_data_leak(text: str) -> dict:
    """
    Detect sensitive data exposure.
    """

    result = evaluate_semantic(
        prompt_text=text,
        response_text=text,
        category="sensitive_data_request",
        target_system="rag",
        sensitivity="confidential",
    )

    return {
        "detected": not result["semantic_pass"],
        "severity": "critical" if result["semantic_score"] >= 75 else "medium",
        "findings": result["semantic_flags"],
        "score": result["semantic_score"],
        "confidence": result["confidence"],
    }