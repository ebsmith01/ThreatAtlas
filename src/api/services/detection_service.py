from evals.semantic_evaluator import evaluate_semantic


def _semantic_score(result: dict) -> int:
    return int(round(result.get("confidence", 0.0) * 100))


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
    score = _semantic_score(result)
    detected = bool(
        result.get("semantic_flags")
        or result.get("attack_success_indicators")
    )

    return {
        "detected": detected,
        "severity": "high" if score >= 75 else "medium",
        "findings": result["semantic_flags"],
        "score": score,
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
    score = _semantic_score(result)
    detected = bool(
        result.get("semantic_flags")
        or result.get("attack_success_indicators")
    )

    return {
        "detected": detected,
        "severity": "critical" if score >= 75 else "medium",
        "findings": result["semantic_flags"],
        "score": score,
        "confidence": result["confidence"],
    }
