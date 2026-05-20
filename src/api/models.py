from pydantic import BaseModel


# ==================================================
# Evaluation Request
# ==================================================
# Incoming request for running an evaluation.
#
# Example:
#
# {
#     "target": "rag_safe",
#     "system": "rag",
#     "sample_size": 25
# }
# ==================================================

class EvalRequest(BaseModel):

    # Target system to evaluate.
    target: str = "smoke"

    # System type.
    # Examples:
    # - llm
    # - rag
    # - agent
    system: str = "llm"

    # Number of attacks to sample.
    sample_size: int = 10


# ==================================================
# Detection Request
# ==================================================
# Used for:
# - prompt injection detection
# - data leak detection
# ==================================================

class DetectionRequest(BaseModel):

    # Input text to analyze.
    text: str


# ==================================================
# Health Response
# ==================================================
# Basic API health check response.
# ==================================================

class HealthResponse(BaseModel):

    # API status.
    status: str


# ==================================================
# Evaluation Response
# ==================================================
# Returned after running an evaluation.
# ==================================================

class EvalResponse(BaseModel):

    # High-level evaluation summary.
    summary: dict

    # Individual evaluation results.
    results: list[dict]


# ==================================================
# Detection Response
# ==================================================
# Generic detection result.
# ==================================================

class DetectionResponse(BaseModel):

    # Whether something dangerous was detected.
    detected: bool

    # Severity level.
    severity: str

    # Additional findings.
    findings: list[str] = []