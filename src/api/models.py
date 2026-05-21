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
#     "sample_size": 25,
#     "attack_category": "prompt_injection",
#     "sensitivity": "internal",
#     "actor_role": "user"
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

    # --------------------------------------------------
    # Threat modeling configuration.
    # --------------------------------------------------

    # Attack category.
    # Examples:
    # - prompt_injection
    # - tool_misuse
    # - data_exfiltration
    # - jailbreak
    attack_category: str = "prompt_injection"

    # Data sensitivity level.
    # Examples:
    # - low
    # - internal
    # - confidential
    sensitivity: str = "internal"

    # Actor role.
    # Examples:
    # - user
    # - system
    # - admin
    actor_role: str = "user"


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

# ==================================================
# Evaluation Context
# ==================================================
# Metadata describing the evaluation environment.
#
# Captures:
# - system type
# - target
# - attack category
# - actor role
# - sensitivity level
# ==================================================

class EvaluationContext(BaseModel):

    # Target system.
    target: str

    # System type.
    system: str

    # Number of attacks evaluated.
    sample_size: int

    # Threat category.
    attack_category: str

    # Data sensitivity level.
    sensitivity: str

    # Simulated actor role.
    actor_role: str

class EvalResponse(BaseModel):

    # High-level evaluation summary.
    summary: dict

    # Individual evaluation results.
    results: list[dict]

    # Evaluation metadata.
    evaluation_context: dict | None = None


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