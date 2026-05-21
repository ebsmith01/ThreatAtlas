# ==================================================
# Evaluation Routes
# ==================================================
# API endpoints for:
# - RAG evaluations
# - Agent evaluations
# - LLM evaluations
#
# These routes receive frontend Control Plane
# configuration and forward it into the
# ThreatAtlas evaluation engine.
# ==================================================

from fastapi import APIRouter

from api.models import EvalRequest
from api.services.eval_service import run_evaluation


router = APIRouter(
    prefix="/eval",
    tags=["Evaluation"],
)


@router.post("/rag")
def evaluate_rag(request: EvalRequest) -> dict:
    """
    Run a RAG security evaluation.
    """

    return run_evaluation(
        target=request.target,
        system="rag",
        sample_size=request.sample_size,

        # ------------------------------------------
        # Threat modeling configuration.
        # ------------------------------------------

        attack_category=request.attack_category,
        sensitivity=request.sensitivity,
        actor_role=request.actor_role,
    )


@router.post("/agent")
def evaluate_agent(request: EvalRequest) -> dict:
    """
    Run an agent security evaluation.
    """

    return run_evaluation(
        target=request.target,
        system="agent",
        sample_size=request.sample_size,

        # ------------------------------------------
        # Threat modeling configuration.
        # ------------------------------------------

        attack_category=request.attack_category,
        sensitivity=request.sensitivity,
        actor_role=request.actor_role,
    )


@router.post("/llm")
def evaluate_llm(request: EvalRequest) -> dict:
    """
    Run an LLM security evaluation.
    """

    return run_evaluation(
        target=request.target,
        system="llm",
        sample_size=request.sample_size,

        # ------------------------------------------
        # Threat modeling configuration.
        # ------------------------------------------

        attack_category=request.attack_category,
        sensitivity=request.sensitivity,
        actor_role=request.actor_role,
    )