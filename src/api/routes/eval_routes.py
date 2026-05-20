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
    )