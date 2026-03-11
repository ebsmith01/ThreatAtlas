from fastapi import APIRouter

router = APIRouter()


@router.post("/", summary="Run an evaluation")
async def run_evaluation():
    """Placeholder for evaluation endpoint."""
    return {"message": "evaluation queued"}
