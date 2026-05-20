from fastapi import APIRouter


router = APIRouter(
    tags=["Health"],
)


@router.get("/health")
def health() -> dict:
    """
    Basic health check.
    """

    return {
        "status": "ok",
    }


@router.get("/ready")
def ready() -> dict:
    """
    Basic readiness check.
    """

    return {
        "status": "ready",
    }