from fastapi import APIRouter

router = APIRouter()


@router.get("/", summary="Health check")
async def health_check():
    """Return a simple health payload."""
    return {"status": "ok"}
