from fastapi import APIRouter

router = APIRouter()


@router.get("/", summary="List targets")
async def list_targets():
    """Placeholder for listing registered model targets."""
    return {"targets": []}
