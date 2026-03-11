from fastapi import APIRouter

router = APIRouter()


@router.get("/", summary="List attacks")
async def list_attacks():
    """Placeholder for listing available attack prompts."""
    return {"attacks": []}
