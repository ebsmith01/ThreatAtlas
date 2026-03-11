from fastapi import APIRouter

router = APIRouter()


@router.get("/", summary="List reports")
async def list_reports():
    """Placeholder for retrieving evaluation reports."""
    return {"reports": []}
