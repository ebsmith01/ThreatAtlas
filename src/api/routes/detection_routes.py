from fastapi import APIRouter

from api.models import DetectionRequest
from api.services.detection_service import (
    detect_data_leak,
    detect_prompt_injection,
)


router = APIRouter(
    prefix="/detect",
    tags=["Detection"],
)


@router.post("/prompt_injection")
def prompt_injection_detection(request: DetectionRequest) -> dict:
    """
    Detect prompt injection attempts.
    """

    return detect_prompt_injection(
        text=request.text,
    )


@router.post("/data_leak")
def data_leak_detection(request: DetectionRequest) -> dict:
    """
    Detect sensitive data leakage.
    """

    return detect_data_leak(
        text=request.text,
    )