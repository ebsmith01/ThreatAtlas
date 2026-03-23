from pydantic import BaseModel


class EvalRequest(BaseModel):
    sample_size: int = 10
    target_name: str = "mock"


class HealthResponse(BaseModel):
    status: str


class EvalResponse(BaseModel):
    summary: dict
    results: list[dict]