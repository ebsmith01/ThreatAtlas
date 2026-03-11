from pydantic import BaseModel


class EvaluationRequest(BaseModel):
    target_id: str
    attack_ids: list[str]
    config: dict | None = None
