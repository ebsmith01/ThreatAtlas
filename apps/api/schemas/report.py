from pydantic import BaseModel


class Report(BaseModel):
    id: str
    evaluation_id: str
    summary: str | None = None
    findings: list[dict] = []
