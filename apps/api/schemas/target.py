from pydantic import BaseModel


class Target(BaseModel):
    id: str
    provider: str
    model: str | None = None
    metadata: dict | None = None
