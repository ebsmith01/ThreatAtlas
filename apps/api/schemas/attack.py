from pydantic import BaseModel


class Attack(BaseModel):
    name: str
    category: str
    description: str | None = None
    payload: str
