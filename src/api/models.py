"""API request/response models."""

from __future__ import annotations

from pydantic import BaseModel


class PromptRequest(BaseModel):
    prompt: str


class FilterResponse(BaseModel):
    blocked: bool
    labels: list[str]


class HealthResponse(BaseModel):
    status: str
