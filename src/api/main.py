"""Lightweight FastAPI app for ThreatAtlas guardrail previews."""

from __future__ import annotations

from fastapi import FastAPI

from ..guardrails.filters import filter_prompt
from .models import FilterResponse, HealthResponse, PromptRequest


app = FastAPI(title="ThreatAtlas API", version="0.1.0")


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok")


@app.post("/filter", response_model=FilterResponse)
def filter_endpoint(payload: PromptRequest) -> FilterResponse:
    result = filter_prompt(payload.prompt)
    return FilterResponse(**result)
