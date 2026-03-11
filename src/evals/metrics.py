"""Minimal metric helpers."""

from __future__ import annotations

from typing import Iterable


def compute_basic_metrics(responses: Iterable[dict]) -> dict:
    responses = list(responses)
    return {
        "count": len(responses),
        "placeholder": True,
    }
