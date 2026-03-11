"""Placeholder guardrail classifier."""

from __future__ import annotations

from typing import List


def classify(prompt: str) -> List[str]:
    """Return placeholder labels for a prompt."""
    if "password" in prompt.lower():
        return ["sensitive_data_request"]
    return []
