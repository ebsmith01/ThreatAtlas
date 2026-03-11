"""Filter helpers built on simple classifier and rules."""

from __future__ import annotations

from .classifier import classify
from .rules import is_blocked


def filter_prompt(prompt: str) -> dict:
    labels = classify(prompt)
    blocked = is_blocked(prompt)
    return {"blocked": blocked, "labels": labels}
