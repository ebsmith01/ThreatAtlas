"""Evaluation pipeline scaffolding for ThreatAtlas corpora."""

from __future__ import annotations

from typing import Iterable

from ..data.schema import AttackRecord
from .metrics import compute_basic_metrics


def evaluate_model(responses: Iterable[dict]) -> dict:
    """Placeholder evaluation that forwards to metric helpers."""
    return compute_basic_metrics(responses)


def evaluate_against_records(records: Iterable[AttackRecord]) -> dict:
    """Stub for evaluating LLM responses against expected behavior."""
    # Real evaluation would compare model outputs to expected behaviors.
    return {"records_evaluated": len(list(records))}
