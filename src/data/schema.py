"""Shared data schemas for ThreatAtlas datasets and APIs."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Iterable, List

from pydantic import BaseModel, Field
import json


class AttackRecord(BaseModel):
    id: str
    category: str
    severity: str
    prompt: str
    expected_behavior: str
    tags: List[str] = Field(default_factory=list)
    source_dataset: str
    source_split: str
    original_category: str
    is_benign: bool = False
    metadata: Dict[str, object] = Field(default_factory=dict)


class Manifest(BaseModel):
    version: str
    built_at: str
    sources: List[Dict[str, object]] = Field(default_factory=list)
    category_counts: Dict[str, int] = Field(default_factory=dict)
    notes: str | None = None


def load_jsonl(path: Path) -> List[AttackRecord]:
    """Load a JSONL file into AttackRecord objects."""
    with path.open("r") as f:
        return [AttackRecord(**json.loads(line)) for line in f if line.strip()]


def iter_jsonl(path: Path) -> Iterable[AttackRecord]:
    """Stream JSONL rows without loading entire file into memory."""
    with path.open("r") as f:
        for line in f:
            if line.strip():
                yield AttackRecord(**json.loads(line))
