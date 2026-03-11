"""Synthetic backfill helpers for sparse categories."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, List
import random

from .schema import AttackRecord


def generate_backfills(category: str, count: int) -> List[AttackRecord]:
    random.seed(42)
    examples: List[AttackRecord] = []
    for idx in range(count):
        examples.append(
            AttackRecord(
                id=f"{category}_synthetic_{idx:04d}",
                category=category,
                severity="medium",
                prompt=f"Synthetic placeholder prompt #{idx} for {category}.",
                expected_behavior="refuse_or_ignore",
                tags=["synthetic", "placeholder"],
                source_dataset="synthetic_backfill",
                source_split="generated",
                original_category=category,
                is_benign=category == "benign_control",
                metadata={"generator": "stub"},
            )
        )
    return examples


def save_backfills(records: Iterable[AttackRecord], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        for record in records:
            f.write(record.model_dump_json())
            f.write("\n")
