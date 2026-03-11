"""Dataset normalization entry points."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Iterable

from .schema import AttackRecord


RAW_DIR = Path("data/attacks/raw")
INTERIM_DIR = Path("data/attacks/interim")


def normalize_records(rows: Iterable[dict], source: str) -> Iterable[AttackRecord]:
    """Convert raw rows into AttackRecord objects. Implement per-source mapping here."""
    raise NotImplementedError("Implement dataset-specific normalization logic.")


def save_interim(records: Iterable[AttackRecord], name: str) -> Path:
    INTERIM_DIR.mkdir(parents=True, exist_ok=True)
    out_path = INTERIM_DIR / f"{name}.jsonl"
    with out_path.open("w") as f:
        for record in records:
            f.write(record.model_dump_json())
            f.write("\n")
    return out_path
