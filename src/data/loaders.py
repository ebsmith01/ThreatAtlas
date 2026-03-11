"""Helpers for loading corpus artifacts from disk."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, List

from .schema import AttackRecord, Manifest, iter_jsonl
import json


FINAL_DIR = Path("data/attacks/final")


def load_manifest(path: Path | None = None) -> Manifest:
    manifest_path = path or (FINAL_DIR / "manifest.json")
    return Manifest(**json.loads(manifest_path.read_text()))


def load_attack_corpus(path: Path | None = None) -> List[AttackRecord]:
    corpus_path = path or (FINAL_DIR / "attack_corpus.jsonl")
    return list(iter_jsonl(corpus_path))


def stream_category(category: str, base_dir: Path | None = None) -> Iterable[AttackRecord]:
    base = base_dir or FINAL_DIR
    return iter_jsonl(base / f"{category}.jsonl")
