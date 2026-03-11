"""Reporting helpers for evaluation outputs."""

from __future__ import annotations

import json
from pathlib import Path


def write_report(data: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))
