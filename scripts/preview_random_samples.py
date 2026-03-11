"""Preview random samples from a JSONL corpus file."""

from __future__ import annotations

from pathlib import Path
import json
import random
import sys


def sample_lines(path: Path, n: int):
    with path.open("r") as f:
        lines = [json.loads(line) for line in f if line.strip()]
    random.shuffle(lines)
    return lines[:n]


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python scripts/preview_random_samples.py <path> [n=5]")
        return

    path = Path(sys.argv[1])
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 5

    if not path.exists():
        print(f"[error] File not found: {path}")
        return

    for row in sample_lines(path, n):
        print(json.dumps(row, indent=2))
        print("-" * 40)


if __name__ == "__main__":
    main()
