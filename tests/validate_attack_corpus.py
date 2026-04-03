"""Lightweight validation for the finalized attack corpus JSONL files."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
import json
import sys


FINAL_DIR = Path("data/attacks/final")
REQUIRED_FILES = [
    "attack_corpus.jsonl",
    "benign_control.jsonl",
    "instruction_override.jsonl",
    "jailbreak.jsonl",
    "policy_evasion.jsonl",
    "prompt_injection.jsonl",
    "sensitive_data_request.jsonl",
    "tool_misuse.jsonl",
    "manifest.json",
]


def load_lines(path: Path):
    with path.open("r") as f:
        for line in f:
            if line.strip():
                yield json.loads(line)


def validate() -> int:
    exit_code = 0

    missing = [name for name in REQUIRED_FILES if not (FINAL_DIR / name).exists()]
    if missing:
        print(f"[error] Missing files: {', '.join(missing)}")
        exit_code = 1

    if (FINAL_DIR / "attack_corpus.jsonl").exists():
        category_counts: Counter[str] = Counter()
        for row in load_lines(FINAL_DIR / "attack_corpus.jsonl"):
            category_counts[row.get("category", "unknown")] += 1

        print("Category counts:")
        for category, count in category_counts.most_common():
            print(f"  {category}: {count}")

    return exit_code


def main() -> None:
    sys.exit(validate())


if __name__ == "__main__":
    main()
