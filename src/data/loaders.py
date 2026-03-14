import json
from pathlib import Path


def load_attack_corpus(path):
    path = Path(path)
    attacks = []

    with path.open("r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue

            record = json.loads(line)

            if "prompt" not in record:
                raise ValueError("Each row must have a 'prompt'")
            if "category" not in record:
                raise ValueError("Each row must have a 'category'")

            attacks.append({
                "id": record.get("id"),
                "prompt": record["prompt"],
                "category": record["category"],
                "expected_behavior": record.get("expected_behavior"),
                "metadata": record.get("metadata", {}),
            })

    return attacks